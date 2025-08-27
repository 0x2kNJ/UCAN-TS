/**
 * Security hardening utilities for UCAN implementation
 * Addresses timing attacks, memory safety, and secure practices
 */

import sodium from "libsodium-wrappers";

// Memory zeroing for sensitive data
export class SecureBuffer {
  private buffer: Uint8Array;
  private isValid: boolean = true;

  constructor(size: number) {
    this.buffer = new Uint8Array(size);
  }

  static from(data: Uint8Array): SecureBuffer {
    const secure = new SecureBuffer(data.length);
    secure.buffer.set(data);
    return secure;
  }

  get(): Uint8Array {
    if (!this.isValid) {
      throw new Error("SecureBuffer has been zeroed and is no longer valid");
    }
    return this.buffer;
  }

  copy(): Uint8Array {
    if (!this.isValid) {
      throw new Error("SecureBuffer has been zeroed and is no longer valid");
    }
    return new Uint8Array(this.buffer);
  }

  zero(): void {
    if (this.isValid) {
      // Overwrite with random data first, then zeros (defense against memory recovery)
      const random = sodium.randombytes_buf(this.buffer.length);
      this.buffer.set(random);
      this.buffer.fill(0);
      this.isValid = false;
    }
  }

  // Automatic cleanup
  [Symbol.dispose](): void {
    this.zero();
  }
}

// Constant-time string comparison (using manual implementation since crypto_verify_32 is not available)
export function constantTimeStringEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  const aBytes = new TextEncoder().encode(a);
  const bBytes = new TextEncoder().encode(b);
  
  return constantTimeEqual(aBytes, bBytes);
}

// Constant-time byte array comparison (manual implementation)
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  
  return result === 0;
}

// Input validation and sanitization
export class InputValidator {
  // Validate DID format
  static validateDID(did: string): boolean {
    if (typeof did !== 'string') return false;
    
    // DID spec: did:method:method-specific-id
    const didRegex = /^did:[a-z0-9]+:[a-zA-Z0-9._-]+$/;
    
    // Length limits (prevent DoS)
    if (did.length < 8 || did.length > 500) return false;
    
    return didRegex.test(did);
  }

  // Validate base64url strings
  static validateBase64Url(input: string): boolean {
    if (typeof input !== 'string') return false;
    
    // Length limits
    if (input.length > 10000) return false; // Prevent DoS
    
    const base64UrlRegex = /^[A-Za-z0-9_-]+$/;
    return base64UrlRegex.test(input);
  }

  // Validate capability resource
  static validateCapabilityResource(resource: string): boolean {
    if (typeof resource !== 'string') return false;
    
    // Length limits
    if (resource.length > 1000) return false;
    
    // Allow alphanumeric, slash, dash, underscore, asterisk for wildcards
    const resourceRegex = /^[a-zA-Z0-9/_*.-]+$/;
    return resourceRegex.test(resource);
  }

  // Validate capability action
  static validateCapabilityAction(action: string): boolean {
    if (typeof action !== 'string') return false;
    
    // Length limits
    if (action.length > 100) return false;
    
    // Allow alphanumeric, slash, dash, underscore, asterisk for wildcards
    const actionRegex = /^[a-zA-Z0-9/_*.-]+$/;
    return actionRegex.test(action);
  }

  // Validate timestamp (Unix epoch)
  static validateTimestamp(timestamp: number): boolean {
    if (typeof timestamp !== 'number') return false;
    
    // Reasonable bounds: not before 2020, not after 2050
    const min = 1577836800; // 2020-01-01
    const max = 2524608000; // 2050-01-01
    
    return timestamp >= min && timestamp <= max && Number.isInteger(timestamp);
  }

  // Validate CBOR data size (prevent DoS)
  static validateCBORSize(data: Uint8Array): boolean {
    // Limit UCAN size to 10MB to prevent DoS
    return data.length <= 10 * 1024 * 1024;
  }
}

// Rate limiting utilities
export class RateLimiter {
  private attempts: Map<string, { count: number; resetTime: number }> = new Map();
  
  constructor(
    private maxAttempts: number = 10,
    private windowMs: number = 60000 // 1 minute
  ) {}

  isAllowed(identifier: string): boolean {
    const now = Date.now();
    const entry = this.attempts.get(identifier);
    
    if (!entry || now >= entry.resetTime) {
      // Reset or first attempt
      this.attempts.set(identifier, { count: 1, resetTime: now + this.windowMs });
      return true;
    }
    
    if (entry.count >= this.maxAttempts) {
      return false;
    }
    
    entry.count++;
    return true;
  }

  // Clean up expired entries
  cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.attempts.entries()) {
      if (now >= entry.resetTime) {
        this.attempts.delete(key);
      }
    }
  }
}

// Secure random utilities
export class SecureRandom {
  // Generate cryptographically secure random string
  static generateId(length: number = 32): string {
    const bytes = sodium.randombytes_buf(length);
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  // Generate random base64url string
  static generateBase64Url(byteLength: number = 32): string {
    const bytes = sodium.randombytes_buf(byteLength);
    return Array.from(bytes, byte => 
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'[byte % 64]
    ).join('');
  }
}

// Environment variable validation
export class EnvValidator {
  static validatePrivateKeyEnv(varName: string): void {
    const value = process.env[varName];
    if (!value) {
      throw new Error(`Missing required environment variable: ${varName}`);
    }
    
    if (!InputValidator.validateBase64Url(value)) {
      throw new Error(`Invalid format for ${varName}: must be base64url`);
    }
    
    // Check key length (Ed25519 keys should be 32 or 64 bytes when base64url decoded)
    try {
      const decoded = Buffer.from(value, 'base64url');
      if (decoded.length !== 32 && decoded.length !== 64) {
        throw new Error(`Invalid key length for ${varName}: expected 32 or 64 bytes`);
      }
    } catch (error) {
      throw new Error(`Failed to decode ${varName}: ${error}`);
    }
  }

  static validateRedisUrl(url?: string): void {
    if (!url) return; // Optional
    
    try {
      const parsed = new URL(url);
      if (!['redis:', 'rediss:'].includes(parsed.protocol)) {
        throw new Error('Redis URL must use redis: or rediss: protocol');
      }
    } catch (error) {
      throw new Error(`Invalid REDIS_URL: ${error}`);
    }
  }
}

// Audit logging for security events
export class SecurityAudit {
  static logFailedVerification(details: {
    type: 'delegation' | 'invocation' | 'chain';
    reason: string;
    issuer?: string;
    timestamp: number;
  }): void {
    console.warn('SECURITY_AUDIT: Failed verification', {
      ...details,
      level: 'WARNING'
    });
  }

  static logSuspiciousActivity(details: {
    activity: string;
    source?: string;
    timestamp: number;
  }): void {
    console.error('SECURITY_AUDIT: Suspicious activity detected', {
      ...details,
      level: 'ERROR'
    });
  }

  static logPrivilegeEscalation(details: {
    requested: string;
    granted: string;
    issuer: string;
    timestamp: number;
  }): void {
    console.error('SECURITY_AUDIT: Potential privilege escalation', {
      ...details,
      level: 'CRITICAL'
    });
  }
}
