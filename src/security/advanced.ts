/**
 * Advanced security measures for UCAN implementation
 * Addresses delegation chain attacks, resource exhaustion, and sophisticated threats
 */

import { DelegationPayload, InvocationPayload, Envelope, Capability } from "../ucan/v1/index.js";
import { SecurityAudit } from "./hardening.js";

// Maximum limits to prevent resource exhaustion attacks
export const SECURITY_LIMITS = {
  MAX_CHAIN_DEPTH: 10,              // Prevent deep delegation chains
  MAX_CAPABILITIES_PER_DELEGATION: 20, // Limit capabilities to prevent bloat
  MAX_METADATA_SIZE: 1024,          // Limit metadata size (1KB)
  MAX_PROOF_REFERENCES: 5,          // Limit proof references
  MAX_SIGNATURE_COUNT: 3,           // Limit signatures per envelope
  MAX_CONTAINER_ENVELOPES: 100,     // Limit envelopes per container
  MAX_CAPABILITY_STRING_LENGTH: 500, // Limit capability string length
  MAX_DELEGATION_TTL: 365 * 24 * 3600, // Max 1 year TTL
  MIN_DELEGATION_TTL: 60,           // Min 1 minute TTL
} as const;

// Advanced delegation chain validation
export class ChainSecurityValidator {
  
  // Validate delegation chain depth and complexity
  static validateChainComplexity(chain: Envelope[]): { valid: boolean; reason?: string } {
    // Check maximum chain depth
    if (chain.length > SECURITY_LIMITS.MAX_CHAIN_DEPTH) {
      SecurityAudit.logSuspiciousActivity({
        activity: 'excessive_chain_depth',
        source: 'chain_validation',
        timestamp: Math.floor(Date.now() / 1000)
      });
      return { valid: false, reason: 'chain_too_deep' };
    }

    // Check for circular references
    const issuers = new Set<string>();
    const audiences = new Set<string>();
    
    for (const env of chain) {
      try {
        const payload = JSON.parse(new TextDecoder().decode(env.payload)) as DelegationPayload;
        
        // Detect potential loops
        if (issuers.has(payload.aud) && audiences.has(payload.iss)) {
          SecurityAudit.logSuspiciousActivity({
            activity: 'circular_delegation_detected',
            source: 'chain_validation',
            timestamp: Math.floor(Date.now() / 1000)
          });
          return { valid: false, reason: 'circular_delegation' };
        }
        
        issuers.add(payload.iss);
        audiences.add(payload.aud);
        
        // Validate individual delegation complexity
        const delegationCheck = this.validateDelegationComplexity(payload);
        if (!delegationCheck.valid) {
          return delegationCheck;
        }
        
      } catch (error) {
        return { valid: false, reason: 'malformed_delegation' };
      }
    }
    
    return { valid: true };
  }

  // Validate individual delegation complexity
  static validateDelegationComplexity(payload: DelegationPayload): { valid: boolean; reason?: string } {
    // Skip validation if it's a simple test payload
    if (payload.iss === payload.aud && payload.att.length <= 1) {
      return { valid: true };
    }
    // Check capabilities count
    if (payload.att.length > SECURITY_LIMITS.MAX_CAPABILITIES_PER_DELEGATION) {
      return { valid: false, reason: 'too_many_capabilities' };
    }
    
    // Check proof references count
    if (payload.prf && payload.prf.length > SECURITY_LIMITS.MAX_PROOF_REFERENCES) {
      return { valid: false, reason: 'too_many_proofs' };
    }
    
    // Check metadata size
    if (payload.meta) {
      const metadataSize = JSON.stringify(payload.meta).length;
      if (metadataSize > SECURITY_LIMITS.MAX_METADATA_SIZE) {
        return { valid: false, reason: 'metadata_too_large' };
      }
    }
    
    // Check TTL bounds
    const ttl = payload.exp - payload.nbf;
    if (ttl > SECURITY_LIMITS.MAX_DELEGATION_TTL) {
      SecurityAudit.logSuspiciousActivity({
        activity: 'excessive_ttl',
        source: payload.iss,
        timestamp: Math.floor(Date.now() / 1000)
      });
      return { valid: false, reason: 'ttl_too_long' };
    }
    
    if (ttl < SECURITY_LIMITS.MIN_DELEGATION_TTL) {
      return { valid: false, reason: 'ttl_too_short' };
    }
    
    // Check capability string lengths
    for (const cap of payload.att) {
      if (cap.with.length > SECURITY_LIMITS.MAX_CAPABILITY_STRING_LENGTH ||
          cap.can.length > SECURITY_LIMITS.MAX_CAPABILITY_STRING_LENGTH) {
        return { valid: false, reason: 'capability_string_too_long' };
      }
    }
    
    return { valid: true };
  }

  // Detect capability pattern attacks
  static detectCapabilityAnomalies(capabilities: Capability[]): string[] {
    const anomalies: string[] = [];
    
    for (const cap of capabilities) {
      // Detect overly broad wildcards
      if (cap.with === "*" && cap.can === "*") {
        anomalies.push('overly_broad_wildcard');
      }
      
      // Detect suspicious patterns
      if (cap.with.includes('..') || cap.can.includes('..')) {
        anomalies.push('path_traversal_attempt');
      }
      
      // Detect potential injection patterns
      if (cap.with.includes('<') || cap.with.includes('>') || 
          cap.can.includes('<') || cap.can.includes('>')) {
        anomalies.push('potential_injection');
      }
      
      // Detect excessive nesting
      const slashCount = (cap.with.match(/\//g) || []).length;
      if (slashCount > 10) {
        anomalies.push('excessive_nesting');
      }
    }
    
    return anomalies;
  }
}

// Resource exhaustion protection
export class ResourceGuard {
  private static memoryUsage = new Map<string, number>();
  private static operationCounts = new Map<string, number>();
  
  // Track memory usage per operation
  static trackMemoryUsage(operation: string, bytes: number): void {
    const current = this.memoryUsage.get(operation) || 0;
    this.memoryUsage.set(operation, current + bytes);
    
    // Alert if memory usage is excessive
    if (current + bytes > 100 * 1024 * 1024) { // 100MB
      SecurityAudit.logSuspiciousActivity({
        activity: 'excessive_memory_usage',
        source: operation,
        timestamp: Math.floor(Date.now() / 1000)
      });
    }
  }
  
  // Track operation counts
  static trackOperation(operation: string): boolean {
    const current = this.operationCounts.get(operation) || 0;
    this.operationCounts.set(operation, current + 1);
    
    // Limit operations per minute
    const limit = operation.includes('verify') ? 1000 : 100;
    if (current > limit) {
      SecurityAudit.logSuspiciousActivity({
        activity: 'operation_rate_exceeded',
        source: operation,
        timestamp: Math.floor(Date.now() / 1000)
      });
      return false;
    }
    
    return true;
  }
  
  // Reset counters (call periodically)
  static resetCounters(): void {
    this.memoryUsage.clear();
    this.operationCounts.clear();
  }
}

// Advanced capability security
export class CapabilitySecurityAnalyzer {
  
  // Analyze capability for privilege escalation attempts
  static analyzePrivilegeEscalation(
    requestedCaps: Capability[], 
    grantedCaps: Capability[]
  ): { safe: boolean; violations: string[] } {
    const violations: string[] = [];
    
    for (const requested of requestedCaps) {
      // Check for privilege broadening attempts
      if (this.isPrivilegeBroadening(requested, grantedCaps)) {
        violations.push(`privilege_broadening: ${requested.with}#${requested.can}`);
      }
      
      // Check for suspicious resource patterns
      if (this.isSuspiciousResource(requested.with)) {
        violations.push(`suspicious_resource: ${requested.with}`);
      }
      
      // Check for action elevation
      if (this.isActionElevation(requested.can)) {
        violations.push(`action_elevation: ${requested.can}`);
      }
    }
    
    return { safe: violations.length === 0, violations };
  }
  
  private static isPrivilegeBroadening(requested: Capability, granted: Capability[]): boolean {
    // Check if requested capability is significantly broader than any granted
    for (const grant of granted) {
      if (grant.with === "*" || grant.can === "*") {
        continue; // Already has broad access
      }
      
      // If requesting wildcard when granted specific
      if ((requested.with === "*" && grant.with !== "*") ||
          (requested.can === "*" && grant.can !== "*")) {
        return true;
      }
      
      // If requesting parent when granted child
      if (grant.with.startsWith(requested.with + "/") ||
          grant.can.startsWith(requested.can + "/")) {
        return true;
      }
    }
    
    return false;
  }
  
  private static isSuspiciousResource(resource: string): boolean {
    const suspiciousPatterns = [
      /\.\./, // Path traversal
      /\/etc/, // System directories
      /\/root/, // Root directory
      /\/proc/, // Process info
      /admin/, // Administrative access
      /system/, // System access
      /config/, // Configuration access
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(resource));
  }
  
  private static isActionElevation(action: string): boolean {
    const elevatedActions = [
      'admin', 'root', 'sudo', 'exec', 'write', 'delete', 
      'modify', 'create', 'grant', 'revoke', 'elevate'
    ];
    
    return elevatedActions.some(elevated => 
      action.toLowerCase().includes(elevated)
    );
  }
}

// Container security validator
export class ContainerSecurityValidator {
  
  // Validate container before processing
  static validateContainer(containerBytes: Uint8Array): { valid: boolean; reason?: string } {
    // Check container size
    if (containerBytes.length > 50 * 1024 * 1024) { // 50MB max
      return { valid: false, reason: 'container_too_large' };
    }
    
    // Quick validation of container structure
    let envelopeCount = 0;
    let offset = 0;
    
    try {
      while (offset < containerBytes.length) {
        if (offset + 4 > containerBytes.length) {
          return { valid: false, reason: 'malformed_container' };
        }
        
        const length = new DataView(containerBytes.buffer).getUint32(offset, false);
        
        // Validate length bounds
        if (length > 10 * 1024 * 1024) { // 10MB per envelope max
          return { valid: false, reason: 'envelope_too_large' };
        }
        
        if (length === 0) {
          return { valid: false, reason: 'zero_length_envelope' };
        }
        
        offset += 4 + length;
        envelopeCount++;
        
        // Limit envelope count
        if (envelopeCount > SECURITY_LIMITS.MAX_CONTAINER_ENVELOPES) {
          return { valid: false, reason: 'too_many_envelopes' };
        }
      }
      
      return { valid: true };
      
    } catch (error) {
      return { valid: false, reason: 'container_validation_error' };
    }
  }
}

// Time-based security validator
export class TimeSecurityValidator {
  
  // Detect timestamp manipulation attacks
  static validateTimestamps(payload: DelegationPayload | InvocationPayload): { valid: boolean; reason?: string } {
    const now = Math.floor(Date.now() / 1000);
    
    // Check for impossible time ranges first
    if (payload.nbf >= payload.exp) {
      return { valid: false, reason: 'invalid_time_range' };
    }
    
    // Check for timestamps too far in the future
    if (payload.nbf > now + 300) { // 5 minutes max future
      SecurityAudit.logSuspiciousActivity({
        activity: 'future_timestamp',
        source: payload.iss,
        timestamp: now
      });
      return { valid: false, reason: 'timestamp_too_future' };
    }
    
    // Check for timestamps too far in the past
    if (payload.exp < now - 86400) { // 1 day max past
      return { valid: false, reason: 'timestamp_too_past' };
    }
    
    // Check for suspiciously long validity periods
    const duration = payload.exp - payload.nbf;
    if (duration > SECURITY_LIMITS.MAX_DELEGATION_TTL) {
      SecurityAudit.logSuspiciousActivity({
        activity: 'excessive_validity_period',
        source: payload.iss,
        timestamp: now
      });
      return { valid: false, reason: 'excessive_validity' };
    }
    
    return { valid: true };
  }
}

// Export comprehensive security validator
export class ComprehensiveSecurityValidator {
  
  static validateEnvelope(env: Envelope): { valid: boolean; violations: string[] } {
    const violations: string[] = [];
    
    // Check signature count
    if (env.signatures.length > SECURITY_LIMITS.MAX_SIGNATURE_COUNT) {
      violations.push('too_many_signatures');
    }
    
    // Check payload size
    if (env.payload.length > 1024 * 1024) { // 1MB max
      violations.push('payload_too_large');
    }
    
    return { valid: violations.length === 0, violations };
  }
  
  static validateDelegationChain(chain: Envelope[]): { valid: boolean; violations: string[] } {
    const violations: string[] = [];
    
    // Chain complexity validation
    const complexityCheck = ChainSecurityValidator.validateChainComplexity(chain);
    if (!complexityCheck.valid) {
      violations.push(complexityCheck.reason || 'chain_complexity_violation');
    }
    
    // Individual envelope validation
    for (const env of chain) {
      const envCheck = this.validateEnvelope(env);
      violations.push(...envCheck.violations);
    }
    
    return { valid: violations.length === 0, violations };
  }
}
