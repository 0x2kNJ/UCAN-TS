/**
 * Security middleware and hardening for UCAN minting endpoints
 */

import { Request, Response, NextFunction } from "express";
import { RateLimiter, InputValidator, SecurityAudit } from "../security/hardening.js";

// Rate limiting for minting endpoints
const mintRateLimit = new RateLimiter(5, 60000); // 5 requests per minute

export function rateLimitMiddleware(req: Request, res: Response, next: NextFunction): void {
  const clientId = req.ip || req.socket.remoteAddress || 'unknown';
  
  if (!mintRateLimit.isAllowed(clientId)) {
    SecurityAudit.logSuspiciousActivity({
      activity: 'rate_limit_exceeded',
      source: clientId,
      timestamp: Math.floor(Date.now() / 1000)
    });
    
    res.status(429).json({
      error: 'rate_limit_exceeded',
      message: 'Too many requests. Please try again later.'
    });
    return;
  }
  
  next();
}

// Input validation middleware
export function validateMintRequest(req: Request, res: Response, next: NextFunction): void {
  const { provider, subjectDid, method, paymentId, productId, amount, currency } = req.body;
  
  // Required field validation
  if (!provider || !subjectDid || !method || !paymentId || !productId) {
    res.status(400).json({
      error: 'validation_failed',
      message: 'Missing required fields: provider, subjectDid, method, paymentId, productId'
    });
    return;
  }
  
  // DID validation
  if (!InputValidator.validateDID(subjectDid)) {
    SecurityAudit.logSuspiciousActivity({
      activity: 'invalid_did_format',
      source: req.ip || 'unknown',
      timestamp: Math.floor(Date.now() / 1000)
    });
    
    res.status(400).json({
      error: 'validation_failed',
      message: 'Invalid DID format'
    });
    return;
  }
  
  // Method validation (prevent injection attacks)
  if (typeof method !== 'string' || method.length > 100 || !/^[a-zA-Z0-9._-]+$/.test(method)) {
    res.status(400).json({
      error: 'validation_failed',
      message: 'Invalid method format'
    });
    return;
  }
  
  // Payment validation
  if (typeof paymentId !== 'string' || paymentId.length > 200 || !/^[a-zA-Z0-9._-]+$/.test(paymentId)) {
    res.status(400).json({
      error: 'validation_failed',
      message: 'Invalid paymentId format'
    });
    return;
  }
  
  if (typeof productId !== 'string' || productId.length > 100 || !/^[a-zA-Z0-9._-]+$/.test(productId)) {
    res.status(400).json({
      error: 'validation_failed',
      message: 'Invalid productId format'
    });
    return;
  }
  
  // Amount validation
  if (amount !== undefined) {
    if (typeof amount !== 'number' || amount < 0 || amount > 1000000) {
      res.status(400).json({
        error: 'validation_failed',
        message: 'Invalid amount: must be number between 0 and 1000000'
      });
      return;
    }
  }
  
  // Currency validation
  if (currency !== undefined) {
    if (typeof currency !== 'string' || !/^[A-Z]{3}$/.test(currency)) {
      res.status(400).json({
        error: 'validation_failed',
        message: 'Invalid currency: must be 3-letter ISO code'
      });
      return;
    }
  }
  
  next();
}

// Security headers middleware
export function securityHeaders(req: Request, res: Response, next: NextFunction): void {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // XSS protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Strict transport security (HTTPS only)
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  // Content security policy
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'none'; object-src 'none'");
  
  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  next();
}

// Error sanitization (prevent information leakage)
export function sanitizeError(error: Error): { error: string; message: string } {
  // Log the full error for debugging
  console.error('Internal error:', error);
  
  // Return sanitized error to client
  if (error.message.includes('payment') && error.message.includes('failed')) {
    return {
      error: 'payment_failed',
      message: 'Payment verification failed'
    };
  }
  
  if (error.message.includes('policy') || error.message.includes('method')) {
    return {
      error: 'invalid_method',
      message: 'Unknown or invalid method'
    };
  }
  
  if (error.message.includes('sign') || error.message.includes('key')) {
    return {
      error: 'service_error',
      message: 'Service temporarily unavailable'
    };
  }
  
  // Generic error for unknown cases
  return {
    error: 'internal_error',
    message: 'An unexpected error occurred'
  };
}

// Capability validation (prevent privilege escalation)
export function validateCapabilities(requestedCaps: string[], allowedCaps: string[]): boolean {
  for (const requested of requestedCaps) {
    let allowed = false;
    
    for (const allowed_cap of allowedCaps) {
      if (allowed_cap === '*' || allowed_cap === requested) {
        allowed = true;
        break;
      }
      
      // Check wildcard patterns
      if (allowed_cap.endsWith('/*') && requested.startsWith(allowed_cap.slice(0, -2))) {
        allowed = true;
        break;
      }
    }
    
    if (!allowed) {
      SecurityAudit.logPrivilegeEscalation({
        requested: requested,
        granted: allowedCaps.join(','),
        issuer: 'system',
        timestamp: Math.floor(Date.now() / 1000)
      });
      return false;
    }
  }
  
  return true;
}
