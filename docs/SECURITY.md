# Security Guide

This document outlines the security measures implemented in the UCAN TypeScript implementation and provides guidance for secure deployment.

## 🔒 Security Features

### 1. **Memory Safety**
- **SecureBuffer**: Automatic memory zeroing for private keys
- **Constant-time operations**: Prevents timing attacks on comparisons
- **Key disposal**: Proper cleanup of sensitive data

```typescript
// Keys are automatically zeroed when disposed
const signer = new Ed25519Signer(secretKey);
// ... use signer
signer.dispose(); // Zeros memory
```

### 2. **Input Validation**
- **DID format validation**: Prevents malformed identifiers
- **Base64url validation**: Ensures proper encoding
- **Size limits**: Prevents DoS attacks via large payloads
- **Timestamp bounds**: Reasonable time window validation

### 3. **Rate Limiting**
- **Request throttling**: 5 requests per minute per IP
- **Automatic cleanup**: Expired entries removed
- **Configurable limits**: Adjustable per deployment

### 4. **Cryptographic Security**
- **Ed25519 signatures**: Industry-standard elliptic curve
- **XSalsa20-Poly1305 encryption**: Authenticated encryption
- **PBKDF2 key derivation**: 100,000 iterations by default
- **Secure random generation**: libsodium-based entropy

### 5. **Audit Logging**
- **Failed verifications**: Logged with context
- **Suspicious activity**: Rate limit violations, malformed requests
- **Privilege escalation**: Capability mismatch attempts

## 🛡️ Deployment Security

### Environment Variables
```bash
# Required - use strong, random values
RECEIPT_SEED_B64URL="your-32-byte-seed-base64url"
RECEIPT_SK_B64URL="your-64-byte-key-base64url"

# Optional - Redis for idempotency
REDIS_URL="redis://localhost:6379"

# Optional - Policy configuration
POLICY_PATH="./config/policies.yaml"
```

### Key Generation
```bash
# Generate secure keys
npm run ucan keygen -o service-key.json

# Use the secretKey for RECEIPT_SK_B64URL
```

### HTTPS Configuration
```typescript
// Always use HTTPS in production
app.use(securityHeaders); // Sets HSTS and other headers
```

### Rate Limiting
```typescript
// Apply rate limiting to minting endpoints
app.use('/mcp/mint', rateLimitMiddleware);
app.use('/mcp/mint', validateMintRequest);
```

## ⚠️ Security Considerations

### 1. **Key Management**
- **Never log private keys**: Use secure logging practices
- **Rotate keys regularly**: Implement key rotation procedures
- **Use environment variables**: Never hardcode secrets
- **Secure storage**: Use HSMs or key management services

### 2. **Network Security**
- **HTTPS only**: Never deploy over HTTP
- **Certificate validation**: Use valid TLS certificates
- **CORS configuration**: Restrict allowed origins
- **Firewall rules**: Limit network access

### 3. **Capability Security**
- **Least privilege**: Grant minimum required capabilities
- **Capability validation**: Verify requested vs granted caps
- **Time bounds**: Use short expiration times
- **Delegation chains**: Validate chain integrity

### 4. **Container Security**
- **Size limits**: Prevent DoS via large containers
- **Validation**: Verify envelope structure
- **Error handling**: Don't leak internal details

## 🚨 Vulnerability Prevention

### Timing Attacks
```typescript
// Use constant-time comparison
if (constantTimeEqual(received, expected)) {
  // Safe comparison
}
```

### Memory Attacks
```typescript
// Secure key handling
const secureKey = SecureBuffer.from(keyData);
// ... use key
secureKey.zero(); // Explicit cleanup
```

### Input Validation
```typescript
// Validate all inputs
if (!InputValidator.validateDID(did)) {
  throw new Error("Invalid DID format");
}
```

### DoS Prevention
```typescript
// Size limits
if (!InputValidator.validateCBORSize(data)) {
  throw new Error("Payload too large");
}
```

## 📊 Security Monitoring

### Audit Events
Monitor these security events in production:
- Failed signature verifications
- Rate limit exceeded
- Invalid DID formats
- Privilege escalation attempts
- Capability mismatches

### Log Analysis
```bash
# Search for security events
grep "SECURITY_AUDIT" logs/app.log

# Monitor failed verifications
grep "Failed verification" logs/app.log
```

### Alerting
Set up alerts for:
- Repeated failed verifications from same source
- Rate limit violations
- Privilege escalation attempts
- Unusual capability requests

## 🔍 Security Testing

### Unit Tests
- All security functions have comprehensive tests
- Edge cases and malformed inputs tested
- Timing attack resistance verified

### Integration Tests
- End-to-end security flows
- Rate limiting behavior
- Error handling validation

### Security Scanning
```bash
# Run security audit
npm audit

# Check for vulnerabilities
npm run test:security
```

## 🆘 Incident Response

### If Compromise Suspected
1. **Immediately rotate all keys**
2. **Review audit logs** for suspicious activity
3. **Check delegation chains** for unauthorized grants
4. **Revoke suspicious UCANs** if possible
5. **Update policies** to prevent recurrence

### Key Rotation Procedure
1. Generate new keys: `npm run ucan keygen`
2. Update environment variables
3. Restart services
4. Verify new key functionality
5. Securely dispose of old keys

## 📚 Additional Resources

- [UCAN Security Specification](https://github.com/ucan-wg/spec)
- [libsodium Documentation](https://doc.libsodium.org/)
- [OWASP Security Guidelines](https://owasp.org/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

## 🔄 Security Updates

This implementation follows security best practices, but security is an ongoing process:

1. **Monitor dependencies** for vulnerabilities
2. **Update regularly** to latest stable versions  
3. **Review code** for new security patterns
4. **Test thoroughly** after any changes
5. **Stay informed** about UCAN security advisories

For security issues, please follow responsible disclosure procedures and contact the maintainers privately.
