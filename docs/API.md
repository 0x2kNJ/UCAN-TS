# UCAN TypeScript API Reference

Complete API documentation for the UCAN TypeScript implementation.

## Table of Contents

- [Core Types](#core-types)
- [Cryptographic Classes](#cryptographic-classes)
- [UCAN Functions](#ucan-functions)
- [Security Classes](#security-classes)
- [Utility Functions](#utility-functions)
- [Express Integration](#express-integration)
- [Error Handling](#error-handling)

## Core Types

### `Capability`
Represents a capability with resource, action, and optional constraints.

```typescript
interface Capability {
  with: string;       // Resource identifier (e.g., "data/photos")
  can: string;        // Action identifier (e.g., "read", "write")
  nb?: Record<string, any>; // Named caveats/constraints
}
```

**Examples:**
```typescript
// Basic capability
{ with: "data/photos", can: "read" }

// Wildcard capability
{ with: "*", can: "*" }

// Capability with constraints
{ 
  with: "storage/bucket", 
  can: "write",
  nb: { maxSize: 1024 * 1024 } // 1MB limit
}
```

### `DelegationPayload`
Payload structure for delegation UCANs.

```typescript
interface DelegationPayload {
  iss: string;        // Issuer DID
  aud: string;        // Audience DID
  att: Capability[];  // Array of capabilities being delegated
  nbf: number;        // Not before (Unix timestamp)
  exp: number;        // Expires (Unix timestamp)
  prf?: string[];     // Array of proof CIDs (for delegation chains)
  meta?: Record<string, any>; // Optional metadata
}
```

### `InvocationPayload`
Payload structure for invocation UCANs.

```typescript
interface InvocationPayload {
  iss: string;        // Issuer DID (who is invoking)
  aud: string;        // Audience DID (service being invoked)
  cap: Capability;    // Single capability being invoked
  nbf: number;        // Not before (Unix timestamp)
  exp: number;        // Expires (Unix timestamp)
  meta?: Record<string, any>; // Optional metadata
}
```

### `Envelope`
Container for UCAN payloads with signatures.

```typescript
interface Envelope {
  payload: Uint8Array;    // CBOR-encoded payload
  signatures: Signature[]; // Array of signatures
}

interface Signature {
  signature: Uint8Array;  // Raw signature bytes
}
```

### `VerifyResult`
Result of UCAN verification operations.

```typescript
interface VerifyResult {
  ok: boolean;           // Whether verification succeeded
  reason?: string;       // Error reason if verification failed
}
```

### `VerifyOptions`
Options for verification functions.

```typescript
interface VerifyOptions {
  now?: number; // Override current time for testing
  isRevokedCID?: (cid: CID) => boolean | Promise<boolean>;
  isRevokedDID?: (did: string) => boolean | Promise<boolean>;
  onTransparencyCID?: (cid: CID, env: Envelope) => void;
  policy?: PolicyEvaluator; // Pluggable policy hook
}
```

## Cryptographic Classes

### Signers
#### `UcanSigner`
Generic signer interface (supports KMS/HSM/WebAuthn-backed signers).

```typescript
interface UcanSigner {
  sign(message: Uint8Array): Promise<Uint8Array>;
  publicKey?(): Promise<Uint8Array>;
  publicKeyB64Url?(): Promise<string>;
}
```

#### `ExternalSigner`
Wrapper for external signing functions.

```typescript
class ExternalSigner implements UcanSigner {
  constructor(
    signFn: (message: Uint8Array) => Promise<Uint8Array>,
    getPublicKeyFn?: () => Promise<Uint8Array>,
  )
}
```

#### `Ed25519Signer`
Core cryptographic signer for UCAN envelopes.

```typescript
class Ed25519Signer {
  constructor(secretKey: Uint8Array);
  
  // Static factory methods
  static async generate(): Promise<{ 
    signer: Ed25519Signer; 
    publicKey: Uint8Array 
  }>;
  static async fromEnv(): Promise<Ed25519Signer>;
  
  // Instance methods
  async publicKey(): Promise<Uint8Array>;
  async publicKeyB64Url(): Promise<string>;
  async sign(message: Uint8Array): Promise<Uint8Array>;
  async signB64Url(message: Uint8Array): Promise<string>;
  dispose(): void; // Secure memory cleanup
  
  // Property access
  get secretKey(): Uint8Array; // Returns copy, not reference
}
```

**Usage Examples:**

```typescript
// Generate new keypair
const { signer, publicKey } = await Ed25519Signer.generate();

// Load from environment variables
const signer = await Ed25519Signer.fromEnv();

// Sign data
const message = new TextEncoder().encode("Hello, UCAN!");
const signature = await signer.sign(message);

// Get public key as DID
const publicKeyB64 = await signer.publicKeyB64Url();
const did = didKeyFromPublicKeyB64Url(publicKeyB64);

// Secure cleanup
signer.dispose();
```

### `SecureBuffer`
Memory-safe buffer for sensitive data.

```typescript
class SecureBuffer {
  constructor(size: number);
  static from(data: Uint8Array): SecureBuffer;
  
  get(): Uint8Array;              // Get reference (dangerous)
  copy(): Uint8Array;             // Get safe copy
  zero(): void;                   // Securely zero memory
  [Symbol.dispose](): void;       // Automatic cleanup
}
```

## UCAN Functions

### Delegation Functions

#### `signDelegationV1`
Creates and signs a delegation UCAN.

```typescript
async function signDelegationV1(
  payload: DelegationPayload,
  signer: UcanSigner
): Promise<Envelope>
```

**Example:**
```typescript
const delegation = await signDelegationV1({
  iss: "did:key:issuer",
  aud: "did:key:audience", 
  att: [{ with: "data/photos", can: "read" }],
  nbf: now(),
  exp: now() + 3600
}, signer);
```

#### `verifyDelegationV1`
Verifies a delegation UCAN.

```typescript
async function verifyDelegationV1(
  envelope: Envelope, 
  options?: VerifyOptions
): Promise<VerifyResult>
```

**Example:**
```typescript
const result = await verifyDelegationV1(delegation);
if (result.ok) {
  console.log("Delegation is valid");
} else {
  console.log("Delegation failed:", result.reason);
}
```

### Invocation Functions

#### `signInvocationV1`
Creates and signs an invocation UCAN.

```typescript
async function signInvocationV1(
  payload: InvocationPayload,
  signer: UcanSigner
): Promise<Envelope>
```

#### `verifyInvocationV1`
Verifies an invocation UCAN.

```typescript
async function verifyInvocationV1(
  envelope: Envelope, 
  options?: VerifyOptions
): Promise<VerifyResult>
```

#### `verifyInvocationAgainstChainV1`
Verifies an invocation against a delegation chain.

```typescript
async function verifyInvocationAgainstChainV1(
  invocation: Envelope,
  chain: Envelope[],
  options?: VerifyOptions
): Promise<VerifyResult>
```

**Example:**
```typescript
// Create delegation chain: root -> intermediate -> leaf
const rootDelegation = await signDelegationV1(rootPayload, rootSigner);
const leafDelegation = await signDelegationV1(leafPayload, intermediateSigner);

// Verify invocation against chain
const result = await verifyInvocationAgainstChainV1(
  invocation, 
  [rootDelegation, leafDelegation]
);
```

### Container Functions

#### `writeContainerV1`
Serializes multiple UCANs into a container format.

```typescript
async function writeContainerV1(envelopes: Envelope[]): Promise<Uint8Array>
```

#### `readContainerV1`
Deserializes UCANs from a container format.

```typescript
async function readContainerV1(containerBytes: Uint8Array): Promise<Envelope[]>
```

**Example:**
```typescript
// Create container
const container = await writeContainerV1([delegation1, delegation2]);

// Read container
const envelopes = await readContainerV1(container);
```

## Security Classes

### `InputValidator`
Static validation methods for input sanitization.

```typescript
class InputValidator {
  static validateDID(did: string): boolean;
  static validateBase64Url(input: string): boolean;
  static validateCapabilityResource(resource: string): boolean;
  static validateCapabilityAction(action: string): boolean;
  static validateTimestamp(timestamp: number): boolean;
  static validateCBORSize(data: Uint8Array): boolean;
}
```

### `SecurityAudit`
Centralized security event logging.

```typescript
class SecurityAudit {
  static logFailedVerification(details: {
    type: 'delegation' | 'invocation' | 'chain';
    reason: string;
    issuer?: string;
    timestamp: number;
  }): void;
  
  static logSuspiciousActivity(details: {
    activity: string;
    source?: string;
    timestamp: number;
  }): void;
  
  static logPrivilegeEscalation(details: {
    requested: string;
    granted: string;
    issuer: string;
    timestamp: number;
  }): void;
}
```

### `RateLimiter`
Request rate limiting implementation.

```typescript
class RateLimiter {
  constructor(maxAttempts: number, windowMs: number);
  
  isAllowed(identifier: string): boolean;
  cleanup(): void;
}
```

### Advanced Security Classes

#### `ChainSecurityValidator`
Advanced delegation chain validation.

```typescript
class ChainSecurityValidator {
  static validateChainComplexity(chain: Envelope[]): { 
    valid: boolean; 
    reason?: string 
  };
  
  static validateDelegationComplexity(payload: DelegationPayload): { 
    valid: boolean; 
    reason?: string 
  };
  
  static detectCapabilityAnomalies(capabilities: Capability[]): string[];
}
```

#### `CapabilitySecurityAnalyzer`
Advanced capability security analysis.

```typescript
class CapabilitySecurityAnalyzer {
  static analyzePrivilegeEscalation(
    requestedCaps: Capability[], 
    grantedCaps: Capability[]
  ): { 
    safe: boolean; 
    violations: string[] 
  };
}
```

#### `SecurityMonitor`
Real-time security monitoring and threat detection.

```typescript
class SecurityMonitor {
  addEvent(event: SecurityEvent): void;
  onAlert(callback: (event: SecurityEvent) => void): void;
  getRecentEvents(minutes?: number): SecurityEvent[];
  getEventsByCategory(category: string, minutes?: number): SecurityEvent[];
  detectAttackPatterns(): AttackPattern[];
  generateSecurityReport(hours?: number): SecurityReport;
}
```

## Utility Functions

### DID Functions

#### `didKeyFromPublicKeyB64Url`
Converts a base64url public key to a did:key DID.

```typescript
function didKeyFromPublicKeyB64Url(publicKeyB64: string): string
```

#### `didKeyEd25519PublicKeyB64Url`
Extracts the public key from a did:key DID.

```typescript
function didKeyEd25519PublicKeyB64Url(did: string): string
```

### Encoding Functions

#### `toB64Url` / `fromB64Url`
Base64url encoding/decoding utilities.

```typescript
function toB64Url(bytes: Uint8Array): string
function fromB64Url(b64url: string): Uint8Array
```

### Time Functions

#### `now`
Returns current Unix timestamp.

```typescript
function now(): number
```

### CID Functions

#### `cidForEnvelope`
Generates a Content Identifier for a UCAN envelope.

```typescript
async function cidForEnvelope(envelope: Envelope): Promise<CID>
```

### Receipts

#### `ReceiptPayload`
Signed audit records for invocations or other actions.

```typescript
interface ReceiptPayload {
  req: CID; // CID of request envelope
  res: { ok: true } | { ok: false; err: string };
  ts: number; // Unix timestamp (seconds)
  pay?: { payer?: string; amount?: string; unit?: string };
  meta?: Record<string, any>;
}
```

#### `signReceiptV1`
```typescript
async function signReceiptV1(payload: ReceiptPayload, signer: UcanSigner): Promise<Envelope>
```

#### `verifyReceiptV1`
```typescript
async function verifyReceiptV1(env: Envelope, options?: VerifyOptions & { issuerDid?: string }): Promise<VerifyResult>
```

### Policy

#### `PolicyEvaluator`
```typescript
interface PolicyEvaluator {
  evaluate(
    invocation: InvocationPayload,
    delegations: DelegationPayload[],
    now: number
  ): Promise<{ ok: true } | { ok: false; reason?: string }> | { ok: true } | { ok: false; reason?: string };
}
```

## Express Integration

### `mountMint`
Mounts UCAN minting endpoint on Express app.

```typescript
function mountMint(app: Express, options?: MountOptions): void

interface MountOptions {
  path?: string;        // Default: '/mcp/mint'
  rateLimit?: {
    max: number;        // Max requests
    window: number;     // Time window in ms
  };
}
```

### Security Middleware

#### `rateLimitMiddleware`
Rate limiting middleware for Express.

```typescript
function rateLimitMiddleware(
  req: Request, 
  res: Response, 
  next: NextFunction
): void
```

#### `validateMintRequest`
Input validation middleware for minting requests.

```typescript
function validateMintRequest(
  req: Request, 
  res: Response, 
  next: NextFunction
): void
```

#### `securityHeaders`
Security headers middleware.

```typescript
function securityHeaders(
  req: Request, 
  res: Response, 
  next: NextFunction
): void
```

## Error Handling

### Common Error Scenarios

```typescript
// Verification errors
interface VerifyResult {
  ok: false;
  reason: 
    | "invalid_format"          // Malformed UCAN
    | "bad_signature"           // Invalid signature
    | "expired"                 // UCAN expired
    | "not_yet_valid"          // UCAN not yet valid
    | "no_signatures"          // Missing signatures
    | "empty_chain"            // Empty delegation chain
    | "root_issuer_mismatch"   // Chain root mismatch
    | "chain_link_broken"      // Broken chain link
    | "leaf_audience_mismatch" // Chain leaf mismatch
    | "invocation_cap_not_covered"
    | "revoked_cid"
    | "revoked_issuer"
    | `delegation_invalid: ${string}` // Delegation error bubbled to chain verification
    | `policy_denied: ${string}`;     // Denied by policy evaluator
}
```

### Security Errors

```typescript
// Container security errors
"container_too_large"         // Container exceeds size limit
"envelope_too_large"          // Individual envelope too large
"too_many_envelopes"         // Too many envelopes in container
"malformed_container"        // Invalid container format

// Chain security errors  
"chain_too_deep"             // Delegation chain too deep
"too_many_capabilities"      // Too many capabilities per delegation
"ttl_too_long"              // Delegation TTL too long
"circular_delegation"        // Circular delegation detected

// Time security errors
"timestamp_too_future"       // Timestamp too far in future
"timestamp_too_past"         // Timestamp too far in past
"invalid_time_range"         // Invalid nbf/exp range
"excessive_validity"         // Validity period too long
```

### Best Practices

1. **Always check `VerifyResult.ok`** before proceeding
2. **Handle all error cases** in production code
3. **Log security events** for monitoring
4. **Use appropriate error codes** for client responses
5. **Never expose internal errors** to clients

```typescript
// Good error handling
const result = await verifyDelegationV1(delegation);
if (!result.ok) {
  SecurityAudit.logFailedVerification({
    type: 'delegation',
    reason: result.reason,
    timestamp: now()
  });
  
  // Return appropriate HTTP status
  switch (result.reason) {
    case "expired":
      return res.status(401).json({ error: "token_expired" });
    case "bad_signature":
      return res.status(403).json({ error: "invalid_token" });
    default:
      return res.status(400).json({ error: "invalid_request" });
  }
}
```

This API reference covers all public interfaces and provides practical examples for common use cases. For more detailed examples, see the [examples directory](../examples/) in the repository.
