# UCAN TypeScript Implementation

A comprehensive, production-ready TypeScript implementation of User-Controlled Authorization Networks (UCAN) v1 with enterprise-grade security features.

## 🚀 Features

- **Complete UCAN v1 Support**: Full delegation and invocation envelope implementation
- **Enterprise Security**: Advanced threat protection and real-time monitoring
- **TypeScript Native**: Full type safety with strict mode compliance
- **Multi-Platform**: Node.js, Browser, and Cloudflare Workers support
- **Production Ready**: Battle-tested with comprehensive security hardening
- **CLI Toolkit**: Complete development and debugging tools
- **Express Integration**: Drop-in middleware for web applications

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Security Features](#security-features)
- [API Documentation](#api-documentation)
- [CLI Tools](#cli-tools)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)

## 🏁 Quick Start

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm run test

# Generate a keypair
npm run ucan keygen

# Create a delegation
npm run ucan delegate --key key.json --audience did:key:... --capability "data/read#read"
```

## 📦 Installation

```bash
npm install ucan-ts
```

### Dependencies

- **Node.js**: >= 18.0.0
- **TypeScript**: >= 5.0.0
- **libsodium-wrappers**: For cryptographic operations
- **@ipld/dag-cbor**: For CBOR encoding/decoding

## 🔧 Basic Usage

### Creating and Verifying Delegations

```typescript
import { 
  Ed25519Signer, 
  signDelegationV1, 
  verifyDelegationV1,
  didKeyFromPublicKeyB64Url,
  now 
} from 'ucan-ts';

// Generate a keypair
const { signer } = await Ed25519Signer.generate();
const did = didKeyFromPublicKeyB64Url(await signer.publicKeyB64Url());

// Create a delegation
const delegation = await signDelegationV1({
  iss: did,                              // Issuer DID
  aud: "did:key:recipient",              // Audience DID  
  att: [{                                // Capabilities
    with: "data/photos",
    can: "read"
  }],
  nbf: now(),                            // Valid from
  exp: now() + 3600                      // Expires in 1 hour
}, signer);

// Verify the delegation
const result = await verifyDelegationV1(delegation);
console.log(result.ok); // true
```

### Creating and Verifying Invocations

```typescript
import { signInvocationV1, verifyInvocationAgainstChainV1 } from 'ucan-ts';

// Create an invocation
const invocation = await signInvocationV1({
  iss: "did:key:invoker",
  aud: did,
  cap: {
    with: "data/photos/vacation.jpg",
    can: "read"
  },
  nbf: now(),
  exp: now() + 300                       // 5 minute validity
}, invokerSigner);

// Verify against delegation chain
const chainResult = await verifyInvocationAgainstChainV1(
  invocation, 
  [delegation]
);
console.log(chainResult.ok); // true if authorized
```

### Express.js Integration

```typescript
import express from 'express';
import { mountMint } from 'ucan-ts/express';

const app = express();

// Mount UCAN minting endpoint
mountMint(app);

// The endpoint will be available at POST /mcp/mint
app.listen(3000);
```

### Cloudflare Workers

```typescript
import { workerHandler } from 'ucan-ts/worker';

export default {
  async fetch(request: Request): Promise<Response> {
    return workerHandler(request);
  }
};
```

## 🛡️ Security Features

This implementation includes comprehensive security measures:

### Core Security
- **Memory Safety**: Automatic private key zeroing
- **Timing Attack Resistance**: Constant-time cryptographic operations
- **Input Validation**: Comprehensive format and size validation
- **Rate Limiting**: Configurable request throttling

### Advanced Security
- **Chain Attack Protection**: Depth limits, circular delegation detection
- **Resource Exhaustion Defense**: Memory limits, container size validation
- **Privilege Escalation Prevention**: Capability pattern analysis
- **Real-Time Monitoring**: Threat detection and automated response

### Security Configuration

```typescript
import { securityMonitor, SecurityLimits } from 'ucan-ts/security';

// Configure security limits
const limits = {
  MAX_CHAIN_DEPTH: 10,
  MAX_CAPABILITIES_PER_DELEGATION: 20,
  MAX_CONTAINER_SIZE: 50 * 1024 * 1024  // 50MB
};

// Monitor security events
securityMonitor.onAlert((event) => {
  console.log('Security alert:', event);
});
```

## 📚 API Documentation

### Core Classes

#### `Ed25519Signer`
Cryptographic signer for UCAN envelopes.

```typescript
class Ed25519Signer {
  static async generate(): Promise<{ signer: Ed25519Signer; publicKey: Uint8Array }>;
  static async fromEnv(): Promise<Ed25519Signer>;
  async sign(message: Uint8Array): Promise<Uint8Array>;
  async publicKeyB64Url(): Promise<string>;
  dispose(): void; // Secure memory cleanup
}
```

#### Core Functions

```typescript
// Delegation functions
async function signDelegationV1(payload: DelegationPayload, signer: Ed25519Signer): Promise<Envelope>;
async function verifyDelegationV1(envelope: Envelope, options?: VerifyOptions): Promise<VerifyResult>;

// Invocation functions  
async function signInvocationV1(payload: InvocationPayload, signer: Ed25519Signer): Promise<Envelope>;
async function verifyInvocationV1(envelope: Envelope, options?: VerifyOptions): Promise<VerifyResult>;
async function verifyInvocationAgainstChainV1(invocation: Envelope, chain: Envelope[], options?: VerifyOptions): Promise<VerifyResult>;

// Container functions
async function writeContainerV1(envelopes: Envelope[]): Promise<Uint8Array>;
async function readContainerV1(containerBytes: Uint8Array): Promise<Envelope[]>;

// Utility functions
function didKeyFromPublicKeyB64Url(publicKeyB64: string): string;
function didKeyEd25519PublicKeyB64Url(did: string): string;
function now(): number;
```

### Type Definitions

```typescript
interface DelegationPayload {
  iss: string;        // Issuer DID
  aud: string;        // Audience DID
  att: Capability[];  // Capabilities granted
  nbf: number;        // Not before (Unix timestamp)
  exp: number;        // Expires (Unix timestamp)
  prf?: string[];     // Proof references
  meta?: any;         // Metadata
}

interface InvocationPayload {
  iss: string;        // Issuer DID
  aud: string;        // Audience DID
  cap: Capability;    // Capability being invoked
  nbf: number;        // Not before
  exp: number;        // Expires
  meta?: any;         // Metadata
}

interface Capability {
  with: string;       // Resource identifier
  can: string;        // Action identifier
  nb?: any;           // Caveats/constraints
}
```

## 🔧 CLI Tools

The UCAN toolkit provides comprehensive command-line tools:

### Key Management
```bash
# Generate a new keypair
ucan-toolkit keygen --output my-key.json

# Convert between DID and public key formats
ucan-toolkit did-convert did:key:z6Mk...
ucan-toolkit did-convert Qm...
```

### Token Operations
```bash
# Inspect a UCAN token
ucan-toolkit inspect <token> --verify

# Create a delegation
ucan-toolkit delegate \
  --key service-key.json \
  --audience did:key:z6Mk... \
  --capability "data/photos#read" \
  --ttl 3600

# Verify a delegation chain
ucan-toolkit verify-chain \
  --invocation <token> \
  --chain <delegation1> <delegation2>
```

### Analytics
```bash
# Analyze tokens in a directory
ucan-toolkit stats ./tokens/
```

## 🚀 Deployment

### Environment Variables

```bash
# Required for production
RECEIPT_SEED_B64URL="base64url-encoded-32-byte-seed"
RECEIPT_SK_B64URL="base64url-encoded-64-byte-secret-key"

# Optional
REDIS_URL="redis://localhost:6379"          # For idempotency
POLICY_PATH="./config/policies.yaml"        # Policy configuration
UCAN_MAX_CHAIN_DEPTH="5"                   # Security limits
```

### Docker Deployment

```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

USER node
EXPOSE 3000

CMD ["node", "dist/server.js"]
```

### Security Configuration

```yaml
# config/policies.yaml
ttl_default_sec: 3600

methods:
  basic_read:
    ttl_sec: 3600
    caps:
      - "data/read"
  
  admin_access:
    ttl_sec: 900  # 15 minutes
    caps:
      - "admin/*"
```

## 🔍 Testing

```bash
# Run all tests
npm run test

# Run with coverage
npm run test:coverage

# Run security tests
npm run test test/security.advanced.spec.ts

# Watch mode
npm run test:watch
```

### Test Coverage
- **Unit Tests**: Core UCAN functionality
- **Integration Tests**: Express endpoints and workflows
- **Security Tests**: Advanced threat scenarios
- **Performance Tests**: Load and stress testing

## 🛡️ Security Considerations

### Production Checklist
- [ ] Generate strong, random keys using `ucan-toolkit keygen`
- [ ] Use HTTPS only in production
- [ ] Configure rate limiting appropriately
- [ ] Monitor security events and alerts
- [ ] Implement key rotation procedures
- [ ] Use environment variables for secrets
- [ ] Enable audit logging

### Key Management
```typescript
// Secure key generation
const { signer } = await Ed25519Signer.generate();

// Proper disposal
signer.dispose(); // Zeros memory

// Environment-based loading
const signer = await Ed25519Signer.fromEnv();
```

### Monitoring
```typescript
import { securityMonitor, logSecurityEvent } from 'ucan-ts/security';

// Custom security event
logSecurityEvent('warning', 'authentication', 'Failed login attempt', clientIP);

// Get security report
const report = securityMonitor.generateSecurityReport(24); // Last 24 hours
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/0x2kNJ/UCAN-TS.git
cd UCAN-TS
npm install
npm run build
npm run test
```

### Code Standards
- TypeScript strict mode
- Comprehensive testing
- Security-first approach
- Complete documentation

## 📖 Additional Documentation

- [Security Guide](docs/SECURITY.md) - Comprehensive security documentation
- [Advanced Security](docs/ADVANCED_SECURITY.md) - Advanced threat protection
- [API Reference](docs/API.md) - Complete API documentation
- [Examples](examples/) - Usage examples and tutorials

## 🔗 Related Projects

- [UCAN Specification](https://github.com/ucan-wg/spec) - Official UCAN specification
- [Go UCAN](https://github.com/ucan-wg/go-ucan) - Reference Go implementation
- [JavaScript UCAN](https://github.com/ucan-wg/js-ucan) - JavaScript implementation

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🏆 Acknowledgments

- [UCAN Working Group](https://github.com/ucan-wg) for the specification
- [Fission](https://fission.codes) for pioneering UCAN development
- [libsodium](https://libsodium.org) for cryptographic primitives

---

**Built with ❤️ for the decentralized web**

For questions, issues, or contributions, please visit our [GitHub repository](https://github.com/0x2kNJ/UCAN-TS).
