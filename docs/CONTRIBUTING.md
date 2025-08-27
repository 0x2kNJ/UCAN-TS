# Contributing to UCAN TypeScript

Thank you for your interest in contributing to the UCAN TypeScript implementation! This guide will help you get started with contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Testing](#testing)
- [Security Considerations](#security-considerations)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## 🤝 Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) to help us maintain a welcoming community.

## 🚀 Getting Started

### Prerequisites

- **Node.js**: >= 18.0.0
- **npm**: >= 8.0.0
- **Git**: Latest version
- **TypeScript**: >= 5.0.0

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/YOUR_USERNAME/UCAN-TS.git
cd UCAN-TS
```

3. Add the upstream repository:

```bash
git remote add upstream https://github.com/0x2kNJ/UCAN-TS.git
```

## 🛠️ Development Setup

### Initial Setup

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Run tests to ensure everything works
npm run test

# Run linting
npm run lint
```

### Development Scripts

```bash
npm run build         # Build TypeScript to JavaScript
npm run test          # Run all tests
npm run test:watch    # Run tests in watch mode
npm run test:coverage # Run tests with coverage report
npm run lint          # Run ESLint
npm run lint:fix      # Fix linting issues automatically
npm run dev           # Start development server
npm run ucan          # Run CLI toolkit
```

### Project Structure

```
src/
├── ucan/v1/           # Core UCAN v1 implementation
│   ├── index.ts       # Main UCAN functions
│   ├── encryption.ts  # Encryption utilities
│   └── did.ts         # DID resolution
├── security/          # Security framework
│   ├── hardening.ts   # Basic security utilities
│   ├── advanced.ts    # Advanced threat protection
│   └── monitoring.ts  # Real-time monitoring
├── mint/              # UCAN minting service
│   ├── handler.ts     # Request handlers
│   ├── deps-env.ts    # Dependencies
│   └── security.ts    # Security middleware
└── cli/               # Command-line tools
    └── toolkit.ts     # CLI implementation

test/                  # Test files
├── ucan.v1.spec.ts    # Core UCAN tests
├── encryption.spec.ts # Encryption tests
├── security.advanced.spec.ts # Security tests
└── mint.express.spec.ts      # Integration tests

docs/                  # Documentation
├── API.md             # API reference
├── SECURITY.md        # Security guide
└── ADVANCED_SECURITY.md # Advanced security

config/                # Configuration files
└── policies.yaml      # Policy definitions
```

## 📝 Contributing Guidelines

### Code Style

We follow strict TypeScript coding standards:

```typescript
// ✅ Good
interface UserProfile {
  id: string;
  name: string;
  email: string;
}

async function getUserProfile(id: string): Promise<UserProfile> {
  const user = await fetchUser(id);
  return {
    id: user.id,
    name: user.fullName,
    email: user.emailAddress
  };
}

// ❌ Bad
interface userprofile {
  id: any;
  name: any;
}

function getUserProfile(id) {
  return fetchUser(id);
}
```

### TypeScript Guidelines

1. **Use strict mode**: All TypeScript must compile with strict mode enabled
2. **Explicit types**: Avoid `any`, use explicit type annotations
3. **Interfaces over types**: Prefer interfaces for object shapes
4. **Async/await**: Use async/await over Promises for readability
5. **Error handling**: Always handle errors explicitly

### Security Guidelines

This is a security-critical project. All contributions must follow security best practices:

1. **Input validation**: Validate all inputs thoroughly
2. **Memory safety**: Use SecureBuffer for sensitive data
3. **Constant-time operations**: Use timing-safe comparisons
4. **Error handling**: Never leak sensitive information in errors
5. **Audit logging**: Log security-relevant events

```typescript
// ✅ Security-conscious code
function validateDID(did: string): boolean {
  if (!InputValidator.validateDID(did)) {
    SecurityAudit.logSuspiciousActivity({
      activity: 'invalid_did_format',
      source: 'validation',
      timestamp: now()
    });
    return false;
  }
  return true;
}

// ❌ Security-problematic code
function validateDID(did: string): boolean {
  return did.startsWith('did:'); // Insufficient validation
}
```

### Commit Message Format

We use conventional commit messages:

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Build/tooling changes
- `security`: Security-related changes

**Examples:**
```
feat(ucan): add delegation chain validation
fix(security): prevent timing attack in signature verification
docs(api): update API documentation for new functions
security(validation): add input sanitization for DID fields
```

## 🧪 Testing

### Test Requirements

All contributions must include comprehensive tests:

1. **Unit tests**: Test individual functions and classes
2. **Integration tests**: Test component interactions
3. **Security tests**: Test security features and edge cases
4. **Error cases**: Test all error conditions

### Writing Tests

```typescript
// Example test structure
describe('UCAN Delegation', () => {
  describe('signDelegationV1', () => {
    it('should create valid delegation', async () => {
      const { signer } = await Ed25519Signer.generate();
      const payload = {
        iss: 'did:key:test',
        aud: 'did:key:test',
        att: [{ with: 'data', can: 'read' }],
        nbf: now(),
        exp: now() + 3600
      };
      
      const delegation = await signDelegationV1(payload, signer);
      expect(delegation).toBeDefined();
      expect(delegation.payload).toBeInstanceOf(Uint8Array);
      expect(delegation.signatures.length).toBe(1);
      
      // Verify the delegation
      const result = await verifyDelegationV1(delegation);
      expect(result.ok).toBe(true);
    });
    
    it('should reject invalid payload', async () => {
      const { signer } = await Ed25519Signer.generate();
      const invalidPayload = {
        iss: 'invalid-did',
        aud: 'did:key:test',
        att: [],
        nbf: now(),
        exp: now() - 1000 // Expired
      };
      
      await expect(signDelegationV1(invalidPayload, signer))
        .rejects.toThrow();
    });
  });
});
```

### Security Test Requirements

Security tests must cover:

1. **Attack scenarios**: Test known attack vectors
2. **Input fuzzing**: Test with malformed inputs
3. **Resource exhaustion**: Test with large inputs
4. **Timing attacks**: Verify constant-time operations

```typescript
describe('Security Features', () => {
  it('should prevent chain bombing attack', async () => {
    const chain = createDeepChain(MAX_CHAIN_DEPTH + 1);
    const result = ChainSecurityValidator.validateChainComplexity(chain);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('chain_too_deep');
  });
  
  it('should use constant-time comparison', () => {
    const start = performance.now();
    constantTimeEqual(new Uint8Array(32), new Uint8Array(32));
    const time1 = performance.now() - start;
    
    const start2 = performance.now();
    constantTimeEqual(new Uint8Array(32), new Uint8Array(32).fill(255));
    const time2 = performance.now() - start2;
    
    // Time difference should be minimal (timing-safe)
    expect(Math.abs(time1 - time2)).toBeLessThan(1); // 1ms tolerance
  });
});
```

### Running Tests

```bash
# Run all tests
npm run test

# Run specific test file
npm run test test/ucan.v1.spec.ts

# Run with coverage
npm run test:coverage

# Run security tests only
npm run test test/security.advanced.spec.ts

# Run in watch mode
npm run test:watch
```

## 🔒 Security Considerations

### Security Review Process

All security-related changes undergo additional review:

1. **Threat modeling**: Analyze potential security impacts
2. **Code review**: Security-focused code review
3. **Testing**: Comprehensive security testing
4. **Documentation**: Update security documentation

### Sensitive Areas

Pay special attention to these areas:

- **Cryptographic operations**: Signing, verification, key handling
- **Input validation**: All user inputs and external data
- **Memory management**: Sensitive data handling
- **Chain validation**: Delegation chain logic
- **Rate limiting**: DoS protection mechanisms

### Security Disclosure

For security vulnerabilities:

1. **Do not** create public issues for security vulnerabilities
2. **Email** security issues to: [security@example.com]
3. **Include** detailed reproduction steps
4. **Allow** reasonable time for response before disclosure

## 📖 Documentation

### Documentation Requirements

All contributions must include appropriate documentation:

1. **API documentation**: JSDoc comments for all public APIs
2. **README updates**: Update README.md for new features
3. **Examples**: Provide usage examples
4. **Security notes**: Document security implications

### JSDoc Standards

```typescript
/**
 * Signs a UCAN delegation with the provided signer.
 * 
 * @param payload - The delegation payload to sign
 * @param signer - Ed25519 signer instance
 * @returns Promise resolving to signed envelope
 * 
 * @throws {Error} When payload validation fails
 * @throws {SecurityError} When security limits are exceeded
 * 
 * @example
 * ```typescript
 * const delegation = await signDelegationV1({
 *   iss: "did:key:issuer",
 *   aud: "did:key:audience",
 *   att: [{ with: "data", can: "read" }],
 *   nbf: now(),
 *   exp: now() + 3600
 * }, signer);
 * ```
 * 
 * @security This function performs input validation and logs security events
 */
async function signDelegationV1(
  payload: DelegationPayload, 
  signer: Ed25519Signer
): Promise<Envelope>
```

## 🔄 Pull Request Process

### Before Submitting

1. **Update your fork**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Create feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes** following the guidelines above

4. **Test thoroughly**:
   ```bash
   npm run test
   npm run lint
   npm run build
   ```

5. **Update documentation** as needed

### Pull Request Guidelines

1. **Clear title**: Describe what the PR does
2. **Detailed description**: Explain the changes and why
3. **Test coverage**: Ensure tests cover new functionality
4. **Breaking changes**: Clearly document any breaking changes
5. **Security impact**: Note any security implications

### PR Template

```markdown
## Description
Brief description of the changes.

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that breaks existing functionality)
- [ ] Security enhancement
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Security tests pass
- [ ] Manual testing completed

## Security Checklist
- [ ] Input validation added/updated
- [ ] Security tests included
- [ ] No sensitive data in logs
- [ ] Constant-time operations used where appropriate

## Documentation
- [ ] API documentation updated
- [ ] README updated (if needed)
- [ ] Examples provided
```

### Review Process

1. **Automated checks**: CI/CD pipeline runs all tests
2. **Code review**: At least one maintainer reviews the code
3. **Security review**: Security-focused review for sensitive changes
4. **Documentation review**: Documentation is clear and complete

## 🚀 Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

### Release Steps

1. **Version bump**: Update version in package.json
2. **Changelog**: Update CHANGELOG.md with changes
3. **Tag release**: Create git tag with version
4. **Publish**: Publish to npm registry
5. **Documentation**: Update documentation website

## 💬 Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Discord**: Real-time chat (link in README)
- **Email**: security@example.com for security issues

### Questions?

Feel free to ask questions by:

1. Opening a GitHub Discussion
2. Creating an issue with the "question" label
3. Joining our Discord community

## 🏆 Recognition

Contributors will be recognized in:

- **CONTRIBUTORS.md**: List of all contributors
- **Release notes**: Notable contributions highlighted
- **README**: Major contributors acknowledged

Thank you for contributing to UCAN TypeScript! Your efforts help build a more secure and decentralized web.
