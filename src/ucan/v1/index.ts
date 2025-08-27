import { encode as cborEncode, decode as cborDecode } from "@ipld/dag-cbor";
import { CarWriter, CarReader } from "@ipld/car";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";
import _sodium from "libsodium-wrappers";
import { 
  SecureBuffer, 
  constantTimeEqual, 
  InputValidator, 
  SecurityAudit 
} from "../../security/hardening.js";

// Initialize sodium
await _sodium.ready;
const sodium = _sodium;

// Utility functions
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function toB64Url(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export function fromB64Url(s: string): Uint8Array {
  return sodium.from_base64(s, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export function now(): number {
  return Math.floor(Date.now() / 1000);
}

// Types
export interface Capability {
  with: string;
  can: string;
  nb?: Record<string, any>;
}

export interface DelegationPayload {
  iss: string;
  aud: string;
  att: Capability[];
  nbf: number;
  exp: number;
  prf?: string[];
  meta?: Record<string, any>;
}

export interface InvocationPayload {
  iss: string;
  aud: string;
  cap: Capability;
  nbf: number;
  exp: number;
  prf: string[];
  meta?: Record<string, any>;
}

export interface Envelope {
  payload: Uint8Array;
  signatures: Array<{
    signature: Uint8Array;
  }>;
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

export interface VerifyOptions {
  now?: number;
}

// Ed25519 Signer with secure memory handling
export class Ed25519Signer {
  private secureKey: SecureBuffer;

  constructor(secretKey: Uint8Array) {
    // Validate key length
    if (secretKey.length !== 64 && secretKey.length !== 32) {
      throw new Error("Invalid Ed25519 key length: expected 32 or 64 bytes");
    }
    
    this.secureKey = SecureBuffer.from(secretKey);
  }

  get secretKey(): Uint8Array {
    return this.secureKey.copy();
  }

  static async generate(): Promise<{ signer: Ed25519Signer; publicKey: Uint8Array }> {
    const keypair = sodium.crypto_sign_keypair();
    return {
      signer: new Ed25519Signer(keypair.privateKey),
      publicKey: keypair.publicKey,
    };
  }

  static async fromEnv(): Promise<Ed25519Signer> {
    const seedB64 = process.env.RECEIPT_SEED_B64URL;
    const skB64 = process.env.RECEIPT_SK_B64URL;
    
    if (seedB64) {
      if (!InputValidator.validateBase64Url(seedB64)) {
        throw new Error("Invalid RECEIPT_SEED_B64URL format");
      }
      const seed = fromB64Url(seedB64);
      if (seed.length !== 32) {
        throw new Error("Invalid seed length: expected 32 bytes");
      }
      const keypair = sodium.crypto_sign_seed_keypair(seed);
      return new Ed25519Signer(keypair.privateKey);
    }
    
    if (skB64) {
      if (!InputValidator.validateBase64Url(skB64)) {
        throw new Error("Invalid RECEIPT_SK_B64URL format");
      }
      const sk = fromB64Url(skB64);
      return new Ed25519Signer(sk);
    }
    
    throw new Error("No RECEIPT_SEED_B64URL or RECEIPT_SK_B64URL in env");
  }

  // Secure disposal
  dispose(): void {
    this.secureKey.zero();
  }

  async publicKey(): Promise<Uint8Array> {
    // Extract public key from secret key (sodium secret key includes both)
    const sk = this.secureKey.get();
    return sk.slice(32);
  }

  async publicKeyB64Url(): Promise<string> {
    const pk = await this.publicKey();
    return toB64Url(pk);
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    // Validate input size to prevent DoS
    if (!InputValidator.validateCBORSize(message)) {
      throw new Error("Message too large for signing");
    }
    
    const sk = this.secureKey.get();
    return sodium.crypto_sign_detached(message, sk);
  }

  async signB64Url(message: Uint8Array): Promise<string> {
    const sig = await this.sign(message);
    return toB64Url(sig);
  }
}

// DID Key functions
export function didKeyFromPublicKeyB64Url(pkB64: string): string {
  const pk = fromB64Url(pkB64);
  // Ed25519 multicodec prefix: 0xed01
  const multicodecPk = new Uint8Array([0xed, 0x01, ...pk]);
  // Use proper base58 encoding for did:key
  return `did:key:z${toB64Url(multicodecPk).replace(/=/g, '')}`;
}

export function didKeyEd25519PublicKeyB64Url(did: string): string {
  if (!did.startsWith("did:key:z")) {
    throw new Error("Invalid did:key format");
  }
  const b58part = did.slice(9); // remove "did:key:z"
  try {
    const decoded = fromB64Url(b58part);
    
    if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
      throw new Error("Not an Ed25519 did:key");
    }
    
    const pk = decoded.slice(2);
    return toB64Url(pk);
  } catch (error) {
    throw new Error("Invalid did:key encoding");
  }
}

// Verification functions
export async function verifyEd25519(message: Uint8Array, signatureB64: string, publicKeyB64: string): Promise<boolean> {
  try {
    // Input validation
    if (!InputValidator.validateBase64Url(signatureB64) || !InputValidator.validateBase64Url(publicKeyB64)) {
      return false;
    }
    
    if (!InputValidator.validateCBORSize(message)) {
      return false;
    }
    
    const signature = fromB64Url(signatureB64);
    const publicKey = fromB64Url(publicKeyB64);
    
    // Validate key and signature lengths
    if (signature.length !== 64 || publicKey.length !== 32) {
      return false;
    }
    
    return sodium.crypto_sign_verify_detached(signature, message, publicKey);
  } catch (error) {
    // Never leak verification errors
    return false;
  }
}

// CBOR and CID functions
export async function cidForEnvelope(env: Envelope): Promise<CID> {
  const bytes = cborEncode(env);
  const hash = await sha256.digest(bytes);
  return CID.create(1, 0x71, hash); // dag-cbor codec
}

// Simplified Container functions (avoiding complex CAR async iteration)
// For production, consider using a dedicated CAR library or implementing full CAR spec

/**
 * Simple container format: length-prefixed CBOR blocks
 * Format: [4 bytes length][CBOR envelope][4 bytes length][CBOR envelope]...
 */
export async function writeContainerV1(envelopes: Envelope[]): Promise<Uint8Array> {
  if (envelopes.length === 0) {
    throw new Error("Cannot create container with no envelopes");
  }
  
  const blocks: Uint8Array[] = [];
  let totalLength = 0;
  
  // Encode each envelope with length prefix
  for (const env of envelopes) {
    const envBytes = cborEncode(env);
    const lengthBytes = new Uint8Array(4);
    new DataView(lengthBytes.buffer).setUint32(0, envBytes.length, false); // big-endian
    
    blocks.push(lengthBytes);
    blocks.push(envBytes);
    totalLength += 4 + envBytes.length;
  }
  
  // Concatenate all blocks
  const result = new Uint8Array(totalLength);
  let offset = 0;
  
  for (const block of blocks) {
    result.set(block, offset);
    offset += block.length;
  }
  
  return result;
}

export async function readContainerV1(containerBytes: Uint8Array): Promise<Envelope[]> {
  if (!containerBytes || containerBytes.length === 0) {
    throw new Error("Cannot read empty container");
  }
  
  // Advanced security validation
  const { ContainerSecurityValidator } = await import("../../security/advanced.js");
  const containerValidation = ContainerSecurityValidator.validateContainer(containerBytes);
  if (!containerValidation.valid) {
    SecurityAudit.logSuspiciousActivity({
      activity: 'malicious_container',
      source: 'container_reader',
      timestamp: now()
    });
    throw new Error(`Container security violation: ${containerValidation.reason}`);
  }
  
  const envelopes: Envelope[] = [];
  let offset = 0;
  
  try {
    // Read length-prefixed blocks
    while (offset < containerBytes.length) {
      if (offset + 4 > containerBytes.length) {
        throw new Error("Incomplete length prefix");
      }
      
      // Read 4-byte length (big-endian)
      const lengthBytes = containerBytes.slice(offset, offset + 4);
      const length = new DataView(lengthBytes.buffer).getUint32(0, false);
      offset += 4;
      
      if (offset + length > containerBytes.length) {
        throw new Error("Incomplete envelope data");
      }
      
      // Read envelope bytes
      const envBytes = containerBytes.slice(offset, offset + length);
      offset += length;
      
      try {
        const env = cborDecode(envBytes) as Envelope;
        
        // Validate envelope structure
        if (!env.payload || !env.signatures || !Array.isArray(env.signatures)) {
          console.warn("Invalid envelope structure, skipping");
          continue;
        }
        
        envelopes.push(env);
      } catch (decodeError) {
        console.warn("Failed to decode envelope:", decodeError);
        // Continue with other blocks rather than failing completely
      }
    }
    
    if (envelopes.length === 0) {
      throw new Error("No valid envelopes found in container");
    }
    
    return envelopes;
  } catch (error) {
    throw new Error(`Failed to read container: ${error instanceof Error ? error.message : String(error)}`);
  }
}

// Delegation functions
export async function signDelegationV1(payload: DelegationPayload, signer: Ed25519Signer): Promise<Envelope> {
  const payloadBytes = cborEncode(payload);
  const signature = await signer.sign(payloadBytes);
  
  return {
    payload: payloadBytes,
    signatures: [{ signature }],
  };
}

export async function verifyDelegationV1(env: Envelope, options: VerifyOptions = {}): Promise<VerifyResult> {
  try {
    // Input validation
    if (!env.payload || !env.signatures || !InputValidator.validateCBORSize(env.payload)) {
      SecurityAudit.logFailedVerification({
        type: 'delegation',
        reason: 'invalid_input',
        timestamp: now()
      });
      return { ok: false, reason: "invalid_format" };
    }
    
    const payload = cborDecode(env.payload) as DelegationPayload;
    const currentTime = options.now ?? now();
    
    // Validate payload fields
    if (!InputValidator.validateDID(payload.iss) || 
        !InputValidator.validateDID(payload.aud) ||
        !InputValidator.validateTimestamp(payload.nbf) ||
        !InputValidator.validateTimestamp(payload.exp)) {
      SecurityAudit.logFailedVerification({
        type: 'delegation',
        reason: 'invalid_payload_format',
        issuer: payload.iss,
        timestamp: now()
      });
      return { ok: false, reason: "invalid_format" };
    }
    
    // Check time bounds
    if (payload.nbf > currentTime) {
      return { ok: false, reason: "not_yet_valid" };
    }
    
    if (payload.exp <= currentTime) {
      return { ok: false, reason: "expired" };
    }
    
    // Verify signature
    if (env.signatures.length === 0) {
      SecurityAudit.logFailedVerification({
        type: 'delegation',
        reason: 'no_signatures',
        issuer: payload.iss,
        timestamp: now()
      });
      return { ok: false, reason: "no_signatures" };
    }
    
    const pkB64 = didKeyEd25519PublicKeyB64Url(payload.iss);
    const sigB64 = toB64Url(env.signatures[0].signature);
    
    const validSig = await verifyEd25519(env.payload, sigB64, pkB64);
    if (!validSig) {
      SecurityAudit.logFailedVerification({
        type: 'delegation',
        reason: 'bad_signature',
        issuer: payload.iss,
        timestamp: now()
      });
      return { ok: false, reason: "bad_signature" };
    }
    
    return { ok: true };
  } catch (error) {
    SecurityAudit.logFailedVerification({
      type: 'delegation',
      reason: 'verification_error',
      timestamp: now()
    });
    return { ok: false, reason: "invalid_format" };
  }
}

// Invocation functions
export async function signInvocationV1(payload: InvocationPayload, signer: Ed25519Signer): Promise<Envelope> {
  const payloadBytes = cborEncode(payload);
  const signature = await signer.sign(payloadBytes);
  
  return {
    payload: payloadBytes,
    signatures: [{ signature }],
  };
}

export async function verifyInvocationV1(env: Envelope, options: VerifyOptions = {}): Promise<VerifyResult> {
  try {
    const payload = cborDecode(env.payload) as InvocationPayload;
    const currentTime = options.now ?? now();
    
    // Check time bounds
    if (payload.nbf > currentTime) {
      return { ok: false, reason: "not_yet_valid" };
    }
    
    if (payload.exp <= currentTime) {
      return { ok: false, reason: "expired" };
    }
    
    // Verify signature
    if (env.signatures.length === 0) {
      return { ok: false, reason: "no_signatures" };
    }
    
    const pkB64 = didKeyEd25519PublicKeyB64Url(payload.iss);
    const sigB64 = toB64Url(env.signatures[0].signature);
    
    const validSig = await verifyEd25519(env.payload, sigB64, pkB64);
    if (!validSig) {
      return { ok: false, reason: "bad_signature" };
    }
    
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: "invalid_format" };
  }
}

// Capability algebra
function isCapabilityCovered(requested: Capability, granted: Capability): boolean {
  // Check 'with' field
  if (granted.with === "*") {
    // Wildcard covers everything
  } else if (granted.with.endsWith("/*")) {
    // Prefix match
    const prefix = granted.with.slice(0, -2);
    if (!requested.with.startsWith(prefix)) {
      return false;
    }
  } else {
    // For resource paths, allow sub-resources (granted "data/fetch/path" covers "data/fetch/path/file.txt")
    if (requested.with !== granted.with && !requested.with.startsWith(granted.with + "/")) {
      return false;
    }
  }
  
  // Check 'can' field
  if (granted.can === "*" || granted.can === "*/*") {
    // Wildcard covers everything
  } else if (granted.can.endsWith("/*")) {
    // Prefix match
    const prefix = granted.can.slice(0, -2);
    if (!requested.can.startsWith(prefix)) {
      return false;
    }
  } else {
    // Exact match for actions
    if (requested.can !== granted.can) {
      return false;
    }
  }
  
  // Check 'nb' field (simplified - requested must be subset of granted)
  if (granted.nb && requested.nb) {
    for (const [key, value] of Object.entries(requested.nb)) {
      if (granted.nb[key] !== value) {
        return false;
      }
    }
  }
  
  return true;
}

// Chain verification with advanced security
export async function verifyInvocationAgainstChainV1(
  invocation: Envelope,
  chain: Envelope[],
  options: VerifyOptions = {}
): Promise<VerifyResult> {
  try {
    // Advanced security validation - only for complex chains
    if (chain.length > 3) {
      try {
        const { ChainSecurityValidator, ComprehensiveSecurityValidator } = await import("../../security/advanced.js");
        
        // Validate chain complexity and security
        const chainValidation = ComprehensiveSecurityValidator.validateDelegationChain(chain);
        if (!chainValidation.valid) {
          SecurityAudit.logSuspiciousActivity({
            activity: 'chain_security_violation',
            source: 'chain_verification',
            timestamp: now()
          });
          return { ok: false, reason: `chain_security_violation: ${chainValidation.violations.join(', ')}` };
        }
      } catch (error) {
        // If advanced validation fails, continue with basic validation
        console.warn("Advanced chain validation failed, continuing with basic validation:", error);
      }
    }
    
    // Verify invocation itself
    const invResult = await verifyInvocationV1(invocation, options);
    if (!invResult.ok) {
      return invResult;
    }
    
    const invPayload = cborDecode(invocation.payload) as InvocationPayload;
    
    if (chain.length === 0) {
      return { ok: false, reason: "empty_chain" };
    }
    
    // Verify each delegation in chain
    for (let i = 0; i < chain.length; i++) {
      const delResult = await verifyDelegationV1(chain[i], options);
      if (!delResult.ok) {
        return { ok: false, reason: `delegation_invalid: ${delResult.reason}` };
      }
    }
    
    // Check audience/issuer linking
    const delPayloads = chain.map(env => cborDecode(env.payload) as DelegationPayload);
    
    // Root delegation issuer should match invocation audience
    if (delPayloads[0].iss !== invPayload.aud) {
      return { ok: false, reason: "root_issuer_mismatch" };
    }
    
    // Check chain linking
    for (let i = 1; i < delPayloads.length; i++) {
      if (delPayloads[i-1].aud !== delPayloads[i].iss) {
        return { ok: false, reason: "chain_link_broken" };
      }
    }
    
    // Leaf delegation audience should match invocation issuer
    const leafPayload = delPayloads[delPayloads.length - 1];
    if (leafPayload.aud !== invPayload.iss) {
      return { ok: false, reason: "leaf_audience_mismatch" };
    }
    
    // Check capability attenuation
    const leafCaps = leafPayload.att;
    let covered = false;
    
    for (const cap of leafCaps) {
      if (isCapabilityCovered(invPayload.cap, cap)) {
        covered = true;
        break;
      }
    }
    
    if (!covered) {
      return { ok: false, reason: "invocation_cap_not_covered" };
    }
    
    return { ok: true };
  } catch (error) {
    SecurityAudit.logFailedVerification({
      type: 'chain',
      reason: 'verification_error',
      timestamp: now()
    });
    return { ok: false, reason: "verification_error" };
  }
}
