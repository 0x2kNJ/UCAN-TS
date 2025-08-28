import { encode as cborEncode, decode as cborDecode } from "@ipld/dag-cbor";
import { CarWriter, CarReader } from "@ipld/car";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";
import { base58btc } from "multiformats/bases/base58";
import _sodium from "libsodium-wrappers";
import { cryptoProvider } from "./crypto.js";
import { 
  SecureBuffer, 
  constantTimeEqual, 
  InputValidator 
} from "../../../security/hardening.js";

// Initialize sodium
await _sodium.ready;
const sodium = _sodium;

// Utility functions
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function toB64Url(bytes: Uint8Array): string { return cryptoProvider.toB64Url(bytes); }
export function fromB64Url(s: string): Uint8Array { return cryptoProvider.fromB64Url(s); }

export function now(): number {
  return Math.floor(Date.now() / 1000);
}

// Domain separation contexts for signatures
const DELEGATION_CONTEXT: Uint8Array = new TextEncoder().encode("ucan/delegation@v1");
const INVOCATION_CONTEXT: Uint8Array = new TextEncoder().encode("ucan/invocation@v1");
const RECEIPT_CONTEXT: Uint8Array = new TextEncoder().encode("ucan/receipt@v1");

function prefixMessage(prefix: Uint8Array, message: Uint8Array): Uint8Array {
  const out = new Uint8Array(prefix.length + message.length);
  out.set(prefix, 0);
  out.set(message, prefix.length);
  return out;
}

function isCanonicalCBOR(bytes: Uint8Array): boolean {
  try {
    const decoded = cborDecode(bytes);
    const reencoded = cborEncode(decoded);
    return constantTimeEqual(bytes, reencoded);
  } catch {
    return false;
  }
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
  // Optional revocation hooks
  isRevokedCID?: (cid: CID) => Promise<boolean> | boolean;
  isRevokedDID?: (did: string) => Promise<boolean> | boolean;
  // Optional transparency hook (e.g., append verified CIDs to an audit log)
  onTransparencyCID?: (cid: CID, env: Envelope) => void;
  // Optional policy evaluator for invocation + delegation chain
  policy?: PolicyEvaluator;
}

// Ed25519 Signer with secure memory handling
export interface UcanSigner {
  sign(message: Uint8Array): Promise<Uint8Array>;
  publicKey?(): Promise<Uint8Array>;
  publicKeyB64Url?(): Promise<string>;
}

// Ed25519 Signer with secure memory handling
export class Ed25519Signer implements UcanSigner {
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
    const keypair = await cryptoProvider.ed25519KeypairRandom();
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
      const keypair = await cryptoProvider.ed25519KeypairFromSeed(seed);
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
    return cryptoProvider.ed25519Sign(message, sk);
  }

  async signB64Url(message: Uint8Array): Promise<string> {
    const sig = await this.sign(message);
    return toB64Url(sig);
  }
}

// Generic external signer wrapper (e.g., KMS/HSM/WebAuthn)
export class ExternalSigner implements UcanSigner {
  private readonly signFn: (message: Uint8Array) => Promise<Uint8Array>;
  private readonly getPublicKeyFn?: () => Promise<Uint8Array>;

  constructor(
    signFn: (message: Uint8Array) => Promise<Uint8Array>,
    getPublicKeyFn?: () => Promise<Uint8Array>,
  ) {
    this.signFn = signFn;
    this.getPublicKeyFn = getPublicKeyFn;
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    if (!InputValidator.validateCBORSize(message)) {
      throw new Error("Message too large for signing");
    }
    return this.signFn(message);
  }

  async publicKey(): Promise<Uint8Array> {
    if (!this.getPublicKeyFn) throw new Error("Public key not available for ExternalSigner");
    return this.getPublicKeyFn();
  }

  async publicKeyB64Url(): Promise<string> {
    const pk = await this.publicKey();
    return toB64Url(pk);
  }
}

// DID Key functions
export function didKeyFromPublicKeyB64Url(pkB64: string): string {
  const publicKey = fromB64Url(pkB64);
  // Ed25519 multicodec prefix: 0xed01
  const multicodecPublicKey = new Uint8Array([0xed, 0x01, ...publicKey]);
  // did:key requires multibase base58btc (z-prefix)
  const multibase = base58btc.encode(multicodecPublicKey); // already z-prefixed
  return `did:key:${multibase}`;
}

export function didKeyEd25519PublicKeyB64Url(did: string): string {
  if (!did.startsWith("did:key:z")) {
    throw new Error("Invalid did:key format");
  }
  const multibase = did.slice(8); // remove "did:key:"
  try {
    const decoded = base58btc.decode(multibase); // validates z-prefix
    if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
      throw new Error("Not an Ed25519 did:key");
    }
    const publicKey = decoded.slice(2);
    return toB64Url(publicKey);
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
    
    return cryptoProvider.ed25519Verify(message, signature, publicKey);
  } catch {
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

// Compute CID directly from sealed DAG-CBOR bytes (interop helper)
export async function cidForBytes(bytes: Uint8Array): Promise<CID> {
  const hash = await sha256.digest(bytes);
  return CID.create(1, 0x71, hash);
}

// Container functions (CAR v1)
export async function writeContainerV1(envelopes: Envelope[]): Promise<Uint8Array> {
  if (envelopes.length === 0) {
    throw new Error("Cannot create container with no envelopes");
  }

  const cids: CID[] = [];
  const blocks: { cid: CID; bytes: Uint8Array }[] = [];
  for (const env of envelopes) {
    const bytes = cborEncode(env);
    const cid = await cidForEnvelope(env);
    cids.push(cid);
    blocks.push({ cid, bytes });
  }

  // Avoid type conflicts between multiformats versions in deps by casting
  const root = cids[0];
  const { writer, out } = CarWriter.create(root as any);

  (async () => {
    // Put root first, then others
    const rootBlock = blocks.find(b => (b.cid as any).toString() === (root as any).toString());
    if (rootBlock) await (writer as any).put(rootBlock as any);
    for (const block of blocks) {
      if ((block.cid as any).toString() === (root as any).toString()) continue;
      await (writer as any).put(block as any);
    }
    await writer.close();
  })();

  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of out) {
    chunks.push(chunk);
    total += chunk.length;
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

export async function readContainerV1(containerBytes: Uint8Array): Promise<Envelope[]> {
  if (!containerBytes || containerBytes.length === 0) {
    throw new Error("Cannot read empty container");
  }

  // Read as CAR v1
  const reader = await CarReader.fromBytes(containerBytes);
  const envelopes: Envelope[] = [];
  for await (const { bytes } of reader.blocks()) {
    try {
      const env = cborDecode(bytes) as Envelope;
      if (!env.payload || !env.signatures || !Array.isArray(env.signatures)) {
        continue;
      }
      envelopes.push(env);
    } catch {
      // skip invalid blocks
    }
  }
  if (envelopes.length === 0) {
    throw new Error("No valid envelopes found in container");
  }
  return envelopes;
}

// Delegation functions
export async function signDelegationV1(payload: DelegationPayload, signer: UcanSigner): Promise<Envelope> {
  const payloadBytes = cborEncode(payload);
  const message = prefixMessage(DELEGATION_CONTEXT, payloadBytes);
  const signature = await signer.sign(message);
  
  return {
    payload: payloadBytes,
    signatures: [{ signature }],
  };
}

export async function verifyDelegationV1(env: Envelope, options: VerifyOptions = {}): Promise<VerifyResult> {
  try {
    if (!env.payload || !env.signatures || !InputValidator.validateCBORSize(env.payload)) {
      return { ok: false, reason: "invalid_format" };
    }
    
    const payload = cborDecode(env.payload) as DelegationPayload;
    const currentTime = options.now ?? now();
    
    // Validate payload fields
    if (!InputValidator.validateDID(payload.iss) || 
        !InputValidator.validateDID(payload.aud) ||
        !InputValidator.validateTimestamp(payload.nbf) ||
        !InputValidator.validateTimestamp(payload.exp)) {
      return { ok: false, reason: "invalid_format" };
    }
    
    // Enforce canonical DAG-CBOR encoding
    if (!isCanonicalCBOR(env.payload)) {
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
      return { ok: false, reason: "no_signatures" };
    }
    
    const pkB64 = didKeyEd25519PublicKeyB64Url(payload.iss);
    const sigB64 = toB64Url(env.signatures[0].signature);
    
    const message = prefixMessage(DELEGATION_CONTEXT, env.payload);
    const validSig = await verifyEd25519(message, sigB64, pkB64);
    if (!validSig) {
      return { ok: false, reason: "bad_signature" };
    }
    // Optional transparency + revocation checks
    if (options.isRevokedCID || options.onTransparencyCID) {
      const cid = await cidForEnvelope(env);
      if (options.onTransparencyCID) options.onTransparencyCID(cid, env);
      if (options.isRevokedCID && (await options.isRevokedCID(cid))) {
        return { ok: false, reason: "revoked_cid" };
      }
    }
    if (options.isRevokedDID && (await options.isRevokedDID(payload.iss))) {
      return { ok: false, reason: "revoked_issuer" };
    }
    
    return { ok: true };
  } catch {
    return { ok: false, reason: "invalid_format" };
  }
}

// Invocation functions
export async function signInvocationV1(payload: InvocationPayload, signer: UcanSigner): Promise<Envelope> {
  const payloadBytes = cborEncode(payload);
  const message = prefixMessage(INVOCATION_CONTEXT, payloadBytes);
  const signature = await signer.sign(message);
  
  return {
    payload: payloadBytes,
    signatures: [{ signature }],
  };
}

export async function verifyInvocationV1(env: Envelope, options: VerifyOptions = {}): Promise<VerifyResult> {
  try {
    if (!env.payload || !env.signatures || !InputValidator.validateCBORSize(env.payload)) {
      return { ok: false, reason: "invalid_format" };
    }

    const payload = cborDecode(env.payload) as InvocationPayload;
    const currentTime = options.now ?? now();
    
    // Validate payload fields
    if (!InputValidator.validateDID(payload.iss) || 
        !InputValidator.validateDID(payload.aud) ||
        !InputValidator.validateTimestamp(payload.nbf) ||
        !InputValidator.validateTimestamp(payload.exp)) {
      return { ok: false, reason: "invalid_format" };
    }
    
    // Enforce canonical DAG-CBOR encoding
    if (!isCanonicalCBOR(env.payload)) {
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
      return { ok: false, reason: "no_signatures" };
    }
    
    const pkB64 = didKeyEd25519PublicKeyB64Url(payload.iss);
    const sigB64 = toB64Url(env.signatures[0].signature);
    
    const message = prefixMessage(INVOCATION_CONTEXT, env.payload);
    const validSig = await verifyEd25519(message, sigB64, pkB64);
    if (!validSig) {
      return { ok: false, reason: "bad_signature" };
    }
    // Optional transparency + revocation checks
    if (options.isRevokedCID || options.onTransparencyCID) {
      const cid = await cidForEnvelope(env);
      if (options.onTransparencyCID) options.onTransparencyCID(cid, env);
      if (options.isRevokedCID && (await options.isRevokedCID(cid))) {
        return { ok: false, reason: "revoked_cid" };
      }
    }
    if (options.isRevokedDID && (await options.isRevokedDID(payload.iss))) {
      return { ok: false, reason: "revoked_issuer" };
    }
    
    return { ok: true };
  } catch {
    return { ok: false, reason: "invalid_format" };
  }
}

// Capability algebra
function normalizeResourcePath(p: string): string {
  // collapse multiple slashes, remove trailing slash except root, remove ./, prevent .. segments
  const parts = p.split('/').filter(seg => seg.length > 0 && seg !== '.');
  const stack: string[] = [];
  for (const seg of parts) {
    if (seg === '..') { if (stack.length) stack.pop(); else return p; } else stack.push(seg);
  }
  return stack.join('/');
}

function isCapabilityCovered(requested: Capability, granted: Capability): boolean {
  // Check 'with' field
  const reqWith = normalizeResourcePath(requested.with);
  const grWith = granted.with === '*' ? '*' : normalizeResourcePath(granted.with);
  if (grWith === "*") {
    // Wildcard covers everything
  } else if (grWith.endsWith("/*")) {
    // Prefix match
    const prefix = grWith.slice(0, -2);
    if (!reqWith.startsWith(prefix)) {
      return false;
    }
  } else {
    // For resource paths, allow sub-resources
    if (reqWith !== grWith && !reqWith.startsWith(grWith + "/")) {
      return false;
    }
  }
  
  // Check 'can' field
  const reqCan = requested.can;
  const grCan = granted.can;
  if (grCan === "*" || grCan === "*/*") {
    // Wildcard covers everything
  } else if (grCan.endsWith("/*")) {
    // Prefix match
    const prefix = grCan.slice(0, -2);
    if (!reqCan.startsWith(prefix)) {
      return false;
    }
  } else {
    // Exact match for actions
    if (reqCan !== grCan) {
      return false;
    }
  }
  
  // Check 'nb' field (simplified - requested must be subset of granted)
  if (granted.nb && requested.nb) {
    for (const [key, value] of Object.entries(requested.nb)) {
      if (!(key in granted.nb)) return false;
      const gv = (granted.nb as any)[key];
      if (typeof value === 'object' && value !== null && typeof gv === 'object' && gv !== null) {
        // shallow structural equality
        if (JSON.stringify(value) !== JSON.stringify(gv)) return false;
      } else if (gv !== value) {
        return false;
      }
    }
  }
  
  return true;
}

// Chain verification (core-only)
export async function verifyInvocationAgainstChainV1(
  invocation: Envelope,
  chain: Envelope[],
  options: VerifyOptions = {}
): Promise<VerifyResult> {
  try {
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
      // Per-delegation revocation transparency
      if (options.isRevokedCID || options.onTransparencyCID) {
        const cid = await cidForEnvelope(chain[i]);
        if (options.isRevokedCID && (await options.isRevokedCID(cid))) {
          return { ok: false, reason: "revoked_cid" };
        }
        if (options.onTransparencyCID) options.onTransparencyCID(cid, chain[i]);
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
    // Optional policy evaluator
    if (options.policy) {
      const policyResult = await options.policy.evaluate(invPayload, delPayloads, options.now ?? now());
      if (!policyResult.ok) {
        return { ok: false, reason: policyResult.reason ? `policy_denied: ${policyResult.reason}` : "policy_denied" };
      }
    }
    
    return { ok: true };
  } catch {
    return { ok: false, reason: "verification_error" };
  }
}

// Policy evaluator interface (pluggable)
export interface PolicyEvaluator {
  evaluate(
    invocation: InvocationPayload,
    delegations: DelegationPayload[],
    now: number
  ): Promise<{ ok: true } | { ok: false; reason?: string }> | { ok: true } | { ok: false; reason?: string };
}

// Deterministic receipts (audit-friendly)
export interface ReceiptPayload {
  // CID of the request envelope (invocation or other)
  req: CID;
  // Result status and optional error
  res: { ok: true } | { ok: false; err: string };
  // Unix timestamp (seconds)
  ts: number;
  // Optional payment attestation
  pay?: {
    payer?: string; // DID or account id
    amount?: string; // decimal string
    unit?: string; // e.g., USD, credits
  };
  meta?: Record<string, any>;
}

export async function signReceiptV1(payload: ReceiptPayload, signer: UcanSigner): Promise<Envelope> {
  const payloadBytes = cborEncode(payload);
  const message = prefixMessage(RECEIPT_CONTEXT, payloadBytes);
  const signature = await signer.sign(message);
  return { payload: payloadBytes, signatures: [{ signature }] };
}

export async function verifyReceiptV1(env: Envelope, options: VerifyOptions & { issuerDid?: string } = {}): Promise<VerifyResult> {
  try {
    if (!env.payload || !env.signatures || !InputValidator.validateCBORSize(env.payload)) {
      return { ok: false, reason: "invalid_format" };
    }
    if (!isCanonicalCBOR(env.payload)) {
      return { ok: false, reason: "invalid_format" };
    }
    const payload = cborDecode(env.payload) as ReceiptPayload;
    if (!payload || typeof payload.ts !== 'number' || !payload.req) {
      return { ok: false, reason: "invalid_format" };
    }
    // If issuer DID is provided, verify with its public key; otherwise accept as structurally valid
    if (options.issuerDid) {
      const pkB64 = didKeyEd25519PublicKeyB64Url(options.issuerDid);
      const sigB64 = toB64Url(env.signatures[0].signature);
      const message = prefixMessage(RECEIPT_CONTEXT, env.payload);
      const ok = await verifyEd25519(message, sigB64, pkB64);
      if (!ok) return { ok: false, reason: "bad_signature" };
    }
    if (options.isRevokedCID || options.onTransparencyCID) {
      const cid = await cidForEnvelope(env);
      if (options.onTransparencyCID) options.onTransparencyCID(cid, env);
      if (options.isRevokedCID && (await options.isRevokedCID(cid))) return { ok: false, reason: "revoked_cid" };
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: "invalid_format" };
  }
}


