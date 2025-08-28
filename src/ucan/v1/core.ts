import { encode as cborEncode, decode as cborDecode } from "@ipld/dag-cbor";
import { CarWriter, CarReader } from "@ipld/car";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";
import { base58btc } from "multiformats/bases/base58";
import _sodium from "libsodium-wrappers";

// Initialize sodium
await _sodium.ready;
const sodium = _sodium;

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
  prf?: string[];
  meta?: Record<string, any>;
}

export interface Envelope {
  payload: Uint8Array;
  signatures: Array<{ signature: Uint8Array }>;
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

export interface VerifyOptions {
  now?: number;
}

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

const DELEGATION_CONTEXT: Uint8Array = new TextEncoder().encode("ucan/delegation@v1");
const INVOCATION_CONTEXT: Uint8Array = new TextEncoder().encode("ucan/invocation@v1");

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
    return bytes.length === reencoded.length && bytes.every((b, i) => b === reencoded[i]);
  } catch {
    return false;
  }
}

export class Ed25519SignerCore {
  private secretKey: Uint8Array;

  constructor(secretKeyOrSeed: Uint8Array) {
    if (secretKeyOrSeed.length === 32) {
      const kp = sodium.crypto_sign_seed_keypair(secretKeyOrSeed);
      this.secretKey = kp.privateKey;
    } else if (secretKeyOrSeed.length === 64) {
      this.secretKey = secretKeyOrSeed.slice();
    } else {
      throw new Error("Invalid Ed25519 key: expected 32-byte seed or 64-byte secret key");
    }
  }

  static async generate(): Promise<{ signer: Ed25519SignerCore; publicKey: Uint8Array }> {
    const kp = sodium.crypto_sign_keypair();
    return { signer: new Ed25519SignerCore(kp.privateKey), publicKey: kp.publicKey };
  }

  async publicKey(): Promise<Uint8Array> {
    return this.secretKey.slice(32);
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return sodium.crypto_sign_detached(message, this.secretKey);
  }
}

export function didKeyFromPublicKeyB64Url(pkB64: string): string {
  const publicKey = fromB64Url(pkB64);
  const multicodecPublicKey = new Uint8Array([0xed, 0x01, ...publicKey]);
  const multibase = base58btc.encode(multicodecPublicKey);
  return `did:key:${multibase}`;
}

export function didKeyEd25519PublicKeyB64Url(did: string): string {
  if (!did.startsWith("did:key:z")) {
    throw new Error("Invalid did:key format");
  }
  const multibase = did.slice(8);
  const decoded = base58btc.decode(multibase);
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("Not an Ed25519 did:key");
  }
  const publicKey = decoded.slice(2);
  return toB64Url(publicKey);
}

export async function verifyEd25519(message: Uint8Array, signatureB64: string, publicKeyB64: string): Promise<boolean> {
  try {
    const signature = fromB64Url(signatureB64);
    const publicKey = fromB64Url(publicKeyB64);
    if (signature.length !== 64 || publicKey.length !== 32) return false;
    return sodium.crypto_sign_verify_detached(signature, message, publicKey);
  } catch {
    return false;
  }
}

export async function cidForEnvelope(env: Envelope): Promise<CID> {
  const bytes = cborEncode(env);
  const hash = await sha256.digest(bytes);
  return CID.create(1, 0x71, hash);
}

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
  const { writer, out } = CarWriter.create(cids);
  (async () => {
    for (const block of blocks) {
      await writer.put(block);
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
  const reader = await CarReader.fromBytes(containerBytes);
  const envelopes: Envelope[] = [];
  for await (const { bytes } of reader.blocks()) {
    try {
      const env = cborDecode(bytes) as Envelope;
      if (!env || !(env.payload instanceof Uint8Array) || !Array.isArray(env.signatures)) {
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

export async function signDelegationV1(payload: DelegationPayload, signer: Ed25519SignerCore): Promise<Envelope> {
  const payloadBytes = cborEncode(payload);
  const message = prefixMessage(DELEGATION_CONTEXT, payloadBytes);
  const signature = await signer.sign(message);
  return { payload: payloadBytes, signatures: [{ signature }] };
}

export async function verifyDelegationV1(env: Envelope, options: VerifyOptions = {}): Promise<VerifyResult> {
  try {
    if (!env.payload || !env.signatures) return { ok: false, reason: "invalid_format" };
    if (!isCanonicalCBOR(env.payload)) return { ok: false, reason: "invalid_format" };
    const payload = cborDecode(env.payload) as DelegationPayload;
    const t = options.now ?? now();
    if (payload.nbf > t) return { ok: false, reason: "not_yet_valid" };
    if (payload.exp <= t) return { ok: false, reason: "expired" };
    if (env.signatures.length === 0) return { ok: false, reason: "no_signatures" };
    const pkB64 = didKeyEd25519PublicKeyB64Url(payload.iss);
    const sigB64 = toB64Url(env.signatures[0].signature);
    const msg = prefixMessage(DELEGATION_CONTEXT, env.payload);
    const ok = await verifyEd25519(msg, sigB64, pkB64);
    return ok ? { ok: true } : { ok: false, reason: "bad_signature" };
  } catch {
    return { ok: false, reason: "invalid_format" };
  }
}

export async function signInvocationV1(payload: InvocationPayload, signer: Ed25519SignerCore): Promise<Envelope> {
  const payloadBytes = cborEncode(payload);
  const message = prefixMessage(INVOCATION_CONTEXT, payloadBytes);
  const signature = await signer.sign(message);
  return { payload: payloadBytes, signatures: [{ signature }] };
}

export async function verifyInvocationV1(env: Envelope, options: VerifyOptions = {}): Promise<VerifyResult> {
  try {
    if (!env.payload || !env.signatures) return { ok: false, reason: "invalid_format" };
    if (!isCanonicalCBOR(env.payload)) return { ok: false, reason: "invalid_format" };
    const payload = cborDecode(env.payload) as InvocationPayload;
    const t = options.now ?? now();
    if (payload.nbf > t) return { ok: false, reason: "not_yet_valid" };
    if (payload.exp <= t) return { ok: false, reason: "expired" };
    if (env.signatures.length === 0) return { ok: false, reason: "no_signatures" };
    const pkB64 = didKeyEd25519PublicKeyB64Url(payload.iss);
    const sigB64 = toB64Url(env.signatures[0].signature);
    const msg = prefixMessage(INVOCATION_CONTEXT, env.payload);
    const ok = await verifyEd25519(msg, sigB64, pkB64);
    return ok ? { ok: true } : { ok: false, reason: "bad_signature" };
  } catch {
    return { ok: false, reason: "invalid_format" };
  }
}


