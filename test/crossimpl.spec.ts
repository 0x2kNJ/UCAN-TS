import { describe, it, expect } from "vitest";
import _sodium from "libsodium-wrappers";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { 
  Ed25519Signer,
  didKeyFromPublicKeyB64Url,
  signDelegationV1,
  cidForEnvelope,
  toB64Url,
  cidForBytes,
} from "../src/ucan/v1/index.js";

type GoUcanVector = {
  name: string;
  seedB64Url: string; // 32-byte Ed25519 seed
  payload: {
    iss: string;
    aud: string;
    att: Array<{ with: string; can: string; nb?: Record<string, any> }>;
    nbf: number;
    exp: number;
    prf?: string[];
    meta?: Record<string, any>;
  };
  expected: {
    did: string; // did:key of public key
    signatureB64Url: string;
    cid: string;
  };
};

describe("Cross-implementation vectors (go-ucan/spec)", () => {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const pinnedFiles = [
    path.join(__dirname, "fixtures", "go-ucan-vectors.json"),
    path.join(__dirname, "fixtures", "spec-delegation.json"),
    path.join(__dirname, "fixtures", "spec-invocation.json"),
  ].filter((p) => fs.existsSync(p));

  const envPath = process.env.UCAN_GO_VECTORS;
  const vectorsPathList = pinnedFiles.length > 0 ? pinnedFiles : (envPath ? [envPath] : []);

  if (vectorsPathList.length === 0) {
    it.skip("skips when no pinned fixtures and UCAN_GO_VECTORS not provided", () => {
      expect(true).toBe(true);
    });
    return;
  }

  it("validates vectors against expected signatures and CIDs", async () => {
    await _sodium.ready;
    const sodium = _sodium;

    for (const vectorsPath of vectorsPathList) {
      let raw: any;
      if (fs.existsSync(vectorsPath)) {
        raw = JSON.parse(fs.readFileSync(vectorsPath, "utf8"));
      } else {
        raw = await import(vectorsPath, { assert: { type: "json" } } as any).then((m: any) => m.default ?? m);
      }
      // Accept either our vector shape or go-ucan/spec interop fixture shape
      let vectors: GoUcanVector[] = Array.isArray(raw) ? raw : raw.vectors;
      if (!vectors && raw && raw.valid && Array.isArray(raw.valid)) {
        vectors = raw.valid.map((v: any, idx: number) => ({
          name: v.name || `interop-${idx}`,
          seedB64Url: "", // interop fixtures may not include seeds
          payload: v.envelope?.payload ?? {},
          expected: {
            did: v.envelope?.payload?.iss ?? "",
            signatureB64Url: (v.envelope?.signature || "").replace(/\s+/g, ""),
            cid: v.cid,
          }
        }));
      }

      for (const vec of vectors) {
        const seed = sodium.from_base64(vec.seedB64Url, sodium.base64_variants.URLSAFE_NO_PADDING);
        if (seed && seed.length === 32) {
          // Deterministic seed path
          const { privateKey, publicKey } = sodium.crypto_sign_seed_keypair(seed);
          const signer = new Ed25519Signer(privateKey);
          const did = didKeyFromPublicKeyB64Url(toB64Url(publicKey));
          expect(did).toBe(vec.expected.did);
          const env = await signDelegationV1(vec.payload as any, signer);
          const sigB64 = toB64Url(env.signatures[0].signature);
          expect(sigB64).toBe(vec.expected.signatureB64Url);
          const cid = await cidForEnvelope(env);
          expect(cid.toString()).toBe(vec.expected.cid);
        } else {
          // Interop fixture path: compute CID from sealed token bytes
          const base64pad = (vec as any).token as string | undefined;
          if (!base64pad) continue;
          const sealed = Buffer.from(base64pad.replace(/\s+/g, ""), 'base64');
          const cid = await cidForBytes(new Uint8Array(sealed));
          expect(cid.toString()).toBe(vec.expected.cid);
        }
      }
    }
  });
});


