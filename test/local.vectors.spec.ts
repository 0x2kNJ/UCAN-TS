import { describe, it, expect } from "vitest";
import _sodium from "libsodium-wrappers";
import vectors from "./fixtures/local-vectors.json" assert { type: "json" };
import { 
  Ed25519Signer,
  didKeyFromPublicKeyB64Url,
  signDelegationV1,
  cidForEnvelope,
  toB64Url,
} from "../src/ucan/v1/index.js";

type Vector = (typeof vectors)["vectors"][number];

describe("Local deterministic vectors", () => {
  it("match pinned DID, signature, and CID", async () => {
    await _sodium.ready;
    const sodium = _sodium;

    for (const vec of (vectors as { vectors: Vector[] }).vectors) {
      const seed = sodium.from_base64(vec.seedB64Url, sodium.base64_variants.URLSAFE_NO_PADDING);
      const { privateKey, publicKey } = sodium.crypto_sign_seed_keypair(seed);

      const signer = new Ed25519Signer(privateKey);
      const did = didKeyFromPublicKeyB64Url(toB64Url(publicKey));
      expect(did).toBe(vec.expected.did);

      const env = await signDelegationV1(vec.payload as any, signer);
      const sig = toB64Url(env.signatures[0].signature);
      expect(sig).toBe(vec.expected.signatureB64Url);

      const cid = await cidForEnvelope(env);
      expect(cid.toString()).toBe(vec.expected.cid);
    }
  });
});


