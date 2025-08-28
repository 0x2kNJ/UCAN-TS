import { describe, it, expect, vi } from "vitest";
import {
  Ed25519Signer,
  ExternalSigner,
  didKeyFromPublicKeyB64Url,
  toB64Url,
  signReceiptV1,
  verifyReceiptV1,
  cidForEnvelope,
  now,
} from "../src/ucan/v1/index.js";

describe("Deterministic receipts", () => {
  it("signs and verifies a receipt with Ed25519Signer", async () => {
    const { signer } = await Ed25519Signer.generate();
    const issuerDid = didKeyFromPublicKeyB64Url(toB64Url(await signer.publicKey()));

    const receipt = await signReceiptV1({
      req: (await cidForEnvelope({ payload: new Uint8Array([1,2,3]), signatures: [{ signature: new Uint8Array(64) }] })),
      res: { ok: true },
      ts: now(),
      pay: { amount: "1.23", unit: "USD" },
    }, signer);

    const verified = await verifyReceiptV1(receipt, { issuerDid });
    expect(verified.ok).toBe(true);
  });

  it("rejects revoked receipt by CID via hook and calls transparency", async () => {
    const { signer } = await Ed25519Signer.generate();
    const issuerDid = didKeyFromPublicKeyB64Url(toB64Url(await signer.publicKey()));

    const receipt = await signReceiptV1({
      req: (await cidForEnvelope({ payload: new Uint8Array([4,5,6]), signatures: [{ signature: new Uint8Array(64) }] })),
      res: { ok: false, err: "denied" },
      ts: now(),
    }, signer);

    const cid = await cidForEnvelope(receipt);
    const onTransparencyCID = vi.fn();
    const verified = await verifyReceiptV1(receipt, {
      issuerDid,
      isRevokedCID: async (c) => c.toString() === cid.toString(),
      onTransparencyCID,
    });
    expect(verified.ok).toBe(false);
    expect(verified.reason).toBe("revoked_cid");
    // Transparency still called before decision
    expect(onTransparencyCID).toHaveBeenCalled();
  });

  it("signs with ExternalSigner abstraction", async () => {
    const { signer } = await Ed25519Signer.generate();
    const pk = await signer.publicKey();
    const ext = new ExternalSigner(
      async (msg) => signer.sign(msg),
      async () => pk,
    );

    const issuerDid = didKeyFromPublicKeyB64Url(toB64Url(pk));
    const receipt = await signReceiptV1({
      req: (await cidForEnvelope({ payload: new Uint8Array([7,8,9]), signatures: [{ signature: new Uint8Array(64) }] })),
      res: { ok: true },
      ts: now(),
    }, ext);

    const verified = await verifyReceiptV1(receipt, { issuerDid });
    expect(verified.ok).toBe(true);
  });
});


