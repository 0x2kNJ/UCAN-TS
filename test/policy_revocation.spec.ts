import { describe, it, expect } from "vitest";
import {
  Ed25519Signer,
  didKeyFromPublicKeyB64Url,
  toB64Url,
  signDelegationV1,
  signInvocationV1,
  verifyInvocationAgainstChainV1,
  cidForEnvelope,
  now,
  type PolicyEvaluator,
} from "../src/ucan/v1/index.js";

describe("Policy and revocation hooks", () => {
  it("denies by isRevokedDID hook", async () => {
    const { signer: svc } = await Ed25519Signer.generate();
    const svcDid = didKeyFromPublicKeyB64Url(toB64Url(await svc.publicKey()));
    const { signer: user } = await Ed25519Signer.generate();
    const userDid = didKeyFromPublicKeyB64Url(toB64Url(await user.publicKey()));

    const d = await signDelegationV1({ iss: svcDid, aud: userDid, att: [{ with: "data", can: "read" }], nbf: now(), exp: now()+60 }, svc);
    const inv = await signInvocationV1({ iss: userDid, aud: svcDid, cap: { with: "data", can: "read" }, nbf: now(), exp: now()+60, prf: [] }, user);

    const res = await verifyInvocationAgainstChainV1(inv, [d], { isRevokedDID: (did) => did === userDid });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("revoked_issuer");
  });

  it("denies by isRevokedCID hook on delegation", async () => {
    const { signer: svc } = await Ed25519Signer.generate();
    const svcDid = didKeyFromPublicKeyB64Url(toB64Url(await svc.publicKey()));
    const { signer: user } = await Ed25519Signer.generate();
    const userDid = didKeyFromPublicKeyB64Url(toB64Url(await user.publicKey()));

    const d = await signDelegationV1({ iss: svcDid, aud: userDid, att: [{ with: "data", can: "read" }], nbf: now(), exp: now()+60 }, svc);
    const dCid = await cidForEnvelope(d);
    const inv = await signInvocationV1({ iss: userDid, aud: svcDid, cap: { with: "data", can: "read" }, nbf: now(), exp: now()+60, prf: [] }, user);

    const res = await verifyInvocationAgainstChainV1(inv, [d], { isRevokedCID: (cid) => cid.toString() === dCid.toString() });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("delegation_invalid: revoked_cid");
  });

  it("applies PolicyEvaluator to deny off-hours access", async () => {
    const { signer: svc } = await Ed25519Signer.generate();
    const svcDid = didKeyFromPublicKeyB64Url(toB64Url(await svc.publicKey()));
    const { signer: user } = await Ed25519Signer.generate();
    const userDid = didKeyFromPublicKeyB64Url(toB64Url(await user.publicKey()));

    const forcedNow = Math.floor(now() / 120) * 120; // force even minute boundary

    const d = await signDelegationV1({ iss: svcDid, aud: userDid, att: [{ with: "data", can: "read" }], nbf: forcedNow, exp: forcedNow+3600 }, svc);

    const policy: PolicyEvaluator = {
      evaluate: () => ({ ok: false, reason: "off_hours" }),
    };

    const inv = await signInvocationV1({ iss: userDid, aud: svcDid, cap: { with: "data", can: "read" }, nbf: forcedNow, exp: forcedNow+60, prf: [] }, user);
    const res = await verifyInvocationAgainstChainV1(inv, [d], { policy, now: forcedNow });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("policy_denied: off_hours");
  });
});


