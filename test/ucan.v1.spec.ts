import { describe, it, expect, beforeAll } from "vitest";
import {
  Ed25519Signer,
  didKeyFromPublicKeyB64Url,
  didKeyEd25519PublicKeyB64Url,
  signDelegationV1,
  verifyDelegationV1,
  signInvocationV1,
  verifyInvocationV1,
  verifyInvocationAgainstChainV1,
  writeContainerV1,
  readContainerV1,
  cidForEnvelope,
  verifyEd25519,
  toB64Url,
  utf8,
  now,
} from "../src/ucan/v1/index.js";

describe("UCAN v1 Delegation/Invocation", () => {
  it("signs and verifies a simple delegation", async () => {
    const { signer } = await Ed25519Signer.generate();
    const pk = await signer.publicKey();
    const iss = didKeyFromPublicKeyB64Url(toB64Url(pk));
    const aud = iss; // self-delegate for test

    const payload = { 
      iss, 
      aud, 
      att: [{ with: "data/fetch", can: "read" }], 
      nbf: now(), 
      exp: now() + 60 
    } as const;
    
    const env = await signDelegationV1(payload, signer);
    const vr = await verifyDelegationV1(env);
    expect(vr.ok).toBe(true);
  });

  it("rejects expired delegation", async () => {
    const { signer } = await Ed25519Signer.generate();
    const pk = await signer.publicKey();
    const did = didKeyFromPublicKeyB64Url(toB64Url(pk));
    
    const env = await signDelegationV1({ 
      iss: did, 
      aud: did, 
      att: [{ with: "*", can: "*/*" }], 
      nbf: now()-10, 
      exp: now()-1 
    }, signer);
    
    const vr = await verifyDelegationV1(env);
    expect(vr.ok).toBe(false);
    expect(vr.reason).toBe("expired");
  });

  it("validates invocation against a delegation chain", async () => {
    const { signer: service } = await Ed25519Signer.generate();
    const svcDid = didKeyFromPublicKeyB64Url(toB64Url(await service.publicKey()));

    const { signer: middle } = await Ed25519Signer.generate();
    const midDid = didKeyFromPublicKeyB64Url(toB64Url(await middle.publicKey()));

    const { signer: user } = await Ed25519Signer.generate();
    const userDid = didKeyFromPublicKeyB64Url(toB64Url(await user.publicKey()));

    const d1 = await signDelegationV1({ 
      iss: svcDid, 
      aud: midDid, 
      att: [{ with: "data/fetch", can: "read" }], 
      nbf: now(), 
      exp: now()+60 
    }, service);
    
    const d2 = await signDelegationV1({ 
      iss: midDid, 
      aud: userDid, 
      att: [{ with: "data/fetch/path", can: "read" }], 
      nbf: now(), 
      exp: now()+60, 
      prf: [] 
    }, middle);

    const inv = await signInvocationV1({ 
      iss: userDid, 
      aud: svcDid, 
      cap: { with: "data/fetch/path/file.txt", can: "read" }, 
      nbf: now(), 
      exp: now()+60, 
      prf: [] 
    }, user);

    const ok = await verifyInvocationAgainstChainV1(inv, [d1, d2]);
    expect(ok.ok).toBe(true);
  });

  it("detects cap broadening", async () => {
    const { signer: service } = await Ed25519Signer.generate();
    const svcDid = didKeyFromPublicKeyB64Url(toB64Url(await service.publicKey()));
    const { signer: user } = await Ed25519Signer.generate();
    const userDid = didKeyFromPublicKeyB64Url(toB64Url(await user.publicKey()));

    const d = await signDelegationV1({ 
      iss: svcDid, 
      aud: userDid, 
      att: [{ with: "data/fetch/path", can: "read" }], 
      nbf: now(), 
      exp: now()+60 
    }, service);
    
    // user attempts broader cap than delegated
    const inv = await signInvocationV1({ 
      iss: userDid, 
      aud: svcDid, 
      cap: { with: "data/fetch", can: "read" }, 
      nbf: now(), 
      exp: now()+60, 
      prf: [] 
    }, user);

    const res = await verifyInvocationAgainstChainV1(inv, [d]);
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("invocation_cap_not_covered");
  });

  it("did:key pk <-> did", async () => {
    const { signer } = await Ed25519Signer.generate();
    const pkB64 = await signer.publicKeyB64Url();
    const did = didKeyFromPublicKeyB64Url(pkB64);
    const pkB64_2 = didKeyEd25519PublicKeyB64Url(did);
    expect(pkB64_2).toBe(pkB64);
    
    const msg = utf8("hello");
    const sig = await signer.signB64Url(msg);
    const ok = await verifyEd25519(msg, sig, pkB64_2);
    expect(ok).toBe(true);
  });

  it("rejects tampered signatures", async () => {
    const { signer } = await Ed25519Signer.generate();
    const pk = await signer.publicKey();
    const did = didKeyFromPublicKeyB64Url(toB64Url(pk));
    
    const env = await signDelegationV1({ 
      iss: did, 
      aud: did, 
      att: [{ with: "*", can: "*/*" }], 
      nbf: now(), 
      exp: now()+60 
    }, signer);
    
    // Tamper with signature
    env.signatures[0].signature[0] ^= 0x01;
    
    const vr = await verifyDelegationV1(env);
    expect(vr.ok).toBe(false);
    expect(vr.reason).toBe("bad_signature");
  });

  it("handles wildcard capabilities correctly", async () => {
    const { signer: service } = await Ed25519Signer.generate();
    const svcDid = didKeyFromPublicKeyB64Url(toB64Url(await service.publicKey()));
    const { signer: user } = await Ed25519Signer.generate();
    const userDid = didKeyFromPublicKeyB64Url(toB64Url(await user.publicKey()));

    // Grant wildcard capability
    const d = await signDelegationV1({ 
      iss: svcDid, 
      aud: userDid, 
      att: [{ with: "*", can: "*" }], 
      nbf: now(), 
      exp: now()+60 
    }, service);
    
    // Should allow any capability
    const inv = await signInvocationV1({ 
      iss: userDid, 
      aud: svcDid, 
      cap: { with: "data/fetch/anything", can: "write" }, 
      nbf: now(), 
      exp: now()+60, 
      prf: [] 
    }, user);

    const res = await verifyInvocationAgainstChainV1(inv, [d]);
    expect(res.ok).toBe(true);
  });

  it("handles prefix matching for capabilities", async () => {
    const { signer: service } = await Ed25519Signer.generate();
    const svcDid = didKeyFromPublicKeyB64Url(toB64Url(await service.publicKey()));
    const { signer: user } = await Ed25519Signer.generate();
    const userDid = didKeyFromPublicKeyB64Url(toB64Url(await user.publicKey()));

    // Grant prefix capability
    const d = await signDelegationV1({ 
      iss: svcDid, 
      aud: userDid, 
      att: [{ with: "data/*", can: "read/*" }], 
      nbf: now(), 
      exp: now()+60 
    }, service);
    
    // Should allow sub-resources
    const inv = await signInvocationV1({ 
      iss: userDid, 
      aud: svcDid, 
      cap: { with: "data/fetch/file.txt", can: "read/metadata" }, 
      nbf: now(), 
      exp: now()+60, 
      prf: [] 
    }, user);

    const res = await verifyInvocationAgainstChainV1(inv, [d]);
    expect(res.ok).toBe(true);
  });

  it("generates valid CIDs for envelopes", async () => {
    const { signer } = await Ed25519Signer.generate();
    const did = didKeyFromPublicKeyB64Url(toB64Url(await signer.publicKey()));
    
    const env = await signDelegationV1({ 
      iss: did, 
      aud: did, 
      att: [{ with: "*", can: "*/*" }], 
      nbf: now(), 
      exp: now()+60 
    }, signer);
    
    const cid = await cidForEnvelope(env);
    expect(cid.toString()).toMatch(/^bafy/); // CIDv1 with dag-cbor
    expect(typeof cid.toString()).toBe("string");
  });

  it("container roundtrip (simplified format)", async () => {
    const { signer } = await Ed25519Signer.generate();
    const did = didKeyFromPublicKeyB64Url(toB64Url(await signer.publicKey()));
    
    // Create multiple envelopes for testing
    const env1 = await signDelegationV1({ 
      iss: did, 
      aud: did, 
      att: [{ with: "data/fetch", can: "read" }], 
      nbf: now(), 
      exp: now()+60 
    }, signer);
    
    const env2 = await signDelegationV1({ 
      iss: did, 
      aud: did, 
      att: [{ with: "data/write", can: "write" }], 
      nbf: now(), 
      exp: now()+60 
    }, signer);
    
    // Test container round-trip
    const container = await writeContainerV1([env1, env2]);
    expect(container).toBeInstanceOf(Uint8Array);
    expect(container.length).toBeGreaterThan(0);
    
    const decoded = await readContainerV1(container);
    expect(decoded.length).toBe(2);
    
    // Verify the envelopes are still valid
    for (const env of decoded) {
      expect(env.payload).toBeInstanceOf(Uint8Array);
      expect(Array.isArray(env.signatures)).toBe(true);
      expect(env.signatures.length).toBeGreaterThan(0);
    }
    
    // Test CID generation still works
    const cid1 = await cidForEnvelope(env1);
    const cid2 = await cidForEnvelope(env2);
    expect(cid1.toString()).toMatch(/^bafy/);
    expect(cid2.toString()).toMatch(/^bafy/);
    expect(cid1.toString()).not.toBe(cid2.toString());
  });
});