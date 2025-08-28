import _sodium from "libsodium-wrappers";
import { 
  Ed25519Signer,
  didKeyFromPublicKeyB64Url,
  signDelegationV1,
  cidForEnvelope,
  toB64Url,
  utf8,
} from "../src/ucan/v1/index.js";

async function main() {
  await _sodium.ready;
  const sodium = _sodium;

  const fixedTime = 1700000000;

  const seeds = [
    "vec-1",
    "vec-2"
  ].map(label => sodium.crypto_generichash(32, utf8(label)));

  const vectors: any[] = [];

  for (let i = 0; i < seeds.length; i++) {
    const seed = seeds[i];
    const { privateKey, publicKey } = sodium.crypto_sign_seed_keypair(seed);
    const signer = new Ed25519Signer(privateKey);

    const did = didKeyFromPublicKeyB64Url(toB64Url(publicKey));

    const payload = {
      iss: did,
      aud: did,
      att: [{ with: "data/fetch", can: "read" }],
      nbf: fixedTime,
      exp: fixedTime + 60,
      prf: [] as string[],
      meta: { note: `local-vector-${i+1}` }
    } as const;

    const env = await signDelegationV1(payload as any, signer);
    const signatureB64Url = toB64Url(env.signatures[0].signature);
    const cid = (await cidForEnvelope(env)).toString();

    vectors.push({
      name: `local-vector-${i+1}`,
      seedB64Url: toB64Url(seed),
      payload,
      expected: {
        did,
        signatureB64Url,
        cid,
      }
    });
  }

  console.log(JSON.stringify({ vectors }, null, 2));
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});


