import express from "express";
import type { CID } from "multiformats/cid";
import Redis from "ioredis";
import {
  verifyInvocationAgainstChainV1,
  type Envelope,
  type VerifyOptions,
  type DelegationPayload,
  type InvocationPayload,
  type PolicyEvaluator,
  cidForEnvelope,
} from "ucan-ts";

const app = express();
app.use(express.json({ limit: "512kb" }));

const redisUrl = process.env.REDIS_URL;
const redis = redisUrl ? new Redis(redisUrl) : null;

function makeVerifyOptions(): VerifyOptions {
  const isRevokedCID = async (cid: CID) => {
    if (!redis) return false;
    const key = `revoked:cid:${cid.toString()}`;
    return Boolean(await redis.get(key));
  };
  const isRevokedDID = async (did: string) => {
    if (!redis) return false;
    const key = `revoked:did:${did}`;
    return Boolean(await redis.get(key));
  };
  const onTransparencyCID = (cid: CID, _env: Envelope) => {
    console.log(JSON.stringify({ event: "transparency", cid: cid.toString(), ts: Date.now() }));
  };
  const policy: PolicyEvaluator = {
    evaluate: (_inv: InvocationPayload, _dels: DelegationPayload[], _now: number) => ({ ok: true }),
  };
  return { isRevokedCID, isRevokedDID, onTransparencyCID, policy };
}

app.post("/verify", async (req, res) => {
  try {
    const { invocation, chain } = req.body as { invocation: Envelope; chain: Envelope[] };
    if (!invocation || !Array.isArray(chain)) {
      return res.status(400).json({ ok: false, error: "invalid_request" });
    }
    const result = await verifyInvocationAgainstChainV1(invocation, chain, makeVerifyOptions());
    if (!result.ok) return res.status(403).json({ ok: false, reason: result.reason });
    const cid = await cidForEnvelope(invocation);
    return res.json({ ok: true, cid: cid.toString() });
  } catch (err: any) {
    return res.status(400).json({ ok: false, error: "invalid_format", detail: err?.message });
  }
});

const port = Number(process.env.PORT || 8787);
app.listen(port, () => {
  console.log(`MCP Sidecar UCAN-TS listening on :${port}`);
});
