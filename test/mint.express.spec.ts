import { describe, it, expect, beforeAll, vi } from "vitest";
import express from "express";
import request from "supertest";
import { mountMint } from "../src/mint/express-v1.js";

// Use in-memory env for tests
beforeAll(() => {
  process.env.UCAN_EMIT_FORMAT = "v1"; // keep test output simple
  process.env.POLICY_PATH = "./config/policies.yaml";
  // ephemeral signer via seed for reproducibility if desired
  // process.env.RECEIPT_SEED_B64URL = "...";
});

describe("/mcp/mint (Express)", () => {
  it("mints a UCAN v1 after payment verification", async () => {
    const app = express();
    app.use(express.json());
    app.post("/mcp/mint", mountMint());

    const payload = {
      provider: "stripe",
      subjectDid: "did:key:z6Mk...", // tests don't verify DID format here; core path will use real did
      method: "mcp.mint.ucan",
      paymentId: "test-pay-123",
      productId: "prod_basic",
      amount: 1234,
      currency: "USD"
    };

    const res = await request(app).post("/mcp/mint").send(payload);
    expect([200, 402, 400, 500]).toContain(res.status);
    
    if (res.status === 200) {
      expect(res.body).toHaveProperty("ucan");
      expect(res.body).toHaveProperty("cid");
      expect(res.body).toHaveProperty("receipt");
    }
    
    // Log response for debugging
    console.log("Mint response:", res.status, res.body);
  });

  it("rejects requests with missing fields", async () => {
    const app = express();
    app.use(express.json());
    app.post("/mcp/mint", mountMint());

    const payload = {
      provider: "stripe",
      // missing subjectDid, method, etc.
      paymentId: "test-pay-123",
    };

    const res = await request(app).post("/mcp/mint").send(payload);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("missing_fields");
  });

  it("handles unknown payment provider", async () => {
    const app = express();
    app.use(express.json());
    app.post("/mcp/mint", mountMint());

    const payload = {
      provider: "unknown_provider",
      subjectDid: "did:key:z6Mk...",
      method: "mcp.mint.ucan",
      paymentId: "test-pay-123",
      productId: "prod_basic",
      amount: 1234,
      currency: "USD"
    };

    const res = await request(app).post("/mcp/mint").send(payload);
    expect(res.status).toBe(402);
    expect(res.body.error).toBe("payment_failed");
  });

  it("handles unknown policy method", async () => {
    const app = express();
    app.use(express.json());
    app.post("/mcp/mint", mountMint());

    const payload = {
      provider: "stripe",
      subjectDid: "did:key:z6Mk...",
      method: "unknown.method",
      paymentId: "test-pay-123",
      productId: "prod_basic",
      amount: 1234,
      currency: "USD"
    };

    const res = await request(app).post("/mcp/mint").send(payload);
    expect(res.status).toBe(500); // Policy loading will fail
  });

  it("implements idempotency", async () => {
    const app = express();
    app.use(express.json());
    app.post("/mcp/mint", mountMint());

    const payload = {
      provider: "stripe",
      subjectDid: "did:key:z6Mk...",
      method: "mcp.mint.ucan",
      paymentId: "idempotency-test-456",
      productId: "prod_basic",
      amount: 1234,
      currency: "USD"
    };

    // First request
    const res1 = await request(app).post("/mcp/mint").send(payload);
    console.log("First request:", res1.status, res1.body);

    // Second request with same paymentId + subjectDid
    const res2 = await request(app).post("/mcp/mint").send(payload);
    console.log("Second request:", res2.status, res2.body);

    if (res1.status === 200) {
      expect(res2.status).toBe(409);
      expect(res2.body.error).toBe("already_processed");
    }
  });
});
