import type { Request, Response } from "express";
import type { MintDeps } from "./deps-env.js";

export interface MintRequest {
  provider: string;
  subjectDid: string;
  method: string;
  paymentId: string;
  productId: string;
  amount: number;
  currency: string;
}

export function mintRoute(deps: MintDeps) {
  return async (req: Request, res: Response): Promise<void> => {
    try {
      const {
        provider,
        subjectDid,
        method,
        paymentId,
        productId,
        amount,
        currency,
      } = req.body as MintRequest;

      // Validate required fields
      if (!provider || !subjectDid || !method || !paymentId || !productId) {
        res.status(400).json({
          error: "missing_fields",
          message: "provider, subjectDid, method, paymentId, and productId are required"
        });
        return;
      }

      // Check idempotency
      const idemKey = `mint:${paymentId}:${subjectDid}`;
      const alreadyProcessed = await deps.idem.check(idemKey);
      if (alreadyProcessed) {
        res.status(409).json({
          error: "already_processed",
          message: "This payment has already been processed"
        });
        return;
      }

      // Verify payment
      const paymentResult = await deps.pay.verify({
        provider,
        paymentId,
        productId,
        amount,
        currency,
      });

      if (!paymentResult.success) {
        res.status(402).json({
          error: "payment_failed",
          message: paymentResult.reason || "Payment verification failed"
        });
        return;
      }

      // Get policy
      const { caps, ttlSec } = await deps.policy(method);
      
      // Mint UCAN
      const result = await deps.mint({
        subjectDid,
        caps,
        ttlSec,
        facts: {
          provider,
          paymentId,
          productId,
          amount,
          currency,
          timestamp: deps.now(),
        },
      });

      // Set idempotency marker
      await deps.idem.set(idemKey, ttlSec);

      // Sign receipt
      const receipt = {
        subjectDid,
        method,
        paymentId,
        amount,
        currency,
        timestamp: deps.now(),
        ucanCid: result.cid,
      };
      
      const receiptSig = await deps.sign(receipt);

      res.json({
        ...result,
        receipt: receiptSig,
      });
    } catch (error) {
      console.error("Mint error:", error);
      res.status(500).json({
        error: "internal_error",
        message: "Failed to mint UCAN"
      });
    }
  };
}

// Cloudflare Worker handler
export function workerHandler(deps: MintDeps) {
  return async (request: any): Promise<any> => {
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    try {
      const body = await request.json();
      
      // Create a promise-based response handler for Worker environment
      return new Promise((resolve) => {
        const mockReq = { body } as any;
        const mockRes = {
          status: (code: number) => ({
            json: (data: any) => resolve(new Response(JSON.stringify(data), {
              status: code,
              headers: { "Content-Type": "application/json" }
            }))
          }),
          json: (data: any) => resolve(new Response(JSON.stringify(data), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          }))
        } as any;

        mintRoute(deps)(mockReq, mockRes);
      });
    } catch (error) {
      return new Response(JSON.stringify({
        error: "internal_error",
        message: "Failed to process request"
      }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
  };
}
