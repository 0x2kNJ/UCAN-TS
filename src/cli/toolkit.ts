#!/usr/bin/env node

import { program } from "commander";
import {
  Ed25519Signer,
  didKeyFromPublicKeyB64Url,
  didKeyEd25519PublicKeyB64Url,
  signDelegationV1,
  verifyDelegationV1,
  signInvocationV1,
  verifyInvocationV1,
  verifyInvocationAgainstChainV1,
  cidForEnvelope,
  toB64Url,
  fromB64Url,
  now,
} from "../ucan/v1/index.js";
import { encode as cborEncode, decode as cborDecode } from "@ipld/dag-cbor";
import fs from "fs";
import path from "path";

// CLI Colors
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

function log(color: string, message: string) {
  console.log(`${color}${message}${colors.reset}`);
}

// Generate a new Ed25519 keypair
program
  .command("keygen")
  .description("Generate a new Ed25519 keypair")
  .option("-o, --output <file>", "Output file for private key")
  .action(async (options) => {
    try {
      const { signer } = await Ed25519Signer.generate();
      const pkB64 = await signer.publicKeyB64Url();
      const did = didKeyFromPublicKeyB64Url(pkB64);
      const skB64 = toB64Url(signer.secretKey);

      if (options.output) {
        const keyData = {
          secretKey: skB64,
          publicKey: pkB64,
          did: did,
          created: new Date().toISOString()
        };
        fs.writeFileSync(options.output, JSON.stringify(keyData, null, 2));
        log(colors.green, `✓ Keypair saved to ${options.output}`);
      } else {
        log(colors.bold, "New Ed25519 Keypair:");
        log(colors.blue, `DID:        ${did}`);
        log(colors.blue, `Public Key: ${pkB64}`);
        log(colors.yellow, `Secret Key: ${skB64}`);
        log(colors.yellow, "⚠️  Keep the secret key safe!");
      }
    } catch (error) {
      log(colors.red, `✗ Error: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

// Inspect a UCAN token
program
  .command("inspect <token>")
  .description("Inspect a UCAN token")
  .option("-v, --verify", "Verify the token signature")
  .action(async (token, options) => {
    try {
      // Try to parse as base64url CBOR envelope
      let envelope: any;
      try {
        const tokenBytes = fromB64Url(token);
        envelope = cborDecode(tokenBytes);
      } catch {
        log(colors.red, "✗ Invalid token format (expected base64url encoded CBOR)");
        process.exit(1);
      }

      if (!envelope.payload || !envelope.signatures) {
        log(colors.red, "✗ Invalid envelope structure");
        process.exit(1);
      }

      const payload = cborDecode(envelope.payload) as any;
      const cid = await cidForEnvelope(envelope);

      log(colors.bold, "UCAN Token Inspection:");
      log(colors.blue, `CID:        ${cid.toString()}`);
      log(colors.blue, `Type:       ${payload.cap ? 'Invocation' : 'Delegation'}`);
      log(colors.blue, `Issuer:     ${payload.iss}`);
      log(colors.blue, `Audience:   ${payload.aud}`);
      log(colors.blue, `Not Before: ${new Date(payload.nbf * 1000).toISOString()}`);
      log(colors.blue, `Expires:    ${new Date(payload.exp * 1000).toISOString()}`);

      if (payload.cap) {
        log(colors.blue, `Capability: ${payload.cap.with}#${payload.cap.can}`);
      } else if (payload.att) {
        log(colors.blue, `Capabilities: ${payload.att.length} granted`);
        payload.att.forEach((cap: any, i: number) => {
          log(colors.blue, `  ${i + 1}. ${cap.with}#${cap.can}`);
        });
      }

      if (payload.prf && payload.prf.length > 0) {
        log(colors.blue, `Proofs:     ${payload.prf.length} delegation(s)`);
      }

      if (payload.meta) {
        log(colors.blue, `Metadata:   ${JSON.stringify(payload.meta)}`);
      }

      log(colors.blue, `Signatures: ${envelope.signatures.length}`);

      if (options.verify) {
        const result = payload.cap 
          ? await verifyInvocationV1(envelope as any)
          : await verifyDelegationV1(envelope as any);
        
        if (result.ok) {
          log(colors.green, "✓ Signature verification: VALID");
        } else {
          log(colors.red, `✗ Signature verification: INVALID (${result.reason})`);
        }
      }

    } catch (error) {
      log(colors.red, `✗ Error: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

// Create a delegation
program
  .command("delegate")
  .description("Create a delegation")
  .requiredOption("-k, --key <file>", "Private key file")
  .requiredOption("-a, --audience <did>", "Audience DID")
  .requiredOption("-c, --capability <cap>", "Capability (format: resource#action)")
  .option("-t, --ttl <seconds>", "TTL in seconds", "3600")
  .option("-o, --output <file>", "Output file")
  .action(async (options) => {
    try {
      // Load key
      const keyData = JSON.parse(fs.readFileSync(options.key, "utf8"));
      const signer = new Ed25519Signer(fromB64Url(keyData.secretKey));
      
      // Parse capability
      const [withResource, canAction] = options.capability.split("#");
      if (!withResource || !canAction) {
        throw new Error("Capability must be in format: resource#action");
      }

      const payload = {
        iss: keyData.did,
        aud: options.audience,
        att: [{ with: withResource, can: canAction }],
        nbf: now(),
        exp: now() + parseInt(options.ttl),
      };

      const envelope = await signDelegationV1(payload, signer);
      const token = toB64Url(cborEncode(envelope));
      const cid = await cidForEnvelope(envelope);

      if (options.output) {
        fs.writeFileSync(options.output, token);
        log(colors.green, `✓ Delegation saved to ${options.output}`);
      } else {
        log(colors.bold, "Delegation Created:");
        log(colors.blue, `CID:   ${cid.toString()}`);
        log(colors.blue, `Token: ${token}`);
      }

    } catch (error) {
      log(colors.red, `✗ Error: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

// Verify a delegation chain
program
  .command("verify-chain")
  .description("Verify an invocation against a delegation chain")
  .requiredOption("-i, --invocation <token>", "Invocation token")
  .requiredOption("-c, --chain <tokens...>", "Delegation chain tokens")
  .action(async (options) => {
    try {
      const invocation = cborDecode(fromB64Url(options.invocation)) as any;
      const chain = options.chain.map((token: string) => cborDecode(fromB64Url(token)) as any);

      const result = await verifyInvocationAgainstChainV1(invocation, chain);

      if (result.ok) {
        log(colors.green, "✓ Chain verification: VALID");
        log(colors.blue, "The invocation is properly authorized by the delegation chain");
      } else {
        log(colors.red, `✗ Chain verification: INVALID`);
        log(colors.red, `Reason: ${result.reason}`);
      }

    } catch (error) {
      log(colors.red, `✗ Error: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

// Convert DID to public key and vice versa
program
  .command("did-convert <input>")
  .description("Convert between DID and public key formats")
  .action((input) => {
    try {
      if (input.startsWith("did:key:")) {
        const pkB64 = didKeyEd25519PublicKeyB64Url(input);
        log(colors.blue, `Public Key: ${pkB64}`);
      } else {
        const did = didKeyFromPublicKeyB64Url(input);
        log(colors.blue, `DID: ${did}`);
      }
    } catch (error) {
      log(colors.red, `✗ Error: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

// Show token stats
program
  .command("stats <directory>")
  .description("Show statistics for UCAN tokens in a directory")
  .action(async (directory) => {
    try {
      const files = fs.readdirSync(directory)
        .filter(f => f.endsWith('.token') || f.endsWith('.ucan'))
        .map(f => path.join(directory, f));

      if (files.length === 0) {
        log(colors.yellow, "No UCAN token files found");
        return;
      }

      let delegations = 0;
      let invocations = 0;
      let valid = 0;
      let expired = 0;
      const issuers = new Set();
      const capabilities = new Set();

      for (const file of files) {
        try {
          const token = fs.readFileSync(file, "utf8").trim();
          const envelope = cborDecode(fromB64Url(token)) as any;
          const payload = cborDecode(envelope.payload) as any;

          issuers.add(payload.iss);

          if (payload.cap) {
            invocations++;
            capabilities.add(`${payload.cap.with}#${payload.cap.can}`);
          } else {
            delegations++;
            payload.att?.forEach((cap: any) => {
              capabilities.add(`${cap.with}#${cap.can}`);
            });
          }

          if (payload.exp * 1000 < Date.now()) {
            expired++;
          } else {
            const result = payload.cap 
              ? await verifyInvocationV1(envelope as any)
              : await verifyDelegationV1(envelope as any);
            if (result.ok) valid++;
          }
        } catch {
          // Skip invalid files
        }
      }

      log(colors.bold, `UCAN Token Statistics (${directory}):`);
      log(colors.blue, `Total Files:    ${files.length}`);
      log(colors.blue, `Delegations:    ${delegations}`);
      log(colors.blue, `Invocations:    ${invocations}`);
      log(colors.green, `Valid:          ${valid}`);
      log(colors.red, `Expired:        ${expired}`);
      log(colors.blue, `Unique Issuers: ${issuers.size}`);
      log(colors.blue, `Capabilities:   ${capabilities.size}`);

    } catch (error) {
      log(colors.red, `✗ Error: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

// Set up the CLI
program
  .name("ucan-toolkit")
  .description("UCAN v1 development and debugging toolkit")
  .version("1.0.0");

program.parse();
