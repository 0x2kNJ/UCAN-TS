// Express wiring that uses the env-backed deps which emit UCAN v1 (and optional legacy)
import type { Request, Response } from "express";
import { mintRoute } from "./handler.js";
import { makeMintDepsFromEnv } from "./deps-env.js";

export const mountMint = () => mintRoute(makeMintDepsFromEnv());

// Usage:
//   import express from 'express';
//   import { mountMint } from './mint/express-v1';
//   const app = express();
//   app.use(express.json());
//   app.post('/mcp/mint', mountMint());
//   app.listen(3000);
