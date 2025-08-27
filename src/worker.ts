// Cloudflare Worker entry that mounts the UCAN mint endpoint
import { workerHandler } from "./mint/handler.js";
import { makeMintDepsFromEnv } from "./mint/deps-env.js";

export default {
  fetch: workerHandler(makeMintDepsFromEnv()),
};
