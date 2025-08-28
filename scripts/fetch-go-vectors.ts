import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Simple fetcher that pulls JSON vectors from a URL
// Usage: npx tsx scripts/fetch-go-vectors.ts https://raw.githubusercontent.com/ucan-wg/go-ucan/main/test/fixtures/vectors.json

async function main() {
  const url = process.argv[2] || process.env.UCAN_GO_VECTORS_URL;
  if (!url) {
    console.error("Provide vectors URL as arg or UCAN_GO_VECTORS_URL env.");
    process.exit(2);
  }

  const res = await fetch(url);
  if (!res.ok) {
    console.error(`Failed to fetch vectors: ${res.status} ${res.statusText}`);
    process.exit(1);
  }
  const text = await res.text();
  let parsed: any;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    console.error("Response was not valid JSON");
    process.exit(1);
  }

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const outDir = path.join(__dirname, "..", "test", "fixtures");
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, "go-ucan-vectors.json");
  fs.writeFileSync(outPath, JSON.stringify(parsed, null, 2));
  console.log(`Saved go-ucan vectors to ${outPath}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});


