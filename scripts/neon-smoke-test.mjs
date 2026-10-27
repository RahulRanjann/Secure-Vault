import { randomUUID } from "node:crypto";
import { AwsClient } from "aws4fetch";
import { neon } from "@neondatabase/serverless";

const bucket = "assets";
const requiredEnv = [
  "DATABASE_URL",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_ENDPOINT_URL_S3",
  "AWS_REGION",
];

async function main() {
  const missing = requiredEnv.filter((name) => !process.env[name]);
  if (missing.length) {
    throw new Error(`Missing required Neon settings: ${missing.join(", ")}`);
  }

  const sql = neon(process.env.DATABASE_URL);
  const [tables] = await sql`
    SELECT
      to_regclass('public.app_users') AS app_users,
      to_regclass('public.app_sessions') AS app_sessions,
      to_regclass('public.google_drive_tokens') AS google_drive_tokens
  `;
  if (!tables?.app_users || !tables?.app_sessions || !tables?.google_drive_tokens) {
    throw new Error("Neon is reachable, but one or more app tables are missing. Apply database/schema.sql first.");
  }
  console.log("Postgres: connected; all three app tables are present.");

  const endpoint = new URL(process.env.AWS_ENDPOINT_URL_S3);
  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new Error("AWS_ENDPOINT_URL_S3 must be a clean HTTPS endpoint.");
  }
  const baseUrl = `${endpoint.origin}${endpoint.pathname.replace(/\/+$/, "")}/`;
  const key = `smoke-tests/${randomUUID()}.txt`;
  const objectUrl = new URL(`${bucket}/${key}`, baseUrl);
  const content = `Secure Vault Neon storage check ${randomUUID()}`;
  const aws = new AwsClient({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    service: "s3",
    region: process.env.AWS_REGION,
    retries: 1,
  });
  let uploaded = false;

  try {
    const put = await aws.fetch(objectUrl, {
      method: "PUT",
      headers: { "content-type": "text/plain" },
      body: content,
    });
    if (!put.ok) throw new Error(`Neon Object Storage upload failed (HTTP ${put.status}).`);
    uploaded = true;

    const get = await aws.fetch(objectUrl);
    if (!get.ok) throw new Error(`Neon Object Storage download failed (HTTP ${get.status}).`);
    if (await get.text() !== content) {
      throw new Error("Neon Object Storage returned content different from the uploaded test object.");
    }
  } finally {
    if (uploaded) {
      const deletion = await aws.fetch(objectUrl, { method: "DELETE" });
      if (!deletion.ok && deletion.status !== 404) {
        throw new Error(`Neon Object Storage test object cleanup failed (HTTP ${deletion.status}).`);
      }
    }
  }

  console.log("Object Storage: upload and download verified; temporary test object deleted.");
  console.log("Neon service smoke test passed.");
}

main().catch((error) => {
  console.error("Neon service smoke test failed:", error instanceof Error ? error.message : "Unknown error.");
  process.exitCode = 1;
});
