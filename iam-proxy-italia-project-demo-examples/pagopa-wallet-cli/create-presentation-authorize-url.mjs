#!/usr/bin/env node
/**
 * Prints one OpenID4VP authorization request URL for WCT test:presentation.
 *
 * Creates a session in the OpenID4VP Mongo collection (same shape as
 * pre-request init_session) and embeds state in request_uri so the wallet
 * SDK fetches /request-uri?state=... without appending state itself.
 */
import { createRequire } from "node:module";
import { randomBytes, randomUUID } from "node:crypto";

const require = createRequire("/opt/wct-tools/package.json");
const { MongoClient } = require("mongodb");

const mongoUrl =
  process.env.WCT_OPENID4VP_MONGO_URL ||
  "mongodb://satosa:thatpassword@satosa-mongo:27017";
const dbName = process.env.WCT_OPENID4VP_DB_NAME || "pyeudiw_openid4vp";
const sessionsCollection =
  process.env.WCT_OPENID4VP_SESSIONS_COLLECTION || "sessions";

const satosaHostname =
  process.env.SATOSA_HOSTNAME || "iam-proxy-italia.example.org";
const verifierBase =
  process.env.WCT_VERIFIER_BASE_URL ||
  `https://${satosaHostname}/OpenID4VP`;
const clientId =
  process.env.WCT_VERIFIER_CLIENT_ID ||
  `openid_federation:${verifierBase}`;
const requestUriBase =
  process.env.WCT_VERIFIER_REQUEST_URI || `${verifierBase}/request-uri`;
const urlScheme = process.env.WCT_VP_URL_SCHEME || "haip-vp";
const flowType =
  process.env.WCT_PRESENTATION_FLOW_TYPE === "cross-device"
    ? "cross_device"
    : "same_device";

function alphanumericState() {
  return randomBytes(16).toString("hex");
}

function buildAuthorizeUrl(state) {
  const requestUri = new URL(requestUriBase);
  requestUri.searchParams.set("state", state);

  const params = new URLSearchParams({
    client_id: clientId,
    request_uri: requestUri.toString(),
    request_uri_method: "get",
    state,
  });

  return `${urlScheme}://?${params.toString()}`;
}

async function main() {
  const state = alphanumericState();
  const sessionId = `urn:uuid:${randomUUID()}`;
  const documentId = randomUUID();

  const client = new MongoClient(mongoUrl);
  try {
    await client.connect();
    const sessions = client.db(dbName).collection(sessionsCollection);
    await sessions.insertOne({
      document_id: documentId,
      creation_date: new Date(),
      state,
      session_id: sessionId,
      remote_flow_typ: flowType,
      finalized: false,
      internal_response: null,
    });
  } finally {
    await client.close();
  }

  process.stdout.write(`${buildAuthorizeUrl(state)}\n`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`create-presentation-authorize-url failed: ${message}\n`);
  process.exit(1);
});
