/**
 * server.js
 * - OAuth install flow for Shopify apps (express)
 * - Stores per-shop access tokens in tokens.json (simple file store for dev)
 * - Exposes POST /appointments which uses the shop's access token to create a metaobject
 *
 * WARNING: tokens.json is a simple file store for development. Use a proper DB in production.
 */

import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import { v4 as uuidv4 } from "uuid";

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

// ---- CONFIG (from env) ----
const {
  SHOPIFY_API_KEY,
  SHOPIFY_API_SECRET,
  HOST, // public URL of this server, e.g. https://appointments-writer.onrender.com
  SCOPES = "write_metaobjects,read_products,read_customers",
  API_VERSION = "2024-07", // update as needed
  SHOPIFY_ADMIN_API_TOKEN, // optional: single-store Admin token fallback
  SHOPIFY_STORE_DOMAIN // optional: used with SHOPIFY_ADMIN_API_TOKEN
} = process.env;

if (!HOST) {
  console.warn("Warning: HOST not set. Set HOST to your public URL (e.g. https://...onrender.com).");
}
if (!SHOPIFY_API_KEY || !SHOPIFY_API_SECRET) {
  console.warn("Warning: SHOPIFY_API_KEY and SHOPIFY_API_SECRET are recommended for OAuth flow.");
}

// ---- simple file-based token store (dev only) ----
const TOKENS_PATH = path.resolve("./tokens.json");
async function readTokens() {
  try {
    const raw = await fs.readFile(TOKENS_PATH, "utf8");
    return JSON.parse(raw || "{}");
  } catch {
    return {};
  }
}
async function writeTokens(json) {
  await fs.writeFile(TOKENS_PATH, JSON.stringify(json, null, 2));
}

// ---- helper: build install URL ----
function buildInstallUrl(shop, state) {
  const redirect = encodeURIComponent(`${HOST.replace(/\/$/, "")}/auth/callback`);
  return `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_API_KEY}&scope=${encodeURIComponent(SCOPES)}&redirect_uri=${redirect}&state=${state}`;
}

// ---- helper: verify HMAC (callback) ----
function verifyHmac(query, secret) {
  const { hmac, signature, ...rest } = query;
  // build message string
  const sorted = Object.keys(rest)
    .filter((k) => k !== "signature" && k !== "hmac")
    .sort()
    .map((k) => `${k}=${rest[k]}`)
    .join("&");

  const digest = crypto
    .createHmac("sha256", secret)
    .update(sorted)
    .digest("hex");
  return digest === hmac;
}

// ---- in-memory state nonces (simple) ----
const STATE_MAP = new Map(); // state -> shop

// ---- CORS - allow frontend origins (optional) ----
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);
app.use(cors({
  origin: (incomingOrigin, cb) => {
    if (!incomingOrigin) return cb(null, true); // allow server-to-server
    if (allowedOrigins.length === 0) return cb(null, true);
    if (allowedOrigins.includes(incomingOrigin)) return cb(null, true);
    cb(new Error("CORS not allowed"));
  },
  methods: ["GET","POST","OPTIONS"]
}));

// ---- ROUTES ----

/**
 * Health
 */
app.get("/", (_req, res) => res.send("OK"));

/**
 * Start OAuth
 * Request: /auth?shop=your-store.myshopify.com
 * Redirects to Shopify install URL
 */
app.get("/auth", async (req, res) => {
  const shop = req.query.shop;
  if (!shop) return res.status(400).send("Missing shop param. Usage: /auth?shop=store.myshopify.com");

  const state = uuidv4();
  STATE_MAP.set(state, shop);
  const installUrl = buildInstallUrl(shop, state);
  res.redirect(installUrl);
});

/**
 * OAuth callback
 * Shopify will redirect here with code & hmac & shop & state
 */
app.get("/auth/callback", async (req, res) => {
  const { shop, code, state, hmac } = req.query;
  if (!shop || !code || !state) return res.status(400).send("Missing required params (shop, code, state).");

  // verify state
  const expectedShop = STATE_MAP.get(state);
  if (!expectedShop || expectedShop !== shop) {
    return res.status(403).send("Invalid state (possible CSRF).");
  }
  // optionally verify HMAC
  if (!verifyHmac(req.query, SHOPIFY_API_SECRET)) {
    return res.status(400).send("HMAC validation failed.");
  }

  // exchange code for access token
  try {
    const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code: code
      })
    });
    const tokenJson = await tokenRes.json();
    if (!tokenRes.ok) {
      console.error("Token exchange failed", tokenJson);
      return res.status(500).send("Failed to get access token.");
    }

    const accessToken = tokenJson.access_token;
    const scope = tokenJson.scope;

    // save token
    const tokens = await readTokens();
    tokens[shop] = { access_token: accessToken, scope, installed_at: new Date().toISOString() };
    await writeTokens(tokens);

    // cleanup state
    STATE_MAP.delete(state);

    // Redirect to a simple success page or the app URL
    // For embeded apps: you typically redirect to the admin app iframe URL. For now redirect to HOST
    return res.redirect(HOST || "/");
  } catch (err) {
    console.error(err);
    return res.status(500).send("Error during OAuth callback.");
  }
});

/**
 * App uninstall webhook endpoint (optional best practice)
 * - Shopify will call this when store uninstalls app. (Requires webhook registration.)
 */
app.post("/webhooks/app/uninstalled", async (req, res) => {
  // remove tokens for shop if present
  // validate HMAC for webhooks in production
  const shop = req.headers["x-shopify-shop-domain"];
  if (shop) {
    const tokens = await readTokens();
    delete tokens[shop];
    await writeTokens(tokens);
  }
  res.sendStatus(200);
});

/**
 * Create Appointment metaobject
 * POST /appointments
 * Body JSON:
 * {
 *   name, email, phone, date, time, notes, products: [id or gid], shop: optional (shop domain)
 * }
 *
 * If shop is present, we look up an access token for that shop (installed via OAuth).
 * If not present, we check if env SHOPIFY_ADMIN_API_TOKEN exists and SHOPIFY_STORE_DOMAIN matches.
 */
app.post("/appointments", async (req, res) => {
  try {
    const { name, email, phone, date, time, notes = "", products = [], shop: bodyShop } = req.body || {};

    // Basic validation
    const errors = {};
    if (!name?.trim()) errors.name = "Please enter your name";
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.email = "Enter a valid email";
    if (!phone?.trim()) errors.phone = "Please enter your contact number";
    if (!date) errors.date = "Pick a date";
    if (!time) errors.time = "Pick a time";
    if (Object.keys(errors).length) {
      return res.status(422).json({ ok: false, errors });
    }

    // Determine shop and token
    const shop = bodyShop || req.headers["x-shopify-shop-domain"] || SHOPIFY_STORE_DOMAIN;
    if (!shop) {
      return res.status(400).json({ ok: false, error: "Shop domain missing. Provide 'shop' in body or header." });
    }

    // Try per-shop token
    const tokens = await readTokens();
    let accessToken = tokens[shop]?.access_token || null;

    // fallback to global admin token (if you set one in env)
    if (!accessToken && SHOPIFY_ADMIN_API_TOKEN && SHOPIFY_STORE_DOMAIN && SHOPIFY_STORE_DOMAIN === shop) {
      accessToken = SHOPIFY_ADMIN_API_TOKEN;
    }
    if (!accessToken) {
      return res.status(403).json({ ok: false, error: "No access token for this shop. Install the app or provide server-level token." });
    }

    // Build datetime
    const datetimeISO = new Date(`${date}T${time}`).toISOString();

    // Convert product ids to GIDs if needed
    const productGids = (Array.isArray(products) ? products : []).map(p => {
      const s = String(p);
      return s.startsWith("gid://") ? s : `gid://shopify/Product/${s}`;
    });

    // Build fields for Metaobject
    const fields = [
      { key: "customer_name", value: name.trim() },
      { key: "email", value: email.trim() },
      { key: "contact_number", value: phone.trim() },
      { key: "datetime", value: datetimeISO },
      { key: "notes", value: notes.trim() },
      { key: "status", value: "new" }
    ];
    if (productGids.length) {
      // storing product GIDs as JSON string in a text field (Metaobject product reference field types are limited in this small demo)
      fields.push({ key: "products", value: JSON.stringify(productGids) });
    }

    const mutation = `
      mutation CreateAppointment($metaobject: MetaobjectCreateInput!) {
        metaobjectCreate(metaobject: $metaobject) {
          metaobject { id }
          userErrors { field message }
        }
      }`;
    const variables = {
      metaobject: {
        definition: { type: "appointment" }, // must match your Metaobject type slug
        fields
      }
    };

    const graphRes = await fetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": accessToken
      },
      body: JSON.stringify({ query: mutation, variables })
    });

    const graphData = await graphRes.json();
    if (graphData.errors || graphData.data?.metaobjectCreate?.userErrors?.length) {
      console.error("Graph errors:", graphData);
      return res.status(500).json({ ok: false, error: graphData.errors || graphData.data.metaobjectCreate.userErrors });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("Server error:", err);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// ---- Start server ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
