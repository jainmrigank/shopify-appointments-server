/**
 * server.js (updated)
 * - Supports App Proxy or direct calls from the storefront
 * - Availability + booking for "appointment" metaobject
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

// ---- CONFIG ----
const {
  SHOPIFY_API_KEY,
  SHOPIFY_API_SECRET,
  HOST,
  SCOPES = "write_metaobjects,read_metaobjects,read_products,read_customers",
  API_VERSION = "2025-10",
  SHOPIFY_ADMIN_API_TOKEN,
  SHOPIFY_STORE_DOMAIN,
  // Comma-separated list of allowed origins, e.g. https://somarra.in,https://www.somarra.in,https://<store>.myshopify.com
  ALLOWED_ORIGINS = ""
} = process.env;

// ---- token store (dev) ----
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

// ---- helper: install URL ----
function buildInstallUrl(shop, state) {
  const redirect = encodeURIComponent(`${HOST?.replace(/\/$/, "")}/auth/callback`);
  return `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_API_KEY}&scope=${encodeURIComponent(SCOPES)}&redirect_uri=${redirect}&state=${state}`;
}

// ---- helper: verify HMAC ----
function verifyHmac(query, secret) {
  const { hmac, signature, ...rest } = query;
  const sorted = Object.keys(rest)
    .filter((k) => k !== "signature" && k !== "hmac")
    .sort()
    .map((k) => `${k}=${rest[k]}`)
    .join("&");
  const digest = crypto.createHmac("sha256", secret).update(sorted).digest("hex");
  return digest === hmac;
}

// ---- state ----
const STATE_MAP = new Map();

// ---- CORS ----
const allowList = ALLOWED_ORIGINS.split(",").map(s => s.trim()).filter(Boolean);
const isAllowedOrigin = (origin) => {
  if (!origin) return true;
  try {
    const u = new URL(origin);
    return (
      allowList.includes(origin) ||
      u.hostname.endsWith(".myshopify.com")
    );
  } catch {
    return false;
  }
};

app.use(cors({
  origin: (origin, cb) => {
    if (isAllowedOrigin(origin)) return cb(null, true);
    return cb(new Error("CORS not allowed"));
  },
  methods: ["GET","POST","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization","X-Shopify-Shop-Domain"],
  credentials: false
}));

// ---- ROUTES ----

app.get("/", (_req, res) => res.send("OK"));

// OAuth start
app.get("/auth", async (req, res) => {
  const shop = req.query.shop;
  if (!shop) return res.status(400).send("Missing shop param. Usage: /auth?shop=store.myshopify.com");
  const state = uuidv4();
  STATE_MAP.set(state, shop);
  res.redirect(buildInstallUrl(shop, state));
});

// OAuth callback
app.get("/auth/callback", async (req, res) => {
  const { shop, code, state } = req.query;
  if (!shop || !code || !state) return res.status(400).send("Missing required params (shop, code, state).");
  if (STATE_MAP.get(state) !== shop) return res.status(403).send("Invalid state.");
  if (!verifyHmac(req.query, SHOPIFY_API_SECRET)) return res.status(400).send("HMAC validation failed.");

  try {
    const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: SHOPIFY_API_KEY, client_secret: SHOPIFY_API_SECRET, code })
    });
    const tokenJson = await tokenRes.json();
    if (!tokenRes.ok) return res.status(500).send("Failed to get access token.");

    const tokens = await readTokens();
    tokens[shop] = { access_token: tokenJson.access_token, scope: tokenJson.scope, installed_at: new Date().toISOString() };
    await writeTokens(tokens);
    STATE_MAP.delete(state);
    return res.redirect(HOST || "/");
  } catch (err) {
    console.error(err);
    return res.status(500).send("Error during OAuth callback.");
  }
});

// App uninstall webhook
app.post("/webhooks/app/uninstalled", async (req, res) => {
  const shop = req.headers["x-shopify-shop-domain"];
  if (shop) {
    const tokens = await readTokens();
    delete tokens[shop];
    await writeTokens(tokens);
  }
  res.sendStatus(200);
});

// ---- Helpers ----
function normalizeShop(req, bodyShop) {
  return bodyShop || req.headers["x-shopify-shop-domain"] || SHOPIFY_STORE_DOMAIN;
}

async function adminFetch(shop, accessToken, query, variables = {}) {
  const res = await fetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken
    },
    body: JSON.stringify({ query, variables })
  });
  const json = await res.json();
  return { ok: res.ok, json };
}

async function getTokenForShop(shop) {
  const tokens = await readTokens();
  let accessToken = tokens[shop]?.access_token || null;
  if (!accessToken && SHOPIFY_ADMIN_API_TOKEN && SHOPIFY_STORE_DOMAIN === shop) {
    accessToken = SHOPIFY_ADMIN_API_TOKEN;
  }
  return accessToken;
}

// ---- Availability: returns booked slots ----
app.get("/appointments/availability", async (req, res) => {
  try {
    const shop = normalizeShop(req, req.query.shop);
    if (!shop) return res.status(400).json({ ok: false, error: "Shop domain missing." });

    const accessToken = await getTokenForShop(shop);
    if (!accessToken) return res.status(403).json({ ok: false, error: "No access token for this shop." });

    const query = `
      query GetAppointments {
        metaobjects(type: "appointment", first: 250) {
          edges {
            node {
              id
              fields { key value }
            }
          }
        }
      }
    `;
    const { json } = await adminFetch(shop, accessToken, query);

    if (json.errors) return res.status(500).json({ ok: false, error: json.errors });

    const bookings = [];
    const edges = json.data?.metaobjects?.edges || [];
    for (const edge of edges) {
      const map = Object.fromEntries((edge.node.fields || []).map(f => [f.key, f.value]));
      if (map.datetime) {
        const dt = new Date(map.datetime);
        const date = dt.toISOString().slice(0,10);
        const time = dt.toISOString().slice(11,16);
        bookings.push({ date, time });
      }
    }
    return res.json({ ok: true, bookings });
  } catch (err) {
    console.error("availability error", err);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// ---- Create appointment ----
app.post("/appointments", async (req, res) => {
  try {
    const { name, email, phone, date, time, notes = "", products = [], shop: bodyShop } = req.body || {};
    const errors = {};
    if (!name?.trim()) errors.name = "Please enter your name";
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.email = "Enter a valid email";
    if (!phone?.trim()) errors.phone = "Please enter your contact number";
    if (!date) errors.date = "Pick a date";
    if (!time) errors.time = "Pick a time";
    if (Object.keys(errors).length) return res.status(422).json({ ok: false, errors });

    const shop = normalizeShop(req, bodyShop);
    if (!shop) return res.status(400).json({ ok: false, error: "Shop domain missing." });

    const accessToken = await getTokenForShop(shop);
    if (!accessToken) return res.status(403).json({ ok: false, error: "No access token for this shop." });

    // Build ISO datetime from local date + time (treat as local time)
    const datetimeISO = new Date(`${date}T${time}`).toISOString();

    // Prevent double-booking: check if an appointment exists for the same datetime
    const checkQuery = `
      query GetAppointments {
        metaobjects(type: "appointment", first: 250) { edges { node { fields { key value } } } }
      }
    `;
    const check = await adminFetch(shop, accessToken, checkQuery);
    const edges = check.json?.data?.metaobjects?.edges || [];
    const isTaken = edges.some(edge => {
      const map = Object.fromEntries((edge.node.fields || []).map(f => [f.key, f.value]));
      return map.datetime && new Date(map.datetime).toISOString() === datetimeISO;
    });
    if (isTaken) return res.status(409).json({ ok: false, errors: { time: "This time slot is already booked" } });

    // Convert product ids to GIDs
    const productGids = (Array.isArray(products) ? products : []).map(p => {
      const s = String(p);
      return s.startsWith("gid://") ? s : `gid://shopify/Product/${s}`;
    });

    // Build fields for the "appointment" metaobject definition
    const fields = [
      { key: "customer_name", value: name.trim() },
      { key: "email", value: email.trim() },
      { key: "contact_number", value: phone.trim() },
      { key: "datetime", value: datetimeISO },
      { key: "notes", value: notes.trim() },
      { key: "status", value: "new" }
    ];
    if (productGids.length) {
      // IMPORTANT: list of product references uses 'references' with IDs
      fields.push({ key: "products", references: productGids });
    }

    const mutation = `
      mutation CreateAppointment($metaobject: MetaobjectCreateInput!) {
        metaobjectCreate(metaobject: $metaobject) {
          metaobject { id }
          userErrors { field message code }
        }
      }
    `;
    const variables = { metaobject: { type: "appointment", fields } };
    const create = await adminFetch(shop, accessToken, mutation, variables);

    const userErrors = create.json?.data?.metaobjectCreate?.userErrors || [];
    if (!create.ok || (userErrors && userErrors.length)) {
      return res.status(500).json({ ok: false, error: userErrors.length ? userErrors : create.json?.errors || "Unknown error" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("create error", err);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
