// server.js (ESM)

import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// __dirname for ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// App
const app = express();
app.use(express.json());
app.use(cookieParser());

// Env
const API_KEY = process.env.SHOPIFY_API_KEY;
const API_SECRET = process.env.SHOPIFY_API_SECRET;
const SCOPES = process.env.SCOPES || 'write_customers,read_customers,write_metaobjects,read_metaobjects,read_products';
const HOST = process.env.HOST || 'https://shopify-appointments-server.onrender.com';
const API_VERSION = process.env.API_VERSION || '2025-10';


// ---------- Token lookups (free-plan friendly) ----------
const STATIC_SHOP  = process.env.SHOPIFY_STORE_DOMAIN || process.env.STATIC_SHOP; // e.g., 1ug0pd-tj.myshopify.com
const STATIC_TOKEN = process.env.STATIC_TOKEN || ''; // set in Render env

function getTokenForShop(shop) {
  // Return static token for your single shop
  if (STATIC_TOKEN && shop === STATIC_SHOP) return STATIC_TOKEN;
  return null; // no token -> force re-install
}

function saveTokenForShop(shop, accessToken, scope) {
  // On free plan we can't persist locally; just log the token once so you can copy it to STATIC_TOKEN.
  console.log(`\n=== COPY THIS AND SAVE AS STATIC_TOKEN ENV ===\nShop: ${shop}\nToken: ${accessToken}\nScope: ${scope}\n===========================================\n`);
}

// Store timezone (use env to change if needed)
const STORE_TZ_OFFSET_MINUTES = Number(process.env.STORE_TZ_OFFSET_MINUTES || 330); // +05:30
function tzSuffixFromMinutes(mins) {
  const sign = mins >= 0 ? '+' : '-';
  const abs = Math.abs(mins);
  const hh = String(Math.floor(abs / 60)).padStart(2, '0');
  const mm = String(abs % 60).padStart(2, '0');
  return `${sign}${hh}:${mm}`;
}
const STORE_TZ_SUFFIX = tzSuffixFromMinutes(STORE_TZ_OFFSET_MINUTES);

// Simple token store (file)
const TOKENS_FILE = path.join(__dirname, 'tokens.json');
function readTokens() {
  try {
    if (!fs.existsSync(TOKENS_FILE)) return {};
    return JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8') || '{}');
  } catch {
    return {};
  }
}
function writeTokens(tokens) {
  fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2));
}

// Normalize shop domain
function normalizeShop(req, fallback = '') {
  return (req.query.shop || req.body?.shop || fallback || '')
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '');
}

// ---- CORS (allow Shopify + your storefront) ----
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const isAllowed = (origin) => {
  if (!origin) return true;
  try {
    const u = new URL(origin);
    return allowedOrigins.includes(origin) || u.hostname.endsWith('.myshopify.com');
  } catch {
    return false;
  }
};

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (isAllowed(origin)) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Vary', 'Origin');
    res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    // include Cache-Control so your earlier preflight passes
    res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Shopify-Shop-Domain,Cache-Control');
    res.header('Access-Control-Expose-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ---- HMAC verification (Shopify OAuth callback) ----
function verifyHmac(query, secret) {
  const { hmac, signature, ...rest } = query;
  const message = Object.keys(rest)
    .filter((k) => k !== 'hmac' && k !== 'signature')
    .sort()
    .map((k) => `${k}=${rest[k]}`)
    .join('&');

  const digest = crypto.createHmac('sha256', secret).update(message).digest('hex');
  return digest === hmac;
}

function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

// ================= OAuth =================

// Step 1: redirect merchant to install/authorize
app.get('/auth', (req, res) => {
  const shop = normalizeShop(req);
  if (!shop || !/^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shop)) {
    return res.status(400).send('Invalid shop parameter');
  }

  const state = generateNonce();
  const redirectUri = `${HOST.replace(/\/$/, '')}/auth/callback`;
  const installUrl =
    `https://${shop}/admin/oauth/authorize?` +
    `client_id=${API_KEY}&` +
    `scope=${encodeURIComponent(SCOPES)}&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&` +
    `state=${state}`;

  // Save nonce in a cookie for CSRF protection
  res.cookie('shopify_nonce', state, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 10 * 60 * 1000
  });

  res.redirect(installUrl);
});

// Step 2: OAuth callback -> exchange code for token
app.get('/auth/callback', async (req, res) => {
  try {
    const { shop, code, state } = req.query;

    // HMAC check
    if (!verifyHmac(req.query, API_SECRET)) {
      return res.status(403).send('HMAC verification failed');
    }

    // State (nonce) check
    const expected = req.cookies?.shopify_nonce;
    if (!expected || expected !== state) {
      return res.status(403).send('State verification failed');
    }

    if (!/^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shop)) {
      return res.status(400).send('Invalid shop domain');
    }

    // Exchange code for access token
    const tokenUrl = `https://${shop}/admin/oauth/access_token`;
    const resp = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: API_KEY,
        client_secret: API_SECRET,
        code
      })
    });
    const json = await resp.json();
    if (!resp.ok || !json.access_token) {
      console.error('Token exchange failed:', json);
      return res.status(500).send('Failed to get access token');
    }

    saveTokenForShop(shop, json.access_token, json.scope);

    console.log(`✅ Access token acquired for ${shop}`);

    res.send(`
      <html>
        <head><title>Installation Complete</title></head>
        <body>
          <h2>App installed successfully!</h2>
          <p>You can now close this window and refresh your store admin.</p>
          <script>
            setTimeout(() => { window.location.href = 'https://${shop}/admin/apps'; }, 1500);
          </script>
        </body>
      </html>
    `);
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.status(500).send('OAuth error');
  }
});

// ================= API =================

// Availability
app.get('/appointments/availability', async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');

    const shop = normalizeShop(req);
    const token = getTokenForShop(shop);
    if (!token) {
      return res.status(403).json({
        ok: false,
        error: 'No access token. Install the app first.',
        installUrl: `${HOST.replace(/\/$/, '')}/auth?shop=${shop}`
      });
    }

    const query = `
      {
        metaobjects(first: 250, type: "appointment") {
          edges {
            node {
              fields { key value }
            }
          }
        }
      }`;

    const apiUrl = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const resp = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': token
      },
      body: JSON.stringify({ query })
    });
    const data = await resp.json();

    if (data.errors) {
      console.error('GraphQL errors:', data.errors);
      return res.status(500).json({ ok: false, error: 'GraphQL query failed' });
    }

    const bookings = [];
    const edges = data?.data?.metaobjects?.edges || [];
    for (const edge of edges) {
      const fields = edge.node.fields || [];
      const map = {};
      fields.forEach(f => (map[f.key] = f.value));
      if (map.datetime) {
        const iso = String(map.datetime); // e.g. "2025-10-28T11:30:00+05:30"
        bookings.push({
          date: iso.slice(0, 10),
          time: iso.slice(11, 16)
        });
      }
    }

    res.json({ ok: true, bookings });
  } catch (err) {
    console.error('Availability error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Create appointment
app.post('/appointments', async (req, res) => {
  try {
    const { name, email, phone, date, time, notes, products, shop: reqShop } = req.body || {};
    const shop = normalizeShop(req, reqShop);
    const token = getTokenForShop(shop);
    if (!token) {
      return res.status(403).json({
        ok: false,
        error: 'No access token',
        installUrl: `${HOST.replace(/\/$/, '')}/auth?shop=${shop}`
      });
    }

    // Basic validation
    const errors = {};
    if (!name?.trim()) errors.name = 'Name required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email || '')) errors.email = 'Valid email required';
    if (!phone?.trim()) errors.phone = 'Phone required';
    if (!date) errors.date = 'Date required';
    if (!time) errors.time = 'Time required';
    if (Object.keys(errors).length) return res.status(400).json({ ok: false, errors });

    // Preserve store-local time with offset, e.g. "2025-10-28T11:30:00+05:30"
    const datetime = `${date}T${time}:00${STORE_TZ_SUFFIX}`;


    const fields = [
      { key: 'customer_name', value: name.trim() },
      { key: 'email', value: email.trim() },
      { key: 'contact_number', value: phone.trim() },
      { key: 'datetime', value: datetime },
      { key: 'notes', value: (notes || '').trim() },
      { key: 'status', value: 'new' }
    ];

    const productGids = (Array.isArray(products) ? products : [])
      .map(p => (String(p).startsWith('gid://') ? String(p) : `gid://shopify/Product/${p}`));
    if (productGids.length) {
      // For a list.product_reference field, value must be a JSON array string of GIDs.
      // For a single product_reference field, value is one GID string.
      const isList = productGids.length > 1; // or make this true if your definition is list.*
      fields.push({
        key: 'products',
        value: JSON.stringify(productGids)
      });
    }

    const mutation = `
      mutation CreateAppointment($metaobject: MetaobjectCreateInput!) {
        metaobjectCreate(metaobject: $metaobject) {
          metaobject { id }
          userErrors { field message }
        }
      }`;
    const variables = { metaobject: { type: 'appointment', fields } };

    const apiUrl = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const resp = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': token
      },
      body: JSON.stringify({ query: mutation, variables })
    });
    const data = await resp.json();
    const userErrors = data?.data?.metaobjectCreate?.userErrors || [];
    if (userErrors.length) {
      console.error('Metaobject creation errors:', userErrors);
      // Map to form-friendly shape and include raw details
      const errors = {};
      for (const e of userErrors) {
        const path = Array.isArray(e.field) ? e.field.join('.') : 'products';
        errors[path] = e.message;
      }
      return res.status(400).json({ ok: false, errors, raw: userErrors });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Create appointment error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Health
app.get('/', (_req, res) => res.send('Shopify Appointments Server is running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
  console.log(`📍 OAuth URL: ${HOST.replace(/\/$/, '')}/auth?shop=YOUR_STORE.myshopify.com`);
});
