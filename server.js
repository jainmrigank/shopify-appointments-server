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
// Increase JSON body limit to accommodate base64 image uploads (10 MB)
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// Env
const API_KEY = process.env.SHOPIFY_API_KEY;
const API_SECRET = process.env.SHOPIFY_API_SECRET;
const SCOPES = process.env.SCOPES || 'write_customers,read_customers,write_metaobjects,read_metaobjects,read_products';
const HOST = process.env.HOST || 'https://shopify-appointments-server.onrender.com';
const API_VERSION = process.env.API_VERSION || '2025-10';


// ---------- Token lookups (free-plan friendly) ----------
const STATIC_SHOP  = process.env.SHOPIFY_STORE_DOMAIN || process.env.STATIC_SHOP;
const STATIC_TOKEN = process.env.STATIC_TOKEN || '';

function getTokenForShop(shop) {
  if (STATIC_TOKEN && shop === STATIC_SHOP) return STATIC_TOKEN;
  return null;
}

function saveTokenForShop(shop, accessToken, scope) {
  console.log(`\n=== COPY THIS AND SAVE AS STATIC_TOKEN ENV ===\nShop: ${shop}\nToken: ${accessToken}\nScope: ${scope}\n===========================================\n`);
}

// Store timezone
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

// ---- CORS ----
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
    res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Shopify-Shop-Domain,Cache-Control');
    res.header('Access-Control-Expose-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ---- HMAC verification ----
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

app.get('/auth', (req, res) => {
  const shop = normalizeShop(req);
  if (!shop || !/^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shop)) {
    return res.status(400).send('Invalid shop parameter');
  }
  const state = generateNonce();
  const redirectUri = `${HOST.replace(/\/$/, '')}/auth/callback`;
  const installUrl =
    `https://${shop}/admin/oauth/authorize?` +
    `client_id=${API_KEY}&scope=${encodeURIComponent(SCOPES)}&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`;
  res.cookie('shopify_nonce', state, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 10 * 60 * 1000 });
  res.redirect(installUrl);
});

app.get('/auth/callback', async (req, res) => {
  try {
    const { shop, code, state } = req.query;
    if (!verifyHmac(req.query, API_SECRET)) return res.status(403).send('HMAC verification failed');
    const expected = req.cookies?.shopify_nonce;
    if (!expected || expected !== state) return res.status(403).send('State verification failed');
    if (!/^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shop)) return res.status(400).send('Invalid shop domain');
    const resp = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: API_KEY, client_secret: API_SECRET, code })
    });
    const json = await resp.json();
    if (!resp.ok || !json.access_token) { console.error('Token exchange failed:', json); return res.status(500).send('Failed to get access token'); }
    saveTokenForShop(shop, json.access_token, json.scope);
    console.log(`✅ Access token acquired for ${shop}`);
    res.send(`<html><body><h2>App installed successfully!</h2><script>setTimeout(()=>{window.location.href='https://${shop}/admin/apps';},1500);</script></body></html>`);
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
    if (!token) return res.status(403).json({ ok: false, error: 'No access token.', installUrl: `${HOST.replace(/\/$/, '')}/auth?shop=${shop}` });

    const query = `{ metaobjects(first: 250, type: "appointment") { edges { node { fields { key value } } } } }`;
    const apiUrl = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const resp = await fetch(apiUrl, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token }, body: JSON.stringify({ query }) });
    const data = await resp.json();
    if (data.errors) { console.error('GraphQL errors:', data.errors); return res.status(500).json({ ok: false, error: 'GraphQL query failed' }); }

    const bookings = [];
    const edges = data?.data?.metaobjects?.edges || [];
    for (const edge of edges) {
      const map = {};
      (edge.node.fields || []).forEach(f => (map[f.key] = f.value));
      if (map.datetime) {
        const iso = String(map.datetime);
        bookings.push({ date: iso.slice(0, 10), time: iso.slice(11, 16) });
      }
    }
    res.json({ ok: true, bookings });
  } catch (err) {
    console.error('Availability error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// ── Helper: summarise reference images in notes ──
// We do NOT store raw base64 in Shopify metaobjects (size limits).
// Instead we append a summary line to the notes field and log a count.
// If you want to persist images, upload them to Shopify Files or an S3
// bucket here and store the resulting URLs instead.
function buildNotesWithImages(notes, referenceImages) {
  const imgs = Array.isArray(referenceImages) ? referenceImages : [];
  if (!imgs.length) return notes || '';
  const names = imgs.map(i => i.filename || 'image').join(', ');
  const base = (notes || '').trim();
  const suffix = `[Reference images attached: ${imgs.length} file(s) — ${names}]`;
  return base ? `${base}\n\n${suffix}` : suffix;
}

// Create appointment
app.post('/appointments', async (req, res) => {
  try {
    const { name, email, phone, date, time, notes, products, reference_images, shop: reqShop } = req.body || {};
    const shop = normalizeShop(req, reqShop);
    const token = getTokenForShop(shop);
    if (!token) return res.status(403).json({ ok: false, error: 'No access token', installUrl: `${HOST.replace(/\/$/, '')}/auth?shop=${shop}` });

    // Basic validation
    const errors = {};
    if (!name?.trim()) errors.name = 'Name required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email || '')) errors.email = 'Valid email required';
    if (!phone?.trim()) errors.phone = 'Phone required';
    if (!date) errors.date = 'Date required';
    if (!time) errors.time = 'Time required';
    if (Object.keys(errors).length) return res.status(400).json({ ok: false, errors });

    const datetime = `${date}T${time}:00${STORE_TZ_SUFFIX}`;

    // Merge reference image filenames into notes (images are client-side only for now)
    // To persist images server-side, upload reference_images[].data (base64) to Shopify Files API
    // or AWS S3, then store the resulting URLs in a separate metaobject field.
    const combinedNotes = buildNotesWithImages(notes, reference_images);

    // Log upload count for visibility
    const imgCount = Array.isArray(reference_images) ? reference_images.length : 0;
    if (imgCount > 0) {
      console.log(`📎 Appointment from ${email} includes ${imgCount} reference image(s)`);
    }

    const fields = [
      { key: 'customer_name', value: name.trim() },
      { key: 'email',         value: email.trim() },
      { key: 'contact_number',value: phone.trim() },
      { key: 'datetime',      value: datetime },
      { key: 'notes',         value: combinedNotes },
      { key: 'status',        value: 'new' }
    ];

    const productGids = (Array.isArray(products) ? products : [])
      .map(p => (String(p).startsWith('gid://') ? String(p) : `gid://shopify/Product/${p}`));
    if (productGids.length) {
      fields.push({ key: 'products', value: JSON.stringify(productGids) });
    }

    const mutation = `
      mutation CreateAppointment($metaobject: MetaobjectCreateInput!) {
        metaobjectCreate(metaobject: $metaobject) {
          metaobject { id }
          userErrors { field message }
        }
      }`;

    const apiUrl = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const resp = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
      body: JSON.stringify({ query: mutation, variables: { metaobject: { type: 'appointment', fields } } })
    });
    const data = await resp.json();
    const userErrors = data?.data?.metaobjectCreate?.userErrors || [];
    if (userErrors.length) {
      console.error('Metaobject creation errors:', userErrors);
      const errMap = {};
      for (const e of userErrors) { const path = Array.isArray(e.field) ? e.field.join('.') : 'products'; errMap[path] = e.message; }
      return res.status(400).json({ ok: false, errors: errMap, raw: userErrors });
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
