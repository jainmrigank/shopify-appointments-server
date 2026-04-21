// server.js (ESM)
// v7 — Removes all polling. GIDs are stored immediately after fileCreate.
// Shopify Flow resolves GIDs to URLs at trigger time (after files are READY).
// This keeps total request time under 10s, well within Render's 30s limit.

import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: '25mb' }));
app.use(cookieParser());

// ── Env ──
const API_KEY     = process.env.SHOPIFY_API_KEY;
const API_SECRET  = process.env.SHOPIFY_API_SECRET;
const SCOPES      = process.env.SCOPES || 'write_customers,read_customers,write_metaobjects,read_metaobjects,read_products,write_files,read_files';
const HOST        = process.env.HOST   || 'https://shopify-appointments-server.onrender.com';
const API_VERSION = process.env.API_VERSION || '2025-10';

const STATIC_SHOP  = process.env.SHOPIFY_STORE_DOMAIN || process.env.STATIC_SHOP;
const STATIC_TOKEN = process.env.STATIC_TOKEN || '';

function getTokenForShop(shop) {
  if (STATIC_TOKEN && shop === STATIC_SHOP) return STATIC_TOKEN;
  return null;
}
function saveTokenForShop(shop, accessToken, scope) {
  console.log(`\n=== COPY THIS AND SAVE AS STATIC_TOKEN ENV ===\nShop: ${shop}\nToken: ${accessToken}\nScope: ${scope}\n===========================================\n`);
}

const STORE_TZ_OFFSET_MINUTES = Number(process.env.STORE_TZ_OFFSET_MINUTES || 330);
function tzSuffixFromMinutes(mins) {
  const sign = mins >= 0 ? '+' : '-';
  const abs  = Math.abs(mins);
  return `${sign}${String(Math.floor(abs/60)).padStart(2,'0')}:${String(abs%60).padStart(2,'0')}`;
}
const STORE_TZ_SUFFIX = tzSuffixFromMinutes(STORE_TZ_OFFSET_MINUTES);

// ── CORS ──
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const isAllowed = origin => {
  if (!origin) return true;
  try { const u = new URL(origin); return allowedOrigins.includes(origin) || u.hostname.endsWith('.myshopify.com'); }
  catch { return false; }
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

// ── HMAC ──
function verifyHmac(query, secret) {
  const { hmac, signature, ...rest } = query;
  const message = Object.keys(rest).filter(k => k !== 'hmac' && k !== 'signature').sort().map(k => `${k}=${rest[k]}`).join('&');
  return crypto.createHmac('sha256', secret).update(message).digest('hex') === hmac;
}
function generateNonce() { return crypto.randomBytes(16).toString('hex'); }
function normalizeShop(req, fallback = '') {
  return (req.query.shop || req.body?.shop || fallback || '').replace(/^https?:\/\//, '').replace(/\/$/, '');
}

// ================= OAuth =================

app.get('/auth', (req, res) => {
  const shop = normalizeShop(req);
  if (!shop || !/^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shop)) return res.status(400).send('Invalid shop parameter');
  const state = generateNonce();
  const redirectUri = `${HOST.replace(/\/$/, '')}/auth/callback`;
  const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${API_KEY}&scope=${encodeURIComponent(SCOPES)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`;
  res.cookie('shopify_nonce', state, { httpOnly:true, secure:true, sameSite:'none', maxAge: 10*60*1000 });
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
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: API_KEY, client_secret: API_SECRET, code })
    });
    const json = await resp.json();
    if (!resp.ok || !json.access_token) { console.error('Token exchange failed:', json); return res.status(500).send('Failed to get access token'); }
    saveTokenForShop(shop, json.access_token, json.scope);
    res.send(`<html><body><h2>App installed successfully!</h2><script>setTimeout(()=>{window.location.href='https://${shop}/admin/apps';},1500);</script></body></html>`);
  } catch (err) { console.error('OAuth callback error:', err); res.status(500).send('OAuth error'); }
});

// ================= API =================

// ── GET /appointments/availability ──
app.get('/appointments/availability', async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const shop  = normalizeShop(req);
    const token = getTokenForShop(shop);
    if (!token) return res.status(403).json({ ok:false, error:'No access token.', installUrl:`${HOST.replace(/\/$/, '')}/auth?shop=${shop}` });
    const query = `{ metaobjects(first: 250, type: "appointment") { edges { node { fields { key value } } } } }`;
    const resp  = await fetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
      method: 'POST', headers: { 'Content-Type':'application/json', 'X-Shopify-Access-Token':token },
      body: JSON.stringify({ query })
    });
    const data = await resp.json();
    if (data.errors) return res.status(500).json({ ok:false, error:'GraphQL query failed' });
    const bookings = [];
    for (const edge of (data?.data?.metaobjects?.edges || [])) {
      const map = {};
      (edge.node.fields || []).forEach(f => (map[f.key] = f.value));
      if (map.datetime) { const iso = String(map.datetime); bookings.push({ date: iso.slice(0,10), time: iso.slice(11,16) }); }
    }
    res.json({ ok: true, bookings });
  } catch (err) { console.error('Availability error:', err); res.status(500).json({ ok:false, error:'Server error' }); }
});

// ── GET /products/all ──
app.get('/products/all', async (req, res) => {
  try {
    const shop  = normalizeShop(req);
    const token = getTokenForShop(shop);
    if (!token) return res.status(403).json({ ok:false, error:'No access token.' });
    res.set('Cache-Control', 'public, max-age=60');
    const PAGE_SIZE = 250;
    let products = [], cursor = null, hasNext = true;
    while (hasNext) {
      const afterClause = cursor ? `, after: "${cursor}"` : '';
      const query = `{ products(first: ${PAGE_SIZE}${afterClause}) { pageInfo { hasNextPage endCursor } edges { node { id title handle featuredImage { url altText } } } } }`;
      const resp = await fetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
        method: 'POST', headers: { 'Content-Type':'application/json', 'X-Shopify-Access-Token':token },
        body: JSON.stringify({ query })
      });
      const data = await resp.json();
      if (data.errors) break;
      const page = data?.data?.products;
      if (!page) break;
      for (const edge of (page.edges || [])) {
        const node = edge.node;
        products.push({ id: node.id.replace('gid://shopify/Product/', ''), title: node.title, handle: node.handle, images: node.featuredImage ? [{ src: node.featuredImage.url }] : [] });
      }
      hasNext = page.pageInfo?.hasNextPage || false;
      cursor  = page.pageInfo?.endCursor   || null;
    }
    res.json({ ok: true, products });
  } catch (err) { console.error('Products list error:', err); res.status(500).json({ ok:false, error:'Server error' }); }
});

// ── GET /debug/upload-test ──
// Hit this endpoint manually to verify the full upload pipeline works.
// GET https://your-server.onrender.com/debug/upload-test?shop=1ug0pd-tj.myshopify.com
app.get('/debug/upload-test', async (req, res) => {
  try {
    const shop  = normalizeShop(req);
    const token = getTokenForShop(shop);
    if (!token) return res.status(403).json({ ok:false, error:'No token' });

    // Create a tiny 1×1 white PNG (base64) as a test image
    const testPng = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
    const testObj = { filename: 'debug_test.png', data: `data:image/png;base64,${testPng}` };

    console.log('[DEBUG] Starting upload test...');
    const result = await uploadImageToShopifyFiles(shop, token, testObj);
    console.log('[DEBUG] Upload result:', result);

    res.json({ ok: true, result });
  } catch (err) {
    console.error('[DEBUG] Upload test error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════
// SHOPIFY FILES UPLOAD — NO POLLING
//
// Key insight: fileCreate returns a GID immediately, even before the file
// status is READY. Shopify Flow runs AFTER the metaobject is created
// (triggered by the metaobject creation event), giving Shopify time to
// finish processing. By the time Flow reads metaobject.referenceImages,
// the files are already READY.
//
// Removing polling cuts request time from ~25s → ~5s per image.
// ══════════════════════════════════════════════════════════════

function parseDataUrl(dataUrl) {
  const match = dataUrl.match(/^data:([^;]+);base64,(.+)$/s);
  if (!match) return null;
  const mimeType   = match[1];
  const base64Data = match[2].replace(/\s/g, ''); // strip any whitespace that crept in
  const extMap = { 'image/jpeg':'jpg','image/jpg':'jpg','image/png':'png','image/webp':'webp','image/gif':'gif','image/heic':'heic' };
  return { mimeType, base64Data, extension: extMap[mimeType] || 'jpg' };
}

/**
 * Upload one base64 image to Shopify Files.
 * Returns the file GID string on success, or null on failure.
 * Does NOT poll — the GID is valid immediately for metaobject storage.
 */
async function uploadImageToShopifyFiles(shop, token, imageObj) {
  const stepLabel = imageObj.filename || 'image';
  try {
    const { filename, data } = imageObj;
    if (!data) { console.error(`[upload] No data for ${stepLabel}`); return null; }
    if (!data.startsWith('data:')) { console.error(`[upload] Not a data URL for ${stepLabel} — starts with: ${data.slice(0,30)}`); return null; }

    const parsed = parseDataUrl(data);
    if (!parsed) { console.error(`[upload] Failed to parse data URL for ${stepLabel}`); return null; }

    const { mimeType, base64Data, extension } = parsed;
    const binaryBuffer  = Buffer.from(base64Data, 'base64');
    const exactByteSize = binaryBuffer.length;

    if (exactByteSize === 0) { console.error(`[upload] Zero-byte buffer for ${stepLabel}`); return null; }

    const safeFilename = (filename || `ref_${Date.now()}.${extension}`)
      .replace(/[^a-zA-Z0-9._-]/g, '_')
      .slice(0, 100); // Shopify has filename length limits

    const graphqlUrl = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const gqlHeaders = { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token };

    console.log(`[upload] ${stepLabel}: ${exactByteSize} bytes, ${mimeType}`);

    // ── Step 1: stagedUploadsCreate ──
    const stageBody = JSON.stringify({
      query: `mutation stagedUploadsCreate($input: [StagedUploadInput!]!) {
        stagedUploadsCreate(input: $input) {
          stagedTargets { url resourceUrl parameters { name value } }
          userErrors { field message }
        }
      }`,
      variables: {
        input: [{
          filename:   safeFilename,
          mimeType,
          resource:   'FILE',
          fileSize:   String(exactByteSize),
          httpMethod: 'PUT'
        }]
      }
    });

    const stageResp = await fetch(graphqlUrl, { method: 'POST', headers: gqlHeaders, body: stageBody });
    const stageJson = await stageResp.json();

    if (stageJson.errors?.length) {
      console.error(`[upload] stagedUploadsCreate GraphQL errors for ${stepLabel}:`, JSON.stringify(stageJson.errors));
      return null;
    }
    const stageUE = stageJson?.data?.stagedUploadsCreate?.userErrors || [];
    if (stageUE.length) {
      console.error(`[upload] stagedUploadsCreate userErrors for ${stepLabel}:`, JSON.stringify(stageUE));
      return null;
    }
    const target = stageJson?.data?.stagedUploadsCreate?.stagedTargets?.[0];
    if (!target?.url || !target?.resourceUrl) {
      console.error(`[upload] No staged target returned for ${stepLabel}. Response:`, JSON.stringify(stageJson).slice(0, 500));
      return null;
    }

    const { url: s3Url, resourceUrl } = target;
    console.log(`[upload] ${stepLabel}: staged OK, uploading to S3...`);

    // ── Step 2: PUT binary to S3 (no Content-Length header — node-fetch handles it) ──
    const s3Resp = await fetch(s3Url, {
      method: 'PUT',
      headers: { 'Content-Type': mimeType },
      body: binaryBuffer
    });

    if (!s3Resp.ok) {
      const errBody = await s3Resp.text().catch(() => '');
      console.error(`[upload] S3 PUT failed (${s3Resp.status}) for ${stepLabel}:`, errBody.slice(0, 400));
      return null;
    }
    console.log(`[upload] ${stepLabel}: S3 PUT OK (${s3Resp.status})`);

    // ── Step 3: fileCreate — register with Shopify, get GID ──
    const fcBody = JSON.stringify({
      query: `mutation fileCreate($files: [FileCreateInput!]!) {
        fileCreate(files: $files) {
          files { id fileStatus }
          userErrors { field message }
        }
      }`,
      variables: {
        files: [{
          originalSource: resourceUrl,
          filename:       safeFilename,
          contentType:    'IMAGE',
          alt:            safeFilename
        }]
      }
    });

    const fcResp = await fetch(graphqlUrl, { method: 'POST', headers: gqlHeaders, body: fcBody });
    const fcJson = await fcResp.json();

    if (fcJson.errors?.length) {
      console.error(`[upload] fileCreate GraphQL errors for ${stepLabel}:`, JSON.stringify(fcJson.errors));
      return null;
    }
    const fcUE = fcJson?.data?.fileCreate?.userErrors || [];
    if (fcUE.length) {
      console.error(`[upload] fileCreate userErrors for ${stepLabel}:`, JSON.stringify(fcUE));
      return null;
    }

    const createdFile = fcJson?.data?.fileCreate?.files?.[0];
    if (!createdFile?.id) {
      console.error(`[upload] fileCreate returned no file for ${stepLabel}. Response:`, JSON.stringify(fcJson).slice(0, 500));
      return null;
    }

    // Return the GID immediately — no polling needed.
    // Status will be UPLOADED here; it transitions to READY within seconds.
    // Shopify Flow resolves the GID to an image URL at trigger time.
    console.log(`[upload] ${stepLabel}: GID=${createdFile.id} status=${createdFile.fileStatus}`);
    return createdFile.id;

  } catch (err) {
    console.error(`[upload] Unexpected error for ${stepLabel}:`, err.message, err.stack?.split('\n')[1]);
    return null;
  }
}

/**
 * Register a product image URL (already on Shopify CDN) with the Files library.
 * Uses fileCreate with originalSource — no S3 staging needed for CDN URLs.
 * Returns the GID string or null.
 */
async function registerProductImageInFiles(shop, token, productImageUrl, productTitle) {
  try {
    if (!productImageUrl) return null;

    const graphqlUrl = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const gqlHeaders = { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token };

    const safeFilename = `product_${(productTitle || 'item').replace(/[^a-zA-Z0-9._-]/g,'_').slice(0,50)}_${Date.now()}.jpg`;

    console.log(`[upload] Product image: ${safeFilename}`);

    const fcResp = await fetch(graphqlUrl, {
      method: 'POST', headers: gqlHeaders,
      body: JSON.stringify({
        query: `mutation fileCreate($files: [FileCreateInput!]!) {
          fileCreate(files: $files) {
            files { id fileStatus }
            userErrors { field message }
          }
        }`,
        variables: {
          files: [{
            originalSource: productImageUrl,
            filename:       safeFilename,
            contentType:    'IMAGE',
            alt:            productTitle || safeFilename
          }]
        }
      })
    });
    const fcJson = await fcResp.json();

    if (fcJson.errors?.length || fcJson?.data?.fileCreate?.userErrors?.length) {
      console.error(`[upload] Product fileCreate errors:`, JSON.stringify(fcJson.errors || fcJson?.data?.fileCreate?.userErrors));
      return null;
    }

    const createdFile = fcJson?.data?.fileCreate?.files?.[0];
    if (!createdFile?.id) { console.error('[upload] Product fileCreate returned no file'); return null; }

    console.log(`[upload] Product image GID=${createdFile.id} status=${createdFile.fileStatus}`);
    return createdFile.id;

  } catch (err) {
    console.error('[upload] registerProductImageInFiles error:', err.message);
    return null;
  }
}

/**
 * Fetch product details for a list of product IDs.
 * Returns Map<numericId, { title, imageUrl }>
 */
async function fetchProductDetails(shop, token, productIds) {
  if (!productIds.length) return new Map();
  try {
    const graphqlUrl = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const gids = productIds.map(id => String(id).startsWith('gid://') ? String(id) : `gid://shopify/Product/${id}`);
    const resp = await fetch(graphqlUrl, {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'X-Shopify-Access-Token': token },
      body: JSON.stringify({
        query: `{ nodes(ids: ${JSON.stringify(gids)}) { ... on Product { id title featuredImage { url } } } }`
      })
    });
    const data = await resp.json();
    const result = new Map();
    for (const node of (data?.data?.nodes || [])) {
      if (!node?.id) continue;
      result.set(node.id.replace('gid://shopify/Product/', ''), { title: node.title, imageUrl: node.featuredImage?.url || null });
    }
    return result;
  } catch (err) {
    console.error('fetchProductDetails error:', err);
    return new Map();
  }
}

// ── POST /appointments ──
app.post('/appointments', async (req, res) => {
  const startTime = Date.now();
  try {
    const { name, email, phone, date, time, notes, products, reference_images, shop: reqShop } = req.body || {};
    const shop  = normalizeShop(req, reqShop);
    const token = getTokenForShop(shop);
    if (!token) return res.status(403).json({ ok:false, error:'No access token' });

    // Validation
    const errors = {};
    if (!name?.trim())  errors.name  = 'Name required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email || '')) errors.email = 'Valid email required';
    if (!phone?.trim()) errors.phone = 'Phone required';
    if (!date)          errors.date  = 'Date required';
    if (!time)          errors.time  = 'Time required';
    if (Object.keys(errors).length) return res.status(400).json({ ok:false, errors });

    const datetime = `${date}T${time}:00${STORE_TZ_SUFFIX}`;

    console.log(`\n=== NEW APPOINTMENT: ${email} ===`);
    console.log(`Ref images: ${Array.isArray(reference_images) ? reference_images.length : 0}, Products: ${Array.isArray(products) ? products.length : 0}`);

    // ══════════════════════════════════════════════════════════
    // Collect all file GIDs for the reference_images field
    // ══════════════════════════════════════════════════════════
    const fileGids  = [];
    const uploadLog = [];

    // 1. Upload customer reference images (base64 → S3 → Shopify Files)
    const refImages = Array.isArray(reference_images) ? reference_images : [];
    for (const imgObj of refImages) {
      const gid = await uploadImageToShopifyFiles(shop, token, imgObj);
      if (gid) {
        fileGids.push(gid);
        uploadLog.push(`Ref: ${imgObj.filename || 'image'} ✓`);
      } else {
        uploadLog.push(`Ref: ${imgObj.filename || 'image'} ✗ (upload failed)`);
      }
    }

    // 2. Register product featured images (CDN URL → Shopify Files)
    const productIds = Array.isArray(products) ? products : [];
    if (productIds.length > 0) {
      const productDetails = await fetchProductDetails(shop, token, productIds);
      for (const [, details] of productDetails) {
        if (!details.imageUrl) continue;
        const gid = await registerProductImageInFiles(shop, token, details.imageUrl, details.title);
        if (gid) {
          fileGids.push(gid);
          uploadLog.push(`Product: ${details.title} ✓`);
        } else {
          uploadLog.push(`Product: ${details.title} ✗ (register failed)`);
        }
      }
    }

    console.log(`GIDs collected: ${fileGids.length} in ${Date.now() - startTime}ms`);
    console.log('Upload log:', uploadLog);

    // Build notes
    const notesBase = (notes || '').trim();
    const notesLog  = uploadLog.length > 0
      ? `[Images (${fileGids.length}/${uploadLog.length} uploaded):\n${uploadLog.join('\n')}]`
      : '';
    const finalNotes = [notesBase, notesLog].filter(Boolean).join('\n\n');

    // Build product GIDs for the products field
    const productGids = productIds.map(p => String(p).startsWith('gid://') ? String(p) : `gid://shopify/Product/${p}`);

    // ── Metaobject fields ──
    const fields = [
      { key: 'customer_name',  value: name.trim() },
      { key: 'email',          value: email.trim() },
      { key: 'contact_number', value: phone.trim() },
      { key: 'datetime',       value: datetime },
      { key: 'notes',          value: finalNotes },
      { key: 'status',         value: 'new' }
    ];

    // reference_images: List·Image(File) — JSON array of GID strings
    if (fileGids.length > 0) {
      fields.push({ key: 'reference_images', value: JSON.stringify(fileGids) });
    }

    // products: List·Product
    if (productGids.length > 0) {
      fields.push({ key: 'products', value: JSON.stringify(productGids) });
    }

    // ── Create metaobject ──
    const mutation = `mutation CreateAppointment($metaobject: MetaobjectCreateInput!) {
      metaobjectCreate(metaobject: $metaobject) {
        metaobject { id }
        userErrors { field message }
      }
    }`;

    const createFn = async (fieldList) => {
      const r = await fetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
        method: 'POST',
        headers: { 'Content-Type':'application/json', 'X-Shopify-Access-Token':token },
        body: JSON.stringify({ query: mutation, variables: { metaobject: { type:'appointment', fields: fieldList } } })
      });
      return r.json();
    };

    let data = await createFn(fields);
    let userErrors = data?.data?.metaobjectCreate?.userErrors || [];

    // Graceful retry: if only unknown-field errors, strip bad fields and retry
    if (userErrors.length) {
      console.warn('metaobjectCreate userErrors:', JSON.stringify(userErrors));
      const badKeys = userErrors
        .filter(e => e.message?.toLowerCase().includes('unknown') || e.message?.toLowerCase().includes('invalid'))
        .map(e => Array.isArray(e.field) ? e.field[e.field.length - 1] : e.field)
        .filter(Boolean);

      if (badKeys.length && badKeys.length === userErrors.length) {
        console.warn(`Retrying without: ${badKeys.join(', ')}`);
        data = await createFn(fields.filter(f => !badKeys.includes(f.key)));
        userErrors = data?.data?.metaobjectCreate?.userErrors || [];
      }
    }

    if (userErrors.length) {
      console.error('Metaobject creation failed:', JSON.stringify(userErrors));
      const errMap = {};
      userErrors.forEach(e => { errMap[Array.isArray(e.field) ? e.field.join('.') : 'general'] = e.message; });
      return res.status(400).json({ ok:false, errors:errMap, raw:userErrors });
    }

    const totalMs = Date.now() - startTime;
    console.log(`✅ Appointment created in ${totalMs}ms, ${fileGids.length} image GIDs stored`);
    res.json({ ok: true, reference_image_count: fileGids.length });

  } catch (err) {
    console.error('Create appointment error:', err);
    res.status(500).json({ ok:false, error:'Server error' });
  }
});

// Health
app.get('/', (_req, res) => res.send('Shopify Appointments Server is running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
  console.log(`📍 OAuth URL: ${HOST.replace(/\/$/, '')}/auth?shop=YOUR_STORE.myshopify.com`);
});
