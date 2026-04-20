// server.js (ESM)

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

// ══════════════════════════════════════════════════════════════
// SHOPIFY FILES UPLOAD
//
// Returns { gid, url } for a successfully uploaded image, or null.
//
// The GID (e.g. "gid://shopify/MediaImage/123456") is what gets stored
// in the metaobject's  reference_images  List·Image(File) field.
// Shopify Flow then resolves it to an image URL via:
//   metaobject.referenceImages | map: 'image' | map: 'url'
// ══════════════════════════════════════════════════════════════

function parseDataUrl(dataUrl) {
  const match = dataUrl.match(/^data:([^;]+);base64,(.+)$/s);
  if (!match) return null;
  const mimeType   = match[1];
  const base64Data = match[2].replace(/\s/g, '');
  const extMap = { 'image/jpeg':'jpg','image/jpg':'jpg','image/png':'png','image/webp':'webp','image/gif':'gif','image/heic':'heic' };
  return { mimeType, base64Data, extension: extMap[mimeType] || 'jpg' };
}

/**
 * Upload one image (base64 data URL) to Shopify Files.
 * Returns { gid, url } on success, null on failure.
 *   gid  – "gid://shopify/MediaImage/…"  → stored in reference_images field
 *   url  – cdn.shopify.com URL            → put in notes for human readability
 */
async function uploadImageToShopifyFiles(shop, token, imageObj) {
  try {
    const { filename, data } = imageObj;
    if (!data || !data.startsWith('data:')) {
      console.error('uploadImage: missing data URL for', filename);
      return null;
    }

    const parsed = parseDataUrl(data);
    if (!parsed) { console.error('uploadImage: bad data URL for', filename); return null; }

    const { mimeType, base64Data, extension } = parsed;
    const binaryBuffer = Buffer.from(base64Data, 'base64');
    const exactByteSize = binaryBuffer.length;
    const safeFilename  = (filename || `ref_${Date.now()}.${extension}`).replace(/[^a-zA-Z0-9._-]/g, '_');

    const graphqlUrl = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const gqlHeaders = { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token };

    console.log(`📤 Staging: ${safeFilename} (${exactByteSize} bytes, ${mimeType})`);

    // ── Step 1: stagedUploadsCreate ──
    const stageResp = await fetch(graphqlUrl, {
      method: 'POST', headers: gqlHeaders,
      body: JSON.stringify({
        query: `mutation stagedUploadsCreate($input: [StagedUploadInput!]!) {
          stagedUploadsCreate(input: $input) {
            stagedTargets { url resourceUrl parameters { name value } }
            userErrors { field message }
          }
        }`,
        variables: { input: [{ filename: safeFilename, mimeType, resource: 'FILE', fileSize: String(exactByteSize), httpMethod: 'PUT' }] }
      })
    });
    const stageJson = await stageResp.json();
    if (stageJson.errors || stageJson?.data?.stagedUploadsCreate?.userErrors?.length) {
      console.error('stagedUploadsCreate failed:', JSON.stringify(stageJson.errors || stageJson?.data?.stagedUploadsCreate?.userErrors));
      return null;
    }
    const target = stageJson?.data?.stagedUploadsCreate?.stagedTargets?.[0];
    if (!target) { console.error('No staged target'); return null; }
    const { url: s3Url, resourceUrl } = target;

    // ── Step 2: PUT binary to S3 ──
    const s3Resp = await fetch(s3Url, {
      method: 'PUT',
      headers: { 'Content-Type': mimeType, 'Content-Length': String(exactByteSize) },
      body: binaryBuffer
    });
    if (!s3Resp.ok) {
      console.error(`S3 PUT failed (${s3Resp.status}):`, (await s3Resp.text()).slice(0, 300));
      return null;
    }
    console.log(`✅ S3 PUT OK (${s3Resp.status})`);

    // ── Step 3: fileCreate ──
    const fcResp = await fetch(graphqlUrl, {
      method: 'POST', headers: gqlHeaders,
      body: JSON.stringify({
        query: `mutation fileCreate($files: [FileCreateInput!]!) {
          fileCreate(files: $files) {
            files {
              id fileStatus
              ... on MediaImage { image { url } }
              ... on GenericFile  { url }
            }
            userErrors { field message }
          }
        }`,
        variables: { files: [{ originalSource: resourceUrl, filename: safeFilename, contentType: 'IMAGE', alt: safeFilename }] }
      })
    });
    const fcJson = await fcResp.json();
    if (fcJson.errors || fcJson?.data?.fileCreate?.userErrors?.length) {
      console.error('fileCreate failed:', JSON.stringify(fcJson.errors || fcJson?.data?.fileCreate?.userErrors));
      return null;
    }
    const createdFile = fcJson?.data?.fileCreate?.files?.[0];
    if (!createdFile) { console.error('fileCreate returned no file'); return null; }

    const fileGid = createdFile.id;
    console.log(`📋 File GID: ${fileGid}  status: ${createdFile.fileStatus}`);

    // If immediately READY, return both gid and url now
    if (createdFile.fileStatus === 'READY') {
      const url = createdFile.image?.url || createdFile.url || null;
      if (url) { console.log(`✅ Immediately READY: ${url}`); return { gid: fileGid, url }; }
    }

    // ── Step 4: Poll for READY ──
    const result = await pollFileReady(graphqlUrl, gqlHeaders, fileGid, 15, 1200);
    if (result) { console.log(`✅ READY after poll: ${result.url}`); return { gid: fileGid, url: result.url }; }

    // Timeout fallback — return gid without url; Flow can still resolve the image
    console.warn(`⚠️  Poll timed out for ${safeFilename}. Returning GID without confirmed URL.`);
    return { gid: fileGid, url: resourceUrl };

  } catch (err) {
    console.error('uploadImageToShopifyFiles error:', err);
    return null;
  }
}

async function pollFileReady(graphqlUrl, headers, fileId, maxAttempts = 15, delayMs = 1200) {
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise(r => setTimeout(r, delayMs));
    try {
      const resp = await fetch(graphqlUrl, {
        method: 'POST', headers,
        body: JSON.stringify({
          query: `{ node(id: "${fileId}") {
            ... on MediaImage { fileStatus image { url } }
            ... on GenericFile  { fileStatus url }
          }}`
        })
      });
      const data = await resp.json();
      const node = data?.data?.node;
      if (!node) continue;
      console.log(`  poll ${i+1}: ${node.fileStatus}`);
      if (node.fileStatus === 'READY')  return { url: node.image?.url || node.url };
      if (node.fileStatus === 'FAILED') { console.error('File FAILED:', fileId); return null; }
    } catch (e) { console.warn(`poll error attempt ${i+1}:`, e.message); }
  }
  return null;
}

/**
 * Given a product image URL (already a CDN URL from Shopify), upload it to the
 * Files library so we can get a proper MediaImage GID for the metaobject field.
 * Returns { gid, url } or null.
 */
async function uploadProductImageToShopifyFiles(shop, token, productImageUrl, productTitle) {
  try {
    if (!productImageUrl) return null;

    const graphqlUrl = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const gqlHeaders = { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token };

    // Product images already live on Shopify CDN — we can use fileCreate with
    // originalSource directly (no S3 staging needed for external URLs).
    const safeFilename = `product_${productTitle.replace(/[^a-zA-Z0-9._-]/g,'_').slice(0,60)}_${Date.now()}.jpg`;

    console.log(`📤 Registering product image in Files: ${safeFilename}`);

    const fcResp = await fetch(graphqlUrl, {
      method: 'POST', headers: gqlHeaders,
      body: JSON.stringify({
        query: `mutation fileCreate($files: [FileCreateInput!]!) {
          fileCreate(files: $files) {
            files {
              id fileStatus
              ... on MediaImage { image { url } }
              ... on GenericFile  { url }
            }
            userErrors { field message }
          }
        }`,
        variables: { files: [{ originalSource: productImageUrl, filename: safeFilename, contentType: 'IMAGE', alt: productTitle }] }
      })
    });
    const fcJson = await fcResp.json();
    if (fcJson.errors || fcJson?.data?.fileCreate?.userErrors?.length) {
      console.error('Product image fileCreate failed:', JSON.stringify(fcJson.errors || fcJson?.data?.fileCreate?.userErrors));
      return null;
    }
    const createdFile = fcJson?.data?.fileCreate?.files?.[0];
    if (!createdFile) return null;

    const fileGid = createdFile.id;
    if (createdFile.fileStatus === 'READY') {
      const url = createdFile.image?.url || createdFile.url || productImageUrl;
      return { gid: fileGid, url };
    }

    const result = await pollFileReady(graphqlUrl, gqlHeaders, fileGid, 15, 1200);
    return result ? { gid: fileGid, url: result.url } : { gid: fileGid, url: productImageUrl };

  } catch (err) {
    console.error('uploadProductImageToShopifyFiles error:', err);
    return null;
  }
}

/**
 * Fetch product details (title + featured image URL) for a list of product GIDs.
 * Returns Map<numericId, { title, imageUrl }>
 */
async function fetchProductDetails(shop, token, productIds) {
  if (!productIds.length) return new Map();
  try {
    const graphqlUrl = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const gids = productIds.map(id => String(id).startsWith('gid://') ? String(id) : `gid://shopify/Product/${id}`);

    const query = `{
      nodes(ids: ${JSON.stringify(gids)}) {
        ... on Product {
          id title
          featuredImage { url }
        }
      }
    }`;

    const resp = await fetch(graphqlUrl, {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'X-Shopify-Access-Token': token },
      body: JSON.stringify({ query })
    });
    const data = await resp.json();
    const result = new Map();
    for (const node of (data?.data?.nodes || [])) {
      if (!node?.id) continue;
      const numericId = node.id.replace('gid://shopify/Product/', '');
      result.set(numericId, { title: node.title, imageUrl: node.featuredImage?.url || null });
    }
    return result;
  } catch (err) {
    console.error('fetchProductDetails error:', err);
    return new Map();
  }
}

// ── POST /appointments ──
app.post('/appointments', async (req, res) => {
  try {
    const { name, email, phone, date, time, notes, products, reference_images, shop: reqShop } = req.body || {};
    const shop  = normalizeShop(req, reqShop);
    const token = getTokenForShop(shop);
    if (!token) return res.status(403).json({ ok:false, error:'No access token' });

    const errors = {};
    if (!name?.trim())  errors.name  = 'Name required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email || '')) errors.email = 'Valid email required';
    if (!phone?.trim()) errors.phone = 'Phone required';
    if (!date)          errors.date  = 'Date required';
    if (!time)          errors.time  = 'Time required';
    if (Object.keys(errors).length) return res.status(400).json({ ok:false, errors });

    const datetime = `${date}T${time}:00${STORE_TZ_SUFFIX}`;

    // ══════════════════════════════════════════════════════════
    // Build the reference_images field — ALL visuals in one list
    //
    // Order: uploaded reference images first, then product images
    // Each item becomes a file GID stored in the List·Image(File) field.
    // Shopify Flow accesses image URLs via:
    //   metaobject.referenceImages | map: 'image' | map: 'url'
    // ══════════════════════════════════════════════════════════

    const fileGids = [];   // GIDs for the metaobject field
    const uploadLog = []; // human-readable notes log

    // ── 1. Upload customer reference images (base64) ──
    const refImages = Array.isArray(reference_images) ? reference_images : [];
    if (refImages.length > 0) {
      console.log(`\n📎 Uploading ${refImages.length} customer reference image(s) for ${email}`);
      for (const imgObj of refImages) {
        const result = await uploadImageToShopifyFiles(shop, token, imgObj);
        if (result?.gid) {
          fileGids.push(result.gid);
          uploadLog.push(`Ref: ${imgObj.filename || 'image'} → ${result.url}`);
          console.log(`  ✅ ${imgObj.filename} → GID: ${result.gid}`);
        } else {
          uploadLog.push(`Ref: ${imgObj.filename || 'image'} → upload failed`);
          console.warn(`  ⚠️  Failed to upload ${imgObj.filename}`);
        }
      }
    }

    // ── 2. Upload product featured images from product IDs ──
    const productIds = Array.isArray(products) ? products : [];
    if (productIds.length > 0) {
      console.log(`\n🛍  Fetching + uploading ${productIds.length} product image(s)`);
      const productDetails = await fetchProductDetails(shop, token, productIds);

      for (const [numericId, details] of productDetails) {
        if (!details.imageUrl) { console.warn(`  ⚠️  No image for product ${numericId}`); continue; }
        const result = await uploadProductImageToShopifyFiles(shop, token, details.imageUrl, details.title);
        if (result?.gid) {
          fileGids.push(result.gid);
          uploadLog.push(`Product: ${details.title} → ${result.url}`);
          console.log(`  ✅ ${details.title} → GID: ${result.gid}`);
        } else {
          console.warn(`  ⚠️  Failed to upload image for ${details.title}`);
        }
      }
    }

    console.log(`\n📋 Total file GIDs collected: ${fileGids.length}`);

    // ── Build the notes field (human-readable log) ──
    const notesBase = (notes || '').trim();
    const notesLog  = uploadLog.length
      ? `[Reference images (${fileGids.length}):\n${uploadLog.join('\n')}]`
      : '';
    const finalNotes = notesBase && notesLog ? `${notesBase}\n\n${notesLog}` : (notesBase || notesLog);

    // ── Build product GIDs for the products field (unchanged) ──
    const productGids = productIds.map(p => String(p).startsWith('gid://') ? String(p) : `gid://shopify/Product/${p}`);

    // ── Metaobject fields ──
    // reference_images: List·Image(File) — stores file GIDs
    // Each GID is a JSON-encoded string in the array (Shopify metaobject list format)
    const fields = [
      { key: 'customer_name',  value: name.trim() },
      { key: 'email',          value: email.trim() },
      { key: 'contact_number', value: phone.trim() },
      { key: 'datetime',       value: datetime },
      { key: 'notes',          value: finalNotes },
      { key: 'status',         value: 'new' }
    ];

    // reference_images field — value is a JSON array of GID strings
    // This is how Shopify stores List type fields in metaobjects
    if (fileGids.length > 0) {
      fields.push({ key: 'reference_images', value: JSON.stringify(fileGids) });
    }

    // products field — unchanged, still stores product GIDs
    if (productGids.length > 0) {
      fields.push({ key: 'products', value: JSON.stringify(productGids) });
    }

    // ── Create metaobject ──
    const mutation = `
      mutation CreateAppointment($metaobject: MetaobjectCreateInput!) {
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

    // Graceful retry: strip any fields Shopify doesn't recognise and retry once
    if (userErrors.length) {
      const badFields = userErrors
        .filter(e => e.message?.toLowerCase().includes('unknown') || e.message?.toLowerCase().includes('invalid field'))
        .map(e => (Array.isArray(e.field) ? e.field[e.field.length - 1] : e.field))
        .filter(Boolean);

      if (badFields.length && badFields.length === userErrors.length) {
        console.warn(`⚠️  Retrying without unrecognised fields: ${badFields.join(', ')}`);
        data = await createFn(fields.filter(f => !badFields.includes(f.key)));
        userErrors = data?.data?.metaobjectCreate?.userErrors || [];
      }
    }

    if (userErrors.length) {
      console.error('Metaobject creation errors:', JSON.stringify(userErrors));
      const errMap = {};
      userErrors.forEach(e => { errMap[Array.isArray(e.field) ? e.field.join('.') : 'general'] = e.message; });
      return res.status(400).json({ ok:false, errors:errMap, raw:userErrors });
    }

    console.log(`✅ Appointment created for ${email} with ${fileGids.length} reference image(s)`);
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
