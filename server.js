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
app.use(express.json({ limit: '25mb' })); // raised to handle multiple base64 images
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
    console.log(`✅ Access token acquired for ${shop}`);
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
    if (data.errors) { console.error('GraphQL errors:', data.errors); return res.status(500).json({ ok:false, error:'GraphQL query failed' }); }

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
    if (!token) return res.status(403).json({ ok:false, error:'No access token.', installUrl:`${HOST.replace(/\/$/, '')}/auth?shop=${shop}` });

    res.set('Cache-Control', 'public, max-age=60');

    const PAGE_SIZE = 250;
    let products = [];
    let cursor   = null;
    let hasNext  = true;

    while (hasNext) {
      const afterClause = cursor ? `, after: "${cursor}"` : '';
      const query = `{
        products(first: ${PAGE_SIZE}${afterClause}) {
          pageInfo { hasNextPage endCursor }
          edges {
            node {
              id title handle
              featuredImage { url altText }
            }
          }
        }
      }`;

      const resp = await fetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
        method: 'POST',
        headers: { 'Content-Type':'application/json', 'X-Shopify-Access-Token':token },
        body: JSON.stringify({ query })
      });
      const data = await resp.json();
      if (data.errors) { console.error('Products GraphQL errors:', data.errors); break; }

      const page = data?.data?.products;
      if (!page) break;

      for (const edge of (page.edges || [])) {
        const node = edge.node;
        const numericId = node.id.replace('gid://shopify/Product/', '');
        products.push({
          id: numericId, title: node.title, handle: node.handle,
          images: node.featuredImage ? [{ src: node.featuredImage.url }] : []
        });
      }

      hasNext = page.pageInfo?.hasNextPage || false;
      cursor  = page.pageInfo?.endCursor   || null;
    }

    res.json({ ok: true, products });
  } catch (err) {
    console.error('Products list error:', err);
    res.status(500).json({ ok:false, error:'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════
// SHOPIFY FILES UPLOAD
// Upload a base64 image to Shopify Files (CDN) and return its URL.
//
// Flow:
//   1. stagedUploadsCreate  → Shopify returns a pre-signed S3 target + a resourceUrl
//   2. PUT the binary to S3 → file is now on S3
//   3. fileCreate           → tells Shopify to ingest the S3 file into the Files library
//   4. Poll fileCreate result for the final CDN URL (Shopify processes async)
//
// This gives permanent cdn.shopify.com URLs safe to embed in emails.
// ══════════════════════════════════════════════════════════════

/**
 * Parse a data URL into { mimeType, base64Data, extension }
 */
function parseDataUrl(dataUrl) {
  // data:[<mediatype>][;base64],<data>
  const match = dataUrl.match(/^data:([^;]+);base64,(.+)$/s);
  if (!match) return null;
  const mimeType = match[1];
  const base64Data = match[2];
  const extMap = {
    'image/jpeg': 'jpg', 'image/jpg': 'jpg', 'image/png': 'png',
    'image/webp': 'webp', 'image/gif': 'gif', 'image/heic': 'heic'
  };
  const extension = extMap[mimeType] || 'jpg';
  return { mimeType, base64Data, extension };
}

/**
 * Upload one reference image to Shopify Files.
 * Returns the CDN URL string, or null on failure.
 */
async function uploadReferenceImageToShopify(shop, token, imageObj) {
  try {
    const { filename, data } = imageObj;
    if (!data || !data.startsWith('data:')) return null;

    const parsed = parseDataUrl(data);
    if (!parsed) return null;

    const { mimeType, base64Data, extension } = parsed;
    const safeFilename = filename
      ? filename.replace(/[^a-zA-Z0-9._-]/g, '_')
      : `ref_${Date.now()}.${extension}`;

    const fileSize = Math.ceil(base64Data.length * 0.75); // approximate byte size
    const graphqlUrl = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const headers = { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token };

    // ── Step 1: Request a staged upload target from Shopify ──
    const stageResp = await fetch(graphqlUrl, {
      method: 'POST', headers,
      body: JSON.stringify({
        query: `
          mutation stagedUploadsCreate($input: [StagedUploadInput!]!) {
            stagedUploadsCreate(input: $input) {
              stagedTargets {
                url
                resourceUrl
                parameters { name value }
              }
              userErrors { field message }
            }
          }`,
        variables: {
          input: [{
            filename:   safeFilename,
            mimeType,
            resource:   'FILE',
            fileSize:   String(fileSize),
            httpMethod: 'PUT'
          }]
        }
      })
    });

    const stageData = await stageResp.json();
    if (stageData.errors) {
      console.error('stagedUploadsCreate errors:', stageData.errors);
      return null;
    }
    const userErrors = stageData?.data?.stagedUploadsCreate?.userErrors || [];
    if (userErrors.length) { console.error('stagedUploads userErrors:', userErrors); return null; }

    const target = stageData?.data?.stagedUploadsCreate?.stagedTargets?.[0];
    if (!target) { console.error('No staged target returned'); return null; }

    const { url: uploadUrl, resourceUrl, parameters } = target;

    // ── Step 2: PUT binary to the pre-signed S3 URL ──
    const binaryBuffer = Buffer.from(base64Data, 'base64');

    // Build form fields if Shopify returned parameters (POST-style) — otherwise PUT directly
    let uploadResp;
    if (parameters && parameters.length > 0) {
      // S3 multipart form POST
      const { default: FormData } = await import('form-data');
      const form = new FormData();
      parameters.forEach(p => form.append(p.name, p.value));
      form.append('file', binaryBuffer, { filename: safeFilename, contentType: mimeType });
      uploadResp = await fetch(uploadUrl, { method: 'POST', body: form, headers: form.getHeaders() });
    } else {
      // Direct PUT (more common for FILE resource)
      uploadResp = await fetch(uploadUrl, {
        method: 'PUT',
        headers: { 'Content-Type': mimeType, 'Content-Length': String(binaryBuffer.length) },
        body: binaryBuffer
      });
    }

    if (!uploadResp.ok) {
      const body = await uploadResp.text();
      console.error(`S3 upload failed (${uploadResp.status}):`, body.slice(0, 300));
      return null;
    }

    // ── Step 3: Tell Shopify to ingest the file from S3 ──
    const fileCreateResp = await fetch(graphqlUrl, {
      method: 'POST', headers,
      body: JSON.stringify({
        query: `
          mutation fileCreate($files: [FileCreateInput!]!) {
            fileCreate(files: $files) {
              files {
                id
                fileStatus
                ... on MediaImage { image { url } }
                ... on GenericFile { url }
              }
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
      })
    });

    const fileCreateData = await fileCreateResp.json();
    if (fileCreateData.errors) { console.error('fileCreate errors:', fileCreateData.errors); return null; }
    const fcUserErrors = fileCreateData?.data?.fileCreate?.userErrors || [];
    if (fcUserErrors.length) { console.error('fileCreate userErrors:', fcUserErrors); return null; }

    const createdFiles = fileCreateData?.data?.fileCreate?.files || [];
    const fileId       = createdFiles[0]?.id;

    // ── Step 4: Poll until Shopify has finished processing the file ──
    // Shopify processes files asynchronously; status moves UPLOADED → READY
    if (fileId) {
      const cdnUrl = await pollFileReady(graphqlUrl, headers, fileId);
      if (cdnUrl) { console.log(`✅ Image uploaded: ${cdnUrl}`); return cdnUrl; }
    }

    // Fallback: return the resourceUrl (S3 pre-signed, will eventually redirect to CDN)
    console.warn('File poll timed out, returning resourceUrl as fallback');
    return resourceUrl || null;

  } catch (err) {
    console.error('uploadReferenceImageToShopify error:', err);
    return null;
  }
}

/**
 * Poll the file status until READY, then return the CDN URL.
 * Times out after ~10 s (10 attempts × 1 s delay).
 */
async function pollFileReady(graphqlUrl, headers, fileId, maxAttempts = 10, delayMs = 1000) {
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise(r => setTimeout(r, delayMs));

    const resp = await fetch(graphqlUrl, {
      method: 'POST', headers,
      body: JSON.stringify({
        query: `{
          node(id: "${fileId}") {
            ... on MediaImage {
              fileStatus
              image { url }
            }
            ... on GenericFile {
              fileStatus
              url
            }
          }
        }`
      })
    });

    const data = await resp.json();
    const node = data?.data?.node;
    if (!node) continue;

    if (node.fileStatus === 'READY') {
      return node.image?.url || node.url || null;
    }
    if (node.fileStatus === 'FAILED') {
      console.error('Shopify file processing FAILED for', fileId);
      return null;
    }
    // UPLOADED or PROCESSING — keep polling
  }
  return null; // timed out
}

/**
 * Upload all reference images in parallel (max 5 concurrent).
 * Returns an array of { filename, url } for images that succeeded,
 * and { filename, url: null } for any that failed.
 */
async function uploadAllReferenceImages(shop, token, referenceImages) {
  if (!Array.isArray(referenceImages) || referenceImages.length === 0) return [];

  // Limit concurrency to 5 to avoid hammering the API
  const CONCURRENCY = 5;
  const results = [];

  for (let i = 0; i < referenceImages.length; i += CONCURRENCY) {
    const batch = referenceImages.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(
      batch.map(async imgObj => {
        const url = await uploadReferenceImageToShopify(shop, token, imgObj);
        return { filename: imgObj.filename || 'image', url };
      })
    );
    results.push(...batchResults);
  }

  return results;
}

// ── Build notes field ──
// If images were uploaded successfully we store their CDN URLs.
// If upload failed for some images we still note the filename.
function buildNotesField(notes, uploadedImages) {
  const uploaded = uploadedImages.filter(i => i.url);
  const failed   = uploadedImages.filter(i => !i.url);
  const parts    = [];

  if (uploaded.length) {
    const lines = uploaded.map(i => `${i.filename}: ${i.url}`).join('\n');
    parts.push(`[Reference images (${uploaded.length}):\n${lines}]`);
  }
  if (failed.length) {
    parts.push(`[Images that could not be uploaded: ${failed.map(i => i.filename).join(', ')}]`);
  }

  const base = (notes || '').trim();
  return parts.length ? (base ? `${base}\n\n${parts.join('\n')}` : parts.join('\n')) : base;
}

// ── POST /appointments ──
app.post('/appointments', async (req, res) => {
  try {
    const { name, email, phone, date, time, notes, products, reference_images, shop: reqShop } = req.body || {};
    const shop  = normalizeShop(req, reqShop);
    const token = getTokenForShop(shop);
    if (!token) return res.status(403).json({ ok:false, error:'No access token', installUrl:`${HOST.replace(/\/$/, '')}/auth?shop=${shop}` });

    const errors = {};
    if (!name?.trim())  errors.name  = 'Name required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email || '')) errors.email = 'Valid email required';
    if (!phone?.trim()) errors.phone = 'Phone required';
    if (!date)          errors.date  = 'Date required';
    if (!time)          errors.time  = 'Time required';
    if (Object.keys(errors).length) return res.status(400).json({ ok:false, errors });

    const datetime = `${date}T${time}:00${STORE_TZ_SUFFIX}`;

    // ── Upload reference images to Shopify Files BEFORE creating the metaobject ──
    const imgCount = Array.isArray(reference_images) ? reference_images.length : 0;
    let uploadedImages = [];

    if (imgCount > 0) {
      console.log(`📎 Uploading ${imgCount} reference image(s) for ${email}...`);
      uploadedImages = await uploadAllReferenceImages(shop, token, reference_images);
      const successCount = uploadedImages.filter(i => i.url).length;
      console.log(`✅ ${successCount}/${imgCount} images uploaded successfully`);
    }

    // Build the notes field — now contains CDN URLs instead of just filenames
    const finalNotes = buildNotesField(notes, uploadedImages);

    // ── Build metaobject fields ──
    const fields = [
      { key:'customer_name',   value: name.trim() },
      { key:'email',           value: email.trim() },
      { key:'contact_number',  value: phone.trim() },
      { key:'datetime',        value: datetime },
      { key:'notes',           value: finalNotes },
      { key:'status',          value: 'new' }
    ];

    // Store uploaded image CDN URLs in a dedicated field (JSON array of URL strings)
    // Your Shopify metaobject definition needs a field with key "reference_image_urls"
    // of type "json" (or "list.url"). If you don't have that field yet, the userErrors
    // from Shopify will tell you — you can safely remove these two lines until you add it.
    const uploadedUrls = uploadedImages.filter(i => i.url).map(i => i.url);
    if (uploadedUrls.length > 0) {
      fields.push({ key: 'reference_image_urls', value: JSON.stringify(uploadedUrls) });
    }

    const productGids = (Array.isArray(products) ? products : [])
      .map(p => String(p).startsWith('gid://') ? String(p) : `gid://shopify/Product/${p}`);
    if (productGids.length) fields.push({ key:'products', value: JSON.stringify(productGids) });

    const mutation = `
      mutation CreateAppointment($metaobject: MetaobjectCreateInput!) {
        metaobjectCreate(metaobject: $metaobject) {
          metaobject { id }
          userErrors { field message }
        }
      }`;

    const resp = await fetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'X-Shopify-Access-Token':token },
      body: JSON.stringify({ query: mutation, variables: { metaobject: { type:'appointment', fields } } })
    });
    const data = await resp.json();
    const userErrors = data?.data?.metaobjectCreate?.userErrors || [];

    if (userErrors.length) {
      // If the only error is about the reference_image_urls field not existing yet,
      // retry without that field so the appointment still gets created.
      const isOnlyUnknownField = userErrors.every(e =>
        Array.isArray(e.field) && e.field.includes('reference_image_urls')
      );

      if (isOnlyUnknownField) {
        console.warn('reference_image_urls field not yet in metaobject definition — retrying without it.');
        const fieldsWithoutUrls = fields.filter(f => f.key !== 'reference_image_urls');
        const retry = await fetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
          method: 'POST',
          headers: { 'Content-Type':'application/json', 'X-Shopify-Access-Token':token },
          body: JSON.stringify({ query: mutation, variables: { metaobject: { type:'appointment', fields: fieldsWithoutUrls } } })
        });
        const retryData = await retry.json();
        const retryErrors = retryData?.data?.metaobjectCreate?.userErrors || [];
        if (retryErrors.length) {
          console.error('Metaobject creation errors (retry):', retryErrors);
          const errMap = {};
          retryErrors.forEach(e => { errMap[Array.isArray(e.field) ? e.field.join('.') : 'general'] = e.message; });
          return res.status(400).json({ ok:false, errors:errMap, raw:retryErrors });
        }
        // Succeeded on retry — return uploaded URLs so the client has them if needed
        return res.json({ ok:true, reference_image_urls: uploadedUrls });
      }

      console.error('Metaobject creation errors:', userErrors);
      const errMap = {};
      userErrors.forEach(e => { errMap[Array.isArray(e.field) ? e.field.join('.') : 'general'] = e.message; });
      return res.status(400).json({ ok:false, errors:errMap, raw:userErrors });
    }

    res.json({ ok:true, reference_image_urls: uploadedUrls });

  } catch (err) { console.error('Create appointment error:', err); res.status(500).json({ ok:false, error:'Server error' }); }
});

// Health
app.get('/', (_req, res) => res.send('Shopify Appointments Server is running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
  console.log(`📍 OAuth URL: ${HOST.replace(/\/$/, '')}/auth?shop=YOUR_STORE.myshopify.com`);
});
