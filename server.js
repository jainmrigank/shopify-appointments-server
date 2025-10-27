require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');

const cookieParser = require('cookie-parser');
app.use(cookieParser());

const app = express();
app.use(express.json());

// Environment variables
const API_KEY = process.env.SHOPIFY_API_KEY;
const API_SECRET = process.env.SHOPIFY_API_SECRET;
const SCOPES = process.env.SCOPES || 'write_customers,read_customers,write_metaobjects,read_metaobjects,read_products';
const HOST = process.env.HOST || 'https://shopify-appointments-server.onrender.com';
const API_VERSION = process.env.API_VERSION || '2025-10';

// Simple file-based token storage
const TOKENS_FILE = path.join(__dirname, 'tokens.json');
function readTokens() {
  if (!fs.existsSync(TOKENS_FILE)) return {};
  return JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8'));
}
function writeTokens(tokens) {
  fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2));
}

// Normalize shop domain
function normalizeShop(req, fallback = '') {
  return (req.query.shop || req.body?.shop || fallback || '').replace(/^https?:\/\//, '').replace(/\/$/, '');
}

// CORS Configuration
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const isAllowed = !origin || 
    allowedOrigins.includes(origin) || 
    (origin && new URL(origin).hostname.endsWith('.myshopify.com'));
  
  if (isAllowed) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Shopify-Shop-Domain');
    res.header('Access-Control-Expose-Headers', 'Content-Type');
  }
  
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// HMAC Verification
function verifyHmac(query, hmac) {
  const message = Object.keys(query)
    .filter(key => key !== 'hmac' && key !== 'signature')
    .sort()
    .map(key => `${key}=${query[key]}`)
    .join('&');
  
  const hash = crypto
    .createHmac('sha256', API_SECRET)
    .update(message)
    .digest('hex');
  
  return hash === hmac;
}

// Generate nonce
function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

// ============ OAUTH ROUTES ============

// Step 1: Install initiation (redirect to Shopify auth)
app.get('/auth', (req, res) => {
  const shop = normalizeShop(req);
  
  if (!shop || !/^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shop)) {
    return res.status(400).send('Invalid shop parameter');
  }

  const nonce = generateNonce();
  const redirectUri = `${HOST}/auth/callback`;
  const installUrl = `https://${shop}/admin/oauth/authorize?` +
    `client_id=${API_KEY}&` +
    `scope=${SCOPES}&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&` +
    `state=${nonce}`;

  // Store nonce in cookie for verification
  res.cookie('shopify_nonce', nonce, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 600000 // 10 minutes
  });

  res.redirect(installUrl);
});

// Step 2: OAuth callback (exchange code for token)
app.get('/auth/callback', async (req, res) => {
  const { code, hmac, shop, state } = req.query;
  
  // Security checks
  if (!verifyHmac(req.query, hmac)) {
    return res.status(403).send('HMAC verification failed');
  }

  const nonce = req.cookies?.shopify_nonce;
  if (state !== nonce) {
    return res.status(403).send('State verification failed');
  }

  if (!/^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shop)) {
    return res.status(400).send('Invalid shop');
  }

  // Exchange code for access token
  try {
    const tokenUrl = `https://${shop}/admin/oauth/access_token`;
    const payload = {
      client_id: API_KEY,
      client_secret: API_SECRET,
      code
    };

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok || !data.access_token) {
      console.error('Token exchange failed:', data);
      return res.status(500).send('Failed to get access token');
    }

    // Store token
    const tokens = readTokens();
    tokens[shop] = {
      accessToken: data.access_token,
      scope: data.scope,
      createdAt: new Date().toISOString()
    };
    writeTokens(tokens);

    console.log(`✅ Access token acquired for ${shop}`);

    // Redirect to your app
    res.send(`
      <html>
        <head><title>Installation Complete</title></head>
        <body>
          <h2>App installed successfully!</h2>
          <p>You can now close this window and refresh your store admin.</p>
          <script>
            setTimeout(() => {
              window.location.href = 'https://${shop}/admin/apps';
            }, 2000);
          </script>
        </body>
      </html>
    `);

  } catch (error) {
    console.error('OAuth callback error:', error);
    res.status(500).send('OAuth error');
  }
});

// ============ API ROUTES ============

// Get availability
app.get('/appointments/availability', async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    
    const shop = normalizeShop(req);
    const tokens = readTokens();
    const token = tokens[shop]?.accessToken;

    if (!token) {
      return res.status(403).json({
        ok: false,
        error: 'No access token. Please install the app first.',
        installUrl: `${HOST}/auth?shop=${shop}`
      });
    }

    // Query metaobjects for appointments
    const query = `{
      metaobjects(first: 250, type: "appointment") {
        edges {
          node {
            fields {
              key
              value
            }
          }
        }
      }
    }`;

    const apiUrl = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': token
      },
      body: JSON.stringify({ query })
    });

    const data = await response.json();

    if (data.errors) {
      console.error('GraphQL errors:', data.errors);
      return res.status(500).json({ ok: false, error: 'GraphQL query failed' });
    }

    // Parse bookings
    const bookings = [];
    const edges = data.data?.metaobjects?.edges || [];

    edges.forEach(edge => {
      const fields = edge.node.fields || [];
      const fieldMap = {};
      fields.forEach(f => { fieldMap[f.key] = f.value; });

      if (fieldMap.datetime) {
        const dt = new Date(fieldMap.datetime);
        bookings.push({
          date: dt.toISOString().slice(0, 10),
          time: dt.toISOString().slice(11, 16)
        });
      }
    });

    res.json({ ok: true, bookings });

  } catch (error) {
    console.error('Availability error:', error);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Create appointment
app.post('/appointments', async (req, res) => {
  try {
    const { name, email, phone, date, time, notes, products, shop: reqShop } = req.body;
    const shop = normalizeShop(req, reqShop);
    
    const tokens = readTokens();
    const token = tokens[shop]?.accessToken;

    if (!token) {
      return res.status(403).json({
        ok: false,
        error: 'No access token',
        installUrl: `${HOST}/auth?shop=${shop}`
      });
    }

    // Validation
    const errors = {};
    if (!name?.trim()) errors.name = 'Name required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email || '')) errors.email = 'Valid email required';
    if (!phone?.trim()) errors.phone = 'Phone required';
    if (!date) errors.date = 'Date required';
    if (!time) errors.time = 'Time required';

    if (Object.keys(errors).length) {
      return res.status(400).json({ ok: false, errors });
    }

    // Build datetime
    const datetime = new Date(`${date}T${time}:00Z`).toISOString();

    // Build fields
    const fields = [
      { key: 'customer_name', value: name.trim() },
      { key: 'email', value: email.trim() },
      { key: 'contact_number', value: phone.trim() },
      { key: 'datetime', value: datetime },
      { key: 'notes', value: notes?.trim() || '' },
      { key: 'status', value: 'new' }
    ];

    // Add products if provided
    const productGids = (Array.isArray(products) ? products : [])
      .map(p => String(p).startsWith('gid://') ? String(p) : `gid://shopify/Product/${p}`);

    if (productGids.length) {
      fields.push({ key: 'products', references: productGids });
    }

    // Create metaobject
    const mutation = `
      mutation CreateAppointment($metaobject: MetaobjectCreateInput!) {
        metaobjectCreate(metaobject: $metaobject) {
          metaobject { id }
          userErrors { field message }
        }
      }`;

    const variables = { metaobject: { type: 'appointment', fields } };
    const apiUrl = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;

    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': token
      },
      body: JSON.stringify({ query: mutation, variables })
    });

    const data = await response.json();
    const userErrors = data.data?.metaobjectCreate?.userErrors || [];

    if (userErrors.length) {
      console.error('Metaobject creation errors:', userErrors);
      return res.status(500).json({ ok: false, error: userErrors });
    }

    res.json({ ok: true });

  } catch (error) {
    console.error('Appointment creation error:', error);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Health check
app.get('/', (req, res) => {
  res.send('Shopify Appointments Server is running');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
  console.log(`📍 OAuth URL: ${HOST}/auth?shop=YOUR_STORE.myshopify.com`);
});
