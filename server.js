import express from "express";
import cors from "cors";

const app = express();

// ---- ENV (all will be set on Render, not hardcoded) ----
const {
  SHOPIFY_STORE_DOMAIN,     // e.g. your-store.myshopify.com
  SHOPIFY_ADMIN_API_TOKEN,  // Admin API access token
  API_VERSION = "2024-07",  // Shopify Admin API version
  METAOBJECT_TYPE = "appointment",
  ALLOWED_ORIGINS           // comma-separated list of allowed origins (front-end domains)
} = process.env;

if (!SHOPIFY_STORE_DOMAIN || !SHOPIFY_ADMIN_API_TOKEN) {
  console.warn("[WARN] Missing required environment variables.");
}

// ---- CORS ----
const allowed = new Set(
  (ALLOWED_ORIGINS || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean)
);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // allow server-to-server / curl
    return cb(null, allowed.size === 0 || allowed.has(origin));
  },
  methods: ["POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"]
}));

// ---- Body parsing ----
app.use(express.json({ limit: "1mb" }));

// ---- Helpers ----
const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function toGid(productIdOrGid) {
  const s = String(productIdOrGid);
  return s.startsWith("gid://") ? s : `gid://shopify/Product/${s}`;
}

// ---- Routes ----
app.post("/appointments", async (req, res) => {
  try {
    const { name, email, phone, date, time, notes = "", products = [] } = req.body || {};

    const errors = {};
    if (!name?.trim()) errors.name = "Please enter your name";
    if (!emailRx.test(email || "")) errors.email = "Enter a valid email";
    if (!phone?.trim()) errors.phone = "Please enter your contact number";
    if (!date) errors.date = "Pick a date";
    if (!time) errors.time = "Pick a time";

    if (Object.keys(errors).length) {
      return res.status(422).json({ ok: false, errors });
    }

    const datetimeISO = new Date(`${date}T${time}`).toISOString();

    const productGids = Array.isArray(products)
      ? products.map(toGid)
      : [];

    const fields = [
      { key: "customer_name",  value: name.trim() },
      { key: "email",          value: (email || "").trim() },
      { key: "contact_number", value: (phone || "").trim() },
      { key: "datetime",       value: datetimeISO },
      { key: "notes",          value: (notes || "").trim() },
      { key: "status",         value: "new" }
    ];
    if (productGids.length) {
      fields.push({ key: "products", value: JSON.stringify(productGids) });
    }

    const query = `
      mutation CreateAppointment($metaobject: MetaobjectCreateInput!) {
        metaobjectCreate(metaobject: $metaobject) {
          metaobject { id }
          userErrors { field message }
        }
      }
    `;
    const variables = {
      metaobject: {
        definition: { type: METAOBJECT_TYPE },
        fields
      }
    };

    const resp = await fetch(`https://${SHOPIFY_STORE_DOMAIN}/admin/api/${API_VERSION}/graphql.json`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_API_TOKEN
      },
      body: JSON.stringify({ query, variables })
    });

    const data = await resp.json();

    if (!resp.ok || data.errors || data?.data?.metaobjectCreate?.userErrors?.length) {
      return res.status(500).json({
        ok: false,
        error: data.errors || data?.data?.metaobjectCreate?.userErrors || "Unknown error"
      });
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Health check (optional)
app.get("/", (_req, res) => {
  res.type("text").send("OK");
});

// Render provides PORT
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Appointments server running on :${PORT}`);
});
