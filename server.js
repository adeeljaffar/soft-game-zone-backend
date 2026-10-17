'use strict';
/**
 * SOFT GAME ZONE — E-Commerce REST API
 * Express + MongoDB (Mongoose) + Nodemailer + JWT admin auth
 */
require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

/* ════════════════════════════ CONFIG ════════════════════════════ */
const env = process.env;
const CONFIG = {
  port: Number(env.PORT) || 5000,
  mongoUri: env.MONGODB_URI,
  jwtSecret: env.JWT_SECRET,
  adminUser: env.ADMIN_USERNAME || 'admin',
  adminPass: env.ADMIN_PASSWORD,
  origins: (env.FRONTEND_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean),
  storeName: env.STORE_NAME || 'SOFT GAME ZONE',
  currency: env.CURRENCY || 'PKR',
  deliveryFee: Math.max(0, Number(env.DELIVERY_FEE) || 0),
  whatsapp: (env.STORE_WHATSAPP || '923201047224').replace(/\D/g, ''),
  tz: env.STORE_TZ || 'Asia/Karachi',
  seed: String(env.SEED_SAMPLE_DATA).toLowerCase() === 'true',
  smtp: {
    host: env.SMTP_HOST,
    port: Number(env.SMTP_PORT) || 587,
    secure: String(env.SMTP_SECURE).toLowerCase() === 'true',
    user: env.SMTP_USER,
    pass: env.SMTP_PASS,
  },
  mailFrom: env.MAIL_FROM || env.SMTP_USER,
  adminEmail: env.ADMIN_EMAIL || env.SMTP_USER,
};

const missing = ['MONGODB_URI', 'JWT_SECRET', 'ADMIN_PASSWORD'].filter((k) => !env[k]);
if (missing.length) {
  console.error(`✖ Missing required environment variables: ${missing.join(', ')}`);
  process.exit(1);
}
if (CONFIG.jwtSecret.length < 24) {
  console.warn('⚠ JWT_SECRET is short — use at least 32 random characters.');
}

const STATUSES = ['Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled'];
const ORDER_ID_RE = /^SGZ-[A-Z0-9]{6}$/;

/* ════════════════════════════ HELPERS ════════════════════════════ */
const asyncH = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/** Trim, strip control characters and cap length. Always returns a string. */
const clean = (v, max = 200) =>
  String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);

const esc = (v) =>
  String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const escapeRegex = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const isObjectId = (v) => typeof v === 'string' && /^[a-f0-9]{24}$/i.test(v);
const money = (n) => `${CONFIG.currency} ${Number(n || 0).toLocaleString('en-US')}`;
const phoneKey = (p) => String(p).replace(/\D/g, '').slice(-10); // matches 0300…, +92300…, 92300…
const safeEqual = (a, b) => {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
};
const httpError = (status, message) => Object.assign(new Error(message), { status, expose: true });

/* ════════════════════════════ MODELS ════════════════════════════ */
mongoose.set('strictQuery', true);

const productSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 120 },
    category: { type: String, required: true, trim: true, maxlength: 60, index: true },
    image: { type: String, default: '', trim: true, maxlength: 600 },
    description: { type: String, default: '', trim: true, maxlength: 600 },
    oldPrice: { type: Number, default: 0, min: 0 },
    price: { type: Number, required: true, min: 0 },
    inStock: { type: Boolean, default: true },
    active: { type: Boolean, default: true }, // hidden from the storefront when false
    featured: { type: Boolean, default: false },
  },
  { timestamps: true }
);
const Product = mongoose.model('Product', productSchema);

const orderItemSchema = new mongoose.Schema(
  {
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    title: String,
    image: String,
    price: Number,
    qty: Number,
  },
  { _id: false }
);

const orderSchema = new mongoose.Schema(
  {
    orderId: { type: String, required: true, unique: true, index: true },
    customer: {
      name: { type: String, required: true },
      phone: { type: String, required: true },
      phoneKey: { type: String, required: true, index: true },
      email: { type: String, required: true },
      address: { type: String, required: true },
      city: { type: String, required: true },
    },
    items: { type: [orderItemSchema], validate: (v) => v.length > 0 },
    subtotal: Number,
    deliveryFee: Number,
    total: Number,
    paymentMethod: { type: String, default: 'Cash on Delivery' },
    notes: { type: String, default: '' },
    status: { type: String, enum: STATUSES, default: 'Pending', index: true },
    statusHistory: [{ _id: false, status: String, at: { type: Date, default: Date.now } }],
    deliveredEmailSent: { type: Boolean, default: false },
  },
  { timestamps: true }
);
orderSchema.index({ createdAt: -1 });
const Order = mongoose.model('Order', orderSchema);

/* ════════════════════════════ EMAIL (Nodemailer) ════════════════════════════ */
let transporter = null;
if (CONFIG.smtp.host) {
  transporter = nodemailer.createTransport({
    host: CONFIG.smtp.host,
    port: CONFIG.smtp.port,
    secure: CONFIG.smtp.secure,
    auth: CONFIG.smtp.user ? { user: CONFIG.smtp.user, pass: CONFIG.smtp.pass } : undefined,
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
  });
} else {
  console.warn('⚠ SMTP_HOST not set — email notifications are disabled.');
}

/** Never throws: email problems must not break order flow. */
async function sendMail({ to, subject, html, text }) {
  if (!transporter || !to) return false;
  try {
    await transporter.sendMail({ from: CONFIG.mailFrom, to, subject, html, text });
    return true;
  } catch (err) {
    console.error(`✖ Email to ${to} failed: ${err.message}`);
    return false;
  }
}

function emailShell(title, inner) {
  return `<!doctype html><html><body style="margin:0;background:#0b0c10;font-family:Segoe UI,Arial,sans-serif;color:#e8eaf0">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0b0c10;padding:24px 12px"><tr><td align="center">
  <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#14161d;border:1px solid #232634;border-radius:14px;overflow:hidden">
    <tr><td style="padding:22px 28px;background:linear-gradient(90deg,#0b0c10,#1a1033);border-bottom:2px solid #00d4ff">
      <div style="font-size:22px;font-weight:800;letter-spacing:1px;color:#fff">SOFT GAME <span style="color:#00d4ff">ZONE</span></div></td></tr>
    <tr><td style="padding:28px">
      <h2 style="margin:0 0 14px;font-size:20px;color:#fff">${esc(title)}</h2>${inner}
    </td></tr>
    <tr><td style="padding:16px 28px;border-top:1px solid #232634;font-size:12px;color:#8b90a3">
      ${esc(CONFIG.storeName)} · Questions? ${CONFIG.whatsapp ? `WhatsApp +${esc(CONFIG.whatsapp)}` : 'Reply to this email.'}</td></tr>
  </table></td></tr></table></body></html>`;
}

function itemsTable(order) {
  const rows = order.items
    .map(
      (i) => `<tr><td style="padding:8px 0;border-bottom:1px solid #232634">${esc(i.title)} × ${i.qty}</td>
      <td align="right" style="padding:8px 0;border-bottom:1px solid #232634">${esc(money(i.price * i.qty))}</td></tr>`
    )
    .join('');
  return `<table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;margin:12px 0">${rows}
    <tr><td style="padding:8px 0;color:#8b90a3">Delivery</td><td align="right" style="color:#8b90a3">${order.deliveryFee ? esc(money(order.deliveryFee)) : 'Free'}</td></tr>
    <tr><td style="padding:10px 0;font-weight:700;color:#fff">Total (Cash on Delivery)</td>
    <td align="right" style="font-weight:800;color:#00d4ff;font-size:16px">${esc(money(order.total))}</td></tr></table>`;
}

function customerBlock(order) {
  const c = order.customer;
  return `<p style="font-size:14px;line-height:1.6;margin:8px 0;color:#c9cde0">
    <b style="color:#fff">${esc(c.name)}</b><br>${esc(c.address)}, ${esc(c.city)}<br>📞 ${esc(c.phone)} · ✉ ${esc(c.email)}</p>`;
}

async function sendOrderEmails(order) {
  const table = itemsTable(order);
  await Promise.allSettled([
    sendMail({
      to: order.customer.email,
      subject: `Order Confirmed ${order.orderId} — ${CONFIG.storeName}`,
      html: emailShell(
        `Thanks ${order.customer.name.split(' ')[0]}, your order is confirmed!`,
        `<p style="font-size:14px;color:#c9cde0;margin:0 0 6px">Your order ID is
          <b style="color:#00d4ff;font-size:16px">${esc(order.orderId)}</b>. Keep it to track your delivery on our website.</p>
          ${table}<p style="font-size:13px;color:#8b90a3;margin:14px 0 4px">Delivering to:</p>${customerBlock(order)}
          <p style="font-size:13px;color:#8b90a3">We'll contact you on WhatsApp to confirm before dispatch.</p>`
      ),
      text: `Order ${order.orderId} confirmed. Total ${money(order.total)} (Cash on Delivery).`,
    }),
    sendMail({
      to: CONFIG.adminEmail,
      subject: `🛒 New order ${order.orderId} — ${money(order.total)}`,
      html: emailShell(
        `New order ${order.orderId}`,
        `${table}<p style="font-size:13px;color:#8b90a3;margin:14px 0 4px">Customer:</p>${customerBlock(order)}
         ${order.notes ? `<p style="font-size:13px;color:#c9cde0">Note: ${esc(order.notes)}</p>` : ''}`
      ),
      text: `New order ${order.orderId} from ${order.customer.name} (${order.customer.phone}) — ${money(order.total)}`,
    }),
  ]);
}

async function sendDeliveredEmail(order) {
  return sendMail({
    to: order.customer.email,
    subject: `Delivered ✔ Order ${order.orderId} — ${CONFIG.storeName}`,
    html: emailShell(
      'Your order has been delivered 🎮',
      `<p style="font-size:14px;color:#c9cde0">Hi ${esc(order.customer.name.split(' ')[0])}, order
       <b style="color:#00d4ff">${esc(order.orderId)}</b> was marked as <b>Delivered</b>. Enjoy your gear!</p>
       ${itemsTable(order)}
       <p style="font-size:13px;color:#8b90a3">Something not right? Message us on WhatsApp and we'll sort it out.</p>`
    ),
    text: `Your order ${order.orderId} has been delivered. Thank you for shopping at ${CONFIG.storeName}!`,
  });
}

/* ════════════════════════════ LIVE VISITORS (in-memory) ════════════════════════════ */
const ACTIVE_WINDOW_MS = 70 * 1000;
const visitors = new Map(); // sid -> last ping timestamp
let visitsToday = { day: '', set: new Set() };
const dayKey = (d = new Date()) => new Intl.DateTimeFormat('en-CA', { timeZone: CONFIG.tz }).format(d);

function recordPing(sid) {
  const now = Date.now();
  if (visitors.size < 50000) visitors.set(sid, now);
  const today = dayKey();
  if (visitsToday.day !== today) visitsToday = { day: today, set: new Set() };
  if (visitsToday.set.size < 200000) visitsToday.set.add(sid);
}
const activeVisitorCount = () => {
  const cutoff = Date.now() - ACTIVE_WINDOW_MS;
  let n = 0;
  for (const t of visitors.values()) if (t >= cutoff) n++;
  return n;
};
setInterval(() => {
  const cutoff = Date.now() - ACTIVE_WINDOW_MS * 2;
  for (const [sid, t] of visitors) if (t < cutoff) visitors.delete(sid);
}, 60 * 1000).unref();

/* ════════════════════════════ APP & MIDDLEWARE ════════════════════════════ */
const app = express();
app.set('trust proxy', 1); // Render sits behind a proxy → correct client IPs for rate limiting
app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));

function originAllowed(origin) {
  if (!CONFIG.origins.length) return true; // dev mode: no list configured
  return CONFIG.origins.some((o) => {
    if (o === origin) return true;
    if (o.includes('*')) {
      const re = new RegExp('^' + o.split('*').map(escapeRegex).join('[a-z0-9-]+(?:\\.[a-z0-9-]+)*') + '$', 'i');
      return re.test(origin);
    }
    return false;
  });
}
if (!CONFIG.origins.length) console.warn('⚠ FRONTEND_ORIGINS not set — CORS is open to every origin.');
app.use(
  cors({
    origin: (origin, cb) => cb(null, !origin || originAllowed(origin)),
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400,
  })
);
app.use(express.json({ limit: '50kb' }));

const limiter = (windowMin, max, message, skip) =>
  rateLimit({
    windowMs: windowMin * 60 * 1000,
    max,
    skip,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: message },
  });
app.use('/api', limiter(15, 600, 'Too many requests, please slow down.', (req) => req.path === '/visit/ping'));
const orderLimiter = limiter(60, 15, 'Too many orders from this connection. Please try again later.');
const trackLimiter = limiter(15, 40, 'Too many tracking requests. Please try again shortly.');
const loginLimiter = limiter(15, 10, 'Too many login attempts. Try again in 15 minutes.');
const pingLimiter = limiter(1, 120, 'Too many pings.'); // generous: many visitors can share one IP (NAT)

/* ── Admin auth ── */
function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  try {
    const payload = jwt.verify(token, CONFIG.jwtSecret, { algorithms: ['HS256'] });
    if (payload.role !== 'admin') throw new Error('bad role');
    req.admin = payload;
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized. Please log in again.' });
  }
}

/* ════════════════════════════ PUBLIC ROUTES ════════════════════════════ */
app.get('/', (req, res) => res.json({ name: `${CONFIG.storeName} API`, status: 'ok' }));
app.get('/api/health', (req, res) =>
  res.json({ status: 'ok', db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected', uptime: Math.round(process.uptime()) })
);

app.get('/api/config', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300');
  res.json({ storeName: CONFIG.storeName, currency: CONFIG.currency, deliveryFee: CONFIG.deliveryFee, whatsapp: CONFIG.whatsapp });
});

// GET /api/products — storefront catalog
app.get('/api/products', asyncH(async (req, res) => {
  const products = await Product.find({ active: true }).sort({ featured: -1, createdAt: -1 }).lean();
  res.set('Cache-Control', 'public, max-age=30');
  res.json(products);
}));

// POST /api/visit/ping — heartbeat for the live-visitor counter
app.post('/api/visit/ping', pingLimiter, (req, res) => {
  const sid = clean(req.body && req.body.sid, 64);
  if (/^[A-Za-z0-9-]{8,64}$/.test(sid)) recordPing(sid);
  res.status(204).end();
});

// POST /api/orders — create order, email customer + admin
app.post('/api/orders', orderLimiter, asyncH(async (req, res) => {
  const b = req.body || {};
  if (b.website) throw httpError(400, 'Invalid request.'); // honeypot field for bots

  const c = b.customer || {};
  const customer = {
    name: clean(c.name, 80),
    phone: clean(c.phone, 20),
    email: clean(c.email, 120).toLowerCase(),
    address: clean(c.address, 300),
    city: clean(c.city, 60),
  };
  const errors = {};
  if (customer.name.length < 2) errors.name = 'Enter your full name.';
  const digits = customer.phone.replace(/\D/g, '');
  if (!/^[+\d][\d\s\-()]*$/.test(customer.phone) || digits.length < 10 || digits.length > 15)
    errors.phone = 'Enter a valid WhatsApp number (e.g. 0300 1234567).';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(customer.email)) errors.email = 'Enter a valid email address.';
  if (customer.address.length < 8) errors.address = 'Enter your complete delivery address.';
  if (customer.city.length < 2) errors.city = 'Enter your city.';

  if (!Array.isArray(b.items) || b.items.length === 0 || b.items.length > 30) errors.items = 'Your cart is empty.';
  if (Object.keys(errors).length) return res.status(400).json({ error: 'Please fix the highlighted fields.', fields: errors });

  // Merge duplicates, validate quantities
  const wanted = new Map();
  for (const it of b.items) {
    const id = String(it && it.productId);
    const qty = Math.floor(Number(it && it.qty));
    if (!isObjectId(id) || !(qty >= 1 && qty <= 50)) throw httpError(400, 'Invalid cart item.');
    wanted.set(id, Math.min(50, (wanted.get(id) || 0) + qty));
  }

  // Prices ALWAYS come from the database — never trust the client.
  const products = await Product.find({ _id: { $in: [...wanted.keys()] }, active: true }).lean();
  const byId = new Map(products.map((p) => [String(p._id), p]));
  const items = [];
  for (const [id, qty] of wanted) {
    const p = byId.get(id);
    if (!p) throw httpError(409, 'An item in your cart is no longer available. Please refresh the page.');
    if (!p.inStock) throw httpError(409, `"${p.title}" is currently out of stock.`);
    items.push({ product: p._id, title: p.title, image: p.image, price: p.price, qty });
  }
  const subtotal = items.reduce((s, i) => s + i.price * i.qty, 0);
  const total = subtotal + CONFIG.deliveryFee;

  let order;
  for (let attempt = 0; attempt < 5 && !order; attempt++) {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 6; i++) code += alphabet[crypto.randomInt(alphabet.length)];
    try {
      order = await Order.create({
        orderId: `SGZ-${code}`,
        customer: { ...customer, phoneKey: phoneKey(customer.phone) },
        items,
        subtotal,
        deliveryFee: CONFIG.deliveryFee,
        total,
        notes: clean(b.notes, 300),
        statusHistory: [{ status: 'Pending' }],
      });
    } catch (err) {
      if (err.code !== 11000) throw err; // retry only on orderId collision
    }
  }
  if (!order) throw httpError(500, 'Could not create order, please try again.');

  sendOrderEmails(order).catch((e) => console.error('Order email error:', e.message)); // don't block response

  res.status(201).json({ orderId: order.orderId, total: order.total, status: order.status, createdAt: order.createdAt });
}));

// GET /api/orders/track/:id — by Order ID (SGZ-XXXXXX) or phone number
const publicOrder = (o) => ({
  orderId: o.orderId,
  status: o.status,
  statusHistory: o.statusHistory,
  items: o.items.map((i) => ({ title: i.title, qty: i.qty, price: i.price })),
  total: o.total,
  city: o.customer.city,
  createdAt: o.createdAt,
});
app.get('/api/orders/track/:id', trackLimiter, asyncH(async (req, res) => {
  const q = clean(req.params.id, 40).toUpperCase();
  res.set('Cache-Control', 'no-store');
  if (ORDER_ID_RE.test(q)) {
    const order = await Order.findOne({ orderId: q }).lean();
    if (!order) throw httpError(404, 'No order found with that ID.');
    return res.json({ orders: [publicOrder(order)] });
  }
  const digits = q.replace(/\D/g, '');
  if (digits.length >= 10) {
    const orders = await Order.find({ 'customer.phoneKey': phoneKey(digits) }).sort({ createdAt: -1 }).limit(10).lean();
    if (!orders.length) throw httpError(404, 'No orders found for that phone number.');
    return res.json({ orders: orders.map(publicOrder) });
  }
  throw httpError(400, 'Enter an Order ID (e.g. SGZ-AB12CD) or the phone number used at checkout.');
}));

/* ════════════════════════════ ADMIN ROUTES ════════════════════════════ */
app.post('/api/admin/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const okUser = safeEqual(username ?? '', CONFIG.adminUser);
  const okPass = safeEqual(password ?? '', CONFIG.adminPass);
  if (!(okUser && okPass)) return res.status(401).json({ error: 'Invalid username or password.' });
  const token = jwt.sign({ role: 'admin', user: CONFIG.adminUser }, CONFIG.jwtSecret, { algorithm: 'HS256', expiresIn: '12h' });
  res.json({ token, expiresIn: 12 * 3600 });
});

app.get('/api/admin/verify', requireAdmin, (req, res) => res.json({ ok: true, user: req.admin.user }));

/* ── Products ── */
function parseProduct(b, partial = false) {
  const out = {};
  const errs = [];
  const num = (v) => (v === '' || v === null || v === undefined ? NaN : Number(v));

  if (!partial || b.title !== undefined) {
    out.title = clean(b.title, 120);
    if (!out.title) errs.push('Title is required.');
  }
  if (!partial || b.category !== undefined) {
    out.category = clean(b.category, 60);
    if (!out.category) errs.push('Category is required.');
  }
  if (!partial || b.price !== undefined) {
    out.price = num(b.price);
    if (!Number.isFinite(out.price) || out.price < 0) errs.push('Price must be a number ≥ 0.');
  }
  if (b.oldPrice !== undefined) {
    const old = b.oldPrice === '' || b.oldPrice === null ? 0 : num(b.oldPrice);
    if (!Number.isFinite(old) || old < 0) errs.push('Old price must be a number ≥ 0.');
    out.oldPrice = old;
  }
  if (b.image !== undefined) {
    out.image = String(b.image).trim().slice(0, 600);
    if (out.image && !/^(https?:\/\/|\/|[\w.-]+\/)/i.test(out.image)) errs.push('Image must be a URL or relative path.');
    if (/^\s*(javascript|data):/i.test(out.image)) errs.push('Invalid image URL.');
  }
  if (b.description !== undefined) out.description = clean(b.description, 600);
  for (const k of ['inStock', 'active', 'featured']) if (b[k] !== undefined) out[k] = b[k] === true || b[k] === 'true';

  if (Number.isFinite(out.price) && out.oldPrice && out.oldPrice < out.price) {
    errs.push('Old price must be higher than the new price (or leave it empty).');
  }
  if (errs.length) throw Object.assign(httpError(400, errs.join(' ')), { fields: errs });
  return out;
}

app.get('/api/admin/products', requireAdmin, asyncH(async (req, res) => {
  res.json(await Product.find().sort({ createdAt: -1 }).lean());
}));

// POST /api/admin/products — add a product (or edit when body.id / body._id is supplied)
app.post('/api/admin/products', requireAdmin, asyncH(async (req, res) => {
  const id = req.body && (req.body.id || req.body._id);
  if (id) {
    if (!isObjectId(String(id))) throw httpError(400, 'Invalid product id.');
    const updated = await Product.findByIdAndUpdate(id, { $set: parseProduct(req.body) }, { new: true, runValidators: true });
    if (!updated) throw httpError(404, 'Product not found.');
    return res.json(updated);
  }
  const created = await Product.create(parseProduct(req.body));
  res.status(201).json(created);
}));

app.put('/api/admin/products/:id', requireAdmin, asyncH(async (req, res) => {
  if (!isObjectId(req.params.id)) throw httpError(400, 'Invalid product id.');
  const updated = await Product.findByIdAndUpdate(req.params.id, { $set: parseProduct(req.body || {}, true) }, { new: true, runValidators: true });
  if (!updated) throw httpError(404, 'Product not found.');
  res.json(updated);
}));

app.delete('/api/admin/products/:id', requireAdmin, asyncH(async (req, res) => {
  if (!isObjectId(req.params.id)) throw httpError(400, 'Invalid product id.');
  const deleted = await Product.findByIdAndDelete(req.params.id);
  if (!deleted) throw httpError(404, 'Product not found.');
  res.json({ ok: true });
}));

/* ── Orders ── */
app.get('/api/admin/orders', requireAdmin, asyncH(async (req, res) => {
  const filter = {};
  const status = clean(req.query.status, 20);
  if (STATUSES.includes(status)) filter.status = status;
  const q = clean(req.query.q, 60);
  if (q) {
    const rx = new RegExp(escapeRegex(q), 'i');
    const digits = q.replace(/\D/g, '');
    filter.$or = [{ orderId: rx }, { 'customer.name': rx }, { 'customer.city': rx }, { 'customer.email': rx }];
    if (digits.length >= 4) filter.$or.push({ 'customer.phone': new RegExp(digits.split('').join('\\D*')) }); // digits only → safe
  }
  const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 100));
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const [orders, total] = await Promise.all([
    Order.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
    Order.countDocuments(filter),
  ]);
  res.json({ orders, total, page, pages: Math.max(1, Math.ceil(total / limit)) });
}));

// PUT /api/admin/orders/:id — update status (accepts Mongo _id or SGZ-XXXXXX)
app.put('/api/admin/orders/:id', requireAdmin, asyncH(async (req, res) => {
  const status = clean(req.body && req.body.status, 20);
  if (!STATUSES.includes(status)) throw httpError(400, `Status must be one of: ${STATUSES.join(', ')}`);
  const key = String(req.params.id).toUpperCase();
  const query = ORDER_ID_RE.test(key) ? { orderId: key } : isObjectId(req.params.id) ? { _id: req.params.id } : null;
  if (!query) throw httpError(400, 'Invalid order id.');

  const order = await Order.findOne(query);
  if (!order) throw httpError(404, 'Order not found.');

  if (order.status !== status) {
    order.status = status;
    order.statusHistory.push({ status });
  }
  let emailQueued = false;
  if (status === 'Delivered' && !order.deliveredEmailSent) {
    order.deliveredEmailSent = true; // set first so a double-click can't send twice
    emailQueued = true;
  }
  await order.save();
  if (emailQueued) {
    sendDeliveredEmail(order).then((ok) => {
      if (!ok && transporter) Order.updateOne({ _id: order._id }, { deliveredEmailSent: false }).catch(() => {});
    });
  }
  res.json(order);
}));

/* ── Analytics ── */
app.get('/api/admin/analytics', requireAdmin, asyncH(async (req, res) => {
  const since = new Date(Date.now() - 8 * 24 * 3600 * 1000);
  const notCancelled = { status: { $ne: 'Cancelled' } };

  const [totals, byStatus, daily, top, productCount] = await Promise.all([
    Order.aggregate([
      { $match: notCancelled },
      { $group: { _id: null, revenue: { $sum: '$total' }, orders: { $sum: 1 } } },
    ]),
    Order.aggregate([{ $group: { _id: '$status', count: { $sum: 1 }, revenue: { $sum: '$total' } } }]),
    Order.aggregate([
      { $match: { ...notCancelled, createdAt: { $gte: since } } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt', timezone: CONFIG.tz } },
          revenue: { $sum: '$total' },
          orders: { $sum: 1 },
        },
      },
    ]),
    Order.aggregate([
      { $match: notCancelled },
      { $unwind: '$items' },
      { $group: { _id: '$items.title', qty: { $sum: '$items.qty' }, revenue: { $sum: { $multiply: ['$items.price', '$items.qty'] } } } },
      { $sort: { qty: -1 } },
      { $limit: 5 },
    ]),
    Product.countDocuments(),
  ]);

  const statusMap = Object.fromEntries(STATUSES.map((s) => [s, { count: 0, revenue: 0 }]));
  byStatus.forEach((s) => { if (statusMap[s._id]) statusMap[s._id] = { count: s.count, revenue: s.revenue }; });

  const dailyMap = new Map(daily.map((d) => [d._id, d]));
  const last7 = [];
  for (let i = 6; i >= 0; i--) {
    const key = dayKey(new Date(Date.now() - i * 24 * 3600 * 1000));
    const d = dailyMap.get(key);
    last7.push({ date: key, revenue: d ? d.revenue : 0, orders: d ? d.orders : 0 });
  }
  const today = last7[last7.length - 1];

  res.set('Cache-Control', 'no-store');
  res.json({
    currency: CONFIG.currency,
    totalRevenue: totals[0] ? totals[0].revenue : 0,
    totalOrders: totals[0] ? totals[0].orders : 0,
    deliveredRevenue: statusMap.Delivered.revenue,
    pendingOrders: statusMap.Pending.count,
    byStatus: Object.fromEntries(Object.entries(statusMap).map(([k, v]) => [k, v.count])),
    todayRevenue: today.revenue,
    todayOrders: today.orders,
    last7Days: last7,
    topProducts: top.map((t) => ({ title: t._id, qty: t.qty, revenue: t.revenue })),
    productCount,
    activeVisitors: activeVisitorCount(),
    visitorsToday: visitsToday.day === dayKey() ? visitsToday.set.size : 0,
    generatedAt: new Date().toISOString(),
  });
}));

/* ════════════════════════════ ERRORS ════════════════════════════ */
app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint not found.' }));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON.' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large.' });
  if (err.name === 'ValidationError') return res.status(400).json({ error: Object.values(err.errors).map((e) => e.message).join(' ') });
  if (err.name === 'CastError') return res.status(400).json({ error: 'Invalid value.' });
  const status = err.status || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: err.expose ? err.message : 'Something went wrong on our side.', ...(err.fields ? { fields: err.fields } : {}) });
});

/* ════════════════════════════ SEED + BOOT ════════════════════════════ */
async function seedIfEmpty() {
  if (!CONFIG.seed || (await Product.estimatedDocumentCount()) > 0) return;
  await Product.insertMany([
    { title: 'GTA 5 Modding USB — 64GB Starter', category: 'GTA 5 Mods', price: 2999, oldPrice: 4500, featured: true,
      description: 'Plug & play USB loaded with script-mod menu, graphics pack and install guide.' },
    { title: 'GTA 5 Ultimate Mods Collection — 128GB', category: 'GTA 5 Mods', price: 4999, oldPrice: 7500, featured: true,
      description: 'Cars, maps, ReShade presets and 4K textures. Step-by-step setup included.' },
    { title: 'PC Games Drive — 500GB (20+ Games)', category: 'PC Game Drives', price: 7999, oldPrice: 10500,
      description: 'Ready-to-play pre-loaded external drive with the most popular PC titles.' },
    { title: 'PC Games Drive — 1TB (40+ Games)', category: 'PC Game Drives', price: 13999, oldPrice: 18000, featured: true,
      description: 'Massive library on a fast 1TB drive. Installer and guide included.' },
    { title: 'Premiere Pro Software Bundle', category: 'Software', price: 1499, oldPrice: 3000,
      description: 'Video-editing bundle with installer, presets and setup support.' },
    { title: 'IDM — Internet Download Manager', category: 'Software', price: 999, oldPrice: 1800,
      description: 'Boost download speeds up to 5×. Setup assistance included.' },
    { title: '16GB DDR4 3200MHz Gaming RAM', category: 'Hardware', price: 8499, oldPrice: 10000,
      description: 'High-speed desktop memory with heat spreader. Plug & play.' },
    { title: 'RGB Gaming Mouse — 7200 DPI', category: 'Hardware', price: 1899, oldPrice: 2800,
      description: 'Ergonomic 6-button mouse, adjustable DPI and RGB lighting.' },
    { title: 'RGB Mechanical Gaming Keyboard', category: 'Hardware', price: 5499, oldPrice: 7500,
      description: 'Blue-switch mechanical keyboard with per-key RGB and anti-ghosting.' },
  ]);
  console.log('✔ Seeded sample products');
}

async function start() {
  await mongoose.connect(CONFIG.mongoUri, { serverSelectionTimeoutMS: 15000 });
  console.log('✔ MongoDB connected');
  await Promise.all([Product.init(), Order.init()]);
  await seedIfEmpty();
  const server = app.listen(CONFIG.port, () => console.log(`✔ ${CONFIG.storeName} API listening on :${CONFIG.port}`));

  const shutdown = (sig) => {
    console.log(`${sig} received, shutting down…`);
    server.close(() => mongoose.connection.close(false).then(() => process.exit(0)));
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

process.on('unhandledRejection', (r) => console.error('Unhandled rejection:', r));
if (require.main === module) {
  start().catch((err) => { console.error('✖ Failed to start:', err.message); process.exit(1); });
}
module.exports = { app, start };
