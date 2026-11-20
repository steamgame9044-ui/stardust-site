import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { db, hashPassword, verifyPassword, initDatabase, seedSiteSettings, getHmacSecret } from './server/db.ts';
import { buildPhpBundleZip, getPhpBundleFiles } from './server/phpBundle.ts';

interface AuthUser {
  id: number;
  full_name: string;
  username: string | null;
  email: string;
  role: 'student' | 'admin';
  phone: string | null;
  preferred_lang: 'fa' | 'en';
}

interface AuthedRequest extends Request {
  authUser?: AuthUser | null;
  sessionId?: string | null;
  csrfToken?: string | null;
}

const PORT = 3000;
const SESSION_COOKIE = 'stardust_sid';
const CSRF_COOKIE = 'stardust_csrf';

initDatabase();
const CSRF_HMAC_SECRET = getHmacSecret();

const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '10mb' }));

// Serve uploaded WebP/JPG/PNG media cleanly
app.use('/uploads', express.static(path.resolve(process.cwd(), 'uploads')));

function createSignedCsrfToken(): string {
  const nonce = crypto.randomBytes(16).toString('hex');
  const sig = crypto.createHmac('sha256', CSRF_HMAC_SECRET).update(nonce).digest('hex');
  return `${nonce}.${sig}`;
}

function isValidSignedCsrfToken(token: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [nonce, sig] = parts;
  if (!nonce || !sig || !/^[a-f0-9]+$/i.test(nonce) || !/^[a-f0-9]+$/i.test(sig)) {
    return false;
  }
  const expected = crypto.createHmac('sha256', CSRF_HMAC_SECRET).update(nonce).digest('hex');
  const a = Buffer.from(sig, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = decodeURIComponent(part.slice(0, idx).trim());
    const val = decodeURIComponent(part.slice(idx + 1).trim());
    out[key] = val;
  }
  return out;
}

function cleanText(input: unknown, maxLen = 2000): string {
  if (typeof input !== 'string') return '';
  return input.replace(/[<>]/g, '').trim().slice(0, maxLen);
}

function extractYoutubeId(raw: string): string {
  const trimmed = raw.trim();
  if (/^[a-zA-Z0-9_-]{11}$/.test(trimmed)) {
    return trimmed;
  }
  const match = trimmed.match(/(?:v=|youtu\.be\/|embed\/|shorts\/)([a-zA-Z0-9_-]{11})/);
  return match ? match[1] : '';
}

function isHttpsRequest(req: Request): boolean {
  const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  return req.secure || proto === 'https';
}

function setCookie(req: Request, res: Response, name: string, value: string, httpOnly: boolean, maxAgeSec: number): void {
  const https = isHttpsRequest(req);
  const parts = [
    `${encodeURIComponent(name)}=${encodeURIComponent(value)}`,
    'Path=/',
    `Max-Age=${maxAgeSec}`,
    https ? 'SameSite=None' : 'SameSite=Lax',
  ];
  if (httpOnly) parts.push('HttpOnly');
  if (https) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

function clearCookie(req: Request, res: Response, name: string, httpOnly: boolean): void {
  setCookie(req, res, name, '', httpOnly, 0);
}

// Attach session user (via HttpOnly cookie OR Authorization: Bearer OR ?token=) & signed CSRF token
app.use((req: AuthedRequest, res: Response, next: NextFunction) => {
  const cookies = parseCookies(req.headers.cookie);
  const authHeader = String(req.headers.authorization || '');
  const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  const queryToken = typeof req.query.token === 'string' ? req.query.token.trim() : '';
  const sid = bearerToken || cookies[SESSION_COOKIE] || queryToken || null;

  let csrf = cookies[CSRF_COOKIE] && isValidSignedCsrfToken(cookies[CSRF_COOKIE]) ? cookies[CSRF_COOKIE] : null;
  let authUser: AuthUser | null = null;

  if (sid) {
    const row = db
      .prepare(
        `SELECT s.id as sid, s.csrf_token, s.expires_at, u.id, u.full_name, u.username, u.email, u.role, u.phone, u.preferred_lang
         FROM sessions s
         INNER JOIN users u ON u.id = s.user_id
         WHERE s.id = ? AND datetime(s.expires_at) > datetime('now')`
      )
      .get(sid) as
      | (AuthUser & { sid: string; csrf_token: string; expires_at: string })
      | undefined;

    if (row) {
      authUser = {
        id: row.id,
        full_name: row.full_name,
        username: row.username,
        email: row.email,
        role: row.role,
        phone: row.phone,
        preferred_lang: row.preferred_lang === 'en' ? 'en' : 'fa',
      };
      csrf = row.csrf_token;
    }
  }

  if (!csrf) {
    csrf = createSignedCsrfToken();
    setCookie(req, res, CSRF_COOKIE, csrf, false, 60 * 60 * 24 * 7);
  }

  req.authUser = authUser;
  req.sessionId = sid;
  req.csrfToken = csrf;
  next();
});

// CSRF protection: validates either session csrf_token OR stateless HMAC-signed CSRF token
// so iframe preview environments where 3P cookies are blocked never trigger spurious 403 errors.
function verifyCsrf(req: AuthedRequest, res: Response, next: NextFunction): void {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    next();
    return;
  }

  // Allow login/register even if client did not cache a CSRF header yet, or validate if provided
  const headerToken = String(req.headers['x-csrf-token'] || '');
  if (!headerToken) {
    if (req.path === '/auth/login' || req.path === '/auth/register') {
      next();
      return;
    }
    res.status(403).json({ error: 'Missing CSRF token.' });
    return;
  }

  // 1) Check stateless HMAC signature
  if (isValidSignedCsrfToken(headerToken)) {
    next();
    return;
  }

  // 2) Fallback: check exact match against active session token
  const expected = String(req.csrfToken || '');
  if (expected && headerToken.length === expected.length) {
    const valid = crypto.timingSafeEqual(Buffer.from(headerToken), Buffer.from(expected));
    if (valid) {
      next();
      return;
    }
  }

  res.status(403).json({ error: 'Invalid CSRF token.' });
}

app.use('/api', verifyCsrf);

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction): void {
  if (!req.authUser) {
    res.status(401).json({ error: 'Authentication required. Please sign in again.' });
    return;
  }
  next();
}

function requireAdmin(req: AuthedRequest, res: Response, next: NextFunction): void {
  if (!req.authUser) {
    res.status(401).json({ error: 'Admin session expired or missing. Please sign in again.' });
    return;
  }
  if (req.authUser.role !== 'admin') {
    res.status(403).json({ error: 'Administrator privileges required.' });
    return;
  }
  next();
}

// CSRF bootstrap
app.get('/api/csrf', (req: AuthedRequest, res: Response) => {
  res.json({ csrfToken: req.csrfToken });
});

// Public site bootstrap
app.get('/api/bootstrap', (req: AuthedRequest, res: Response) => {
  const courses = db.prepare('SELECT * FROM courses ORDER BY is_featured DESC, id DESC').all();
  const services = db.prepare('SELECT * FROM services ORDER BY id ASC').all();
  const videos = db.prepare('SELECT * FROM videos ORDER BY id DESC').all();
  const blogPosts = db.prepare('SELECT * FROM blog_posts ORDER BY published_at DESC, id DESC').all();
  const achievements = db.prepare('SELECT * FROM achievements ORDER BY id DESC').all();
  const testimonials = db
    .prepare("SELECT * FROM testimonials WHERE status = 'approved' ORDER BY id DESC")
    .all();
  const siteSettings = db.prepare('SELECT * FROM site_settings ORDER BY rowid ASC').all();

  res.json({
    csrfToken: req.csrfToken,
    user: req.authUser || null,
    courses,
    services,
    videos,
    blogPosts,
    achievements,
    testimonials,
    siteSettings,
  });
});

// Auth: Register
app.post('/api/auth/register', (req: AuthedRequest, res: Response) => {
  const fullName = cleanText(req.body.full_name, 120);
  const email = cleanText(req.body.email, 160).toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const phone = cleanText(req.body.phone, 30);

  if (fullName.length < 2) {
    res.status(400).json({ error: 'Full name is required.' });
    return;
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    res.status(400).json({ error: 'Please enter a valid email address.' });
    return;
  }
  if (password.length < 8) {
    res.status(400).json({ error: 'Password must be at least 8 characters.' });
    return;
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    res.status(409).json({ error: 'An account with this email already exists.' });
    return;
  }

  const passwordHash = hashPassword(password);
  const info = db
    .prepare(
      `INSERT INTO users (full_name, email, password_hash, role, phone, auth_provider)
       VALUES (?, ?, ?, 'student', ?, 'email')`
    )
    .run(fullName, email, passwordHash, phone || null);

  const userId = Number(info.lastInsertRowid);
  const sid = crypto.randomBytes(32).toString('hex');
  const csrf = createSignedCsrfToken();
  db.prepare(
    `INSERT INTO sessions (id, user_id, csrf_token, expires_at)
     VALUES (?, ?, ?, datetime('now', '+7 days'))`
  ).run(sid, userId, csrf);

  setCookie(req, res, SESSION_COOKIE, sid, true, 60 * 60 * 24 * 7);
  setCookie(req, res, CSRF_COOKIE, csrf, false, 60 * 60 * 24 * 7);

  res.status(201).json({
    csrfToken: csrf,
    sessionToken: sid,
    user: {
      id: userId,
      full_name: fullName,
      username: null,
      email,
      role: 'student',
      phone: phone || null,
      preferred_lang: 'fa',
    },
  });
});

// Auth: Login (email or admin username)
app.post('/api/auth/login', (req: AuthedRequest, res: Response) => {
  const identifier = cleanText(req.body.identifier, 160).toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';

  if (!identifier || !password) {
    res.status(400).json({ error: 'Email/username and password are required.' });
    return;
  }

  const user = db
    .prepare('SELECT * FROM users WHERE lower(email) = ? OR lower(username) = ? LIMIT 1')
    .get(identifier, identifier) as
    | (AuthUser & { password_hash: string })
    | undefined;

  if (!user || !verifyPassword(password, user.password_hash)) {
    res.status(401).json({ error: 'Invalid username/email or password.' });
    return;
  }

  const sid = crypto.randomBytes(32).toString('hex');
  const csrf = createSignedCsrfToken();
  db.prepare(
    `INSERT INTO sessions (id, user_id, csrf_token, expires_at)
     VALUES (?, ?, ?, datetime('now', '+7 days'))`
  ).run(sid, user.id, csrf);

  setCookie(req, res, SESSION_COOKIE, sid, true, 60 * 60 * 24 * 7);
  setCookie(req, res, CSRF_COOKIE, csrf, false, 60 * 60 * 24 * 7);

  res.json({
    csrfToken: csrf,
    sessionToken: sid,
    user: {
      id: user.id,
      full_name: user.full_name,
      username: user.username,
      email: user.email,
      role: user.role,
      phone: user.phone,
      preferred_lang: user.preferred_lang === 'en' ? 'en' : 'fa',
    },
  });
});

app.post('/api/auth/logout', (req: AuthedRequest, res: Response) => {
  if (req.sessionId) {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(req.sessionId);
  }
  clearCookie(req, res, SESSION_COOKIE, true);
  res.json({ ok: true });
});

// Student Dashboard & Profile
app.get('/api/student/dashboard', requireAuth, (req: AuthedRequest, res: Response) => {
  const uid = req.authUser!.id;
  const enrollments = db
    .prepare(
      `SELECT e.id, e.status, e.progress_percent, e.enrolled_at,
              c.id as course_id, c.title_fa, c.title_en, c.type, c.level, c.instructor, c.duration_label_fa, c.duration_label_en, c.image_webp
       FROM enrollments e
       INNER JOIN courses c ON c.id = e.course_id
       WHERE e.user_id = ?
       ORDER BY e.enrolled_at DESC`
    )
    .all(uid);

  const orders = db
    .prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC')
    .all(uid);

  const consultations = db
    .prepare('SELECT * FROM consultations WHERE user_id = ? ORDER BY created_at DESC')
    .all(uid);

  res.json({
    user: req.authUser,
    enrollments,
    orders,
    consultations,
  });
});

app.put('/api/student/profile', requireAuth, (req: AuthedRequest, res: Response) => {
  const uid = req.authUser!.id;
  const fullName = cleanText(req.body.full_name, 120);
  const phone = cleanText(req.body.phone, 30);
  const preferredLang = req.body.preferred_lang === 'en' ? 'en' : 'fa';

  if (fullName.length < 2) {
    res.status(400).json({ error: 'Name must be at least 2 characters.' });
    return;
  }

  db.prepare('UPDATE users SET full_name = ?, phone = ?, preferred_lang = ? WHERE id = ?').run(
    fullName,
    phone || null,
    preferredLang,
    uid
  );

  res.json({
    user: {
      ...req.authUser!,
      full_name: fullName,
      phone: phone || null,
      preferred_lang: preferredLang,
    },
  });
});

// Orders / Cart Checkout
app.post('/api/orders', (req: AuthedRequest, res: Response) => {
  const customerName = cleanText(req.body.customer_name, 120);
  const customerEmail = cleanText(req.body.customer_email, 160).toLowerCase();
  const customerTelegram = cleanText(req.body.customer_telegram, 80);
  const notes = cleanText(req.body.notes, 600);
  const items = Array.isArray(req.body.items) ? req.body.items : [];

  if (!customerName || !customerEmail || items.length === 0) {
    res.status(400).json({ error: 'Customer details and at least one item are required.' });
    return;
  }

  const verifiedItems: Array<{ course_id: number; title_fa: string; title_en: string; qty: number; price: number }> = [];
  let totalAmount = 0;

  for (const item of items) {
    const cid = Number(item?.course_id);
    const qty = Math.max(1, Math.min(20, Number(item?.qty || 1)));
    const course = db.prepare('SELECT id, title_fa, title_en, price FROM courses WHERE id = ?').get(cid) as
      | { id: number; title_fa: string; title_en: string; price: number }
      | undefined;
    if (course) {
      verifiedItems.push({
        course_id: course.id,
        title_fa: course.title_fa,
        title_en: course.title_en,
        qty,
        price: course.price,
      });
      totalAmount += course.price * qty;
    }
  }

  if (verifiedItems.length === 0) {
    res.status(400).json({ error: 'No valid courses or booklets found in order.' });
    return;
  }

  const orderCode = `SD-${Date.now().toString().slice(-6)}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;

  db.prepare(
    `INSERT INTO orders (order_code, user_id, customer_name, customer_email, customer_telegram, items_json, total_amount, notes, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_telegram')`
  ).run(
    orderCode,
    req.authUser?.id || null,
    customerName,
    customerEmail,
    customerTelegram,
    JSON.stringify(verifiedItems),
    totalAmount,
    notes
  );

  if (req.authUser) {
    const enrollStmt = db.prepare(
      'INSERT OR IGNORE INTO enrollments (user_id, course_id, status, progress_percent) VALUES (?, ?, ?, ?)'
    );
    for (const item of verifiedItems) {
      enrollStmt.run(req.authUser.id, item.course_id, 'active', 0);
    }
  }

  res.status(201).json({
    orderCode,
    totalAmount,
    items: verifiedItems,
  });
});

// Consultation Booking
app.post('/api/consultations', (req: AuthedRequest, res: Response) => {
  const fullName = cleanText(req.body.full_name, 120);
  const email = cleanText(req.body.email, 160).toLowerCase();
  const phoneOrTelegram = cleanText(req.body.phone_or_telegram, 120);
  const serviceType = cleanText(req.body.service_type, 80);
  const preferredDate = cleanText(req.body.preferred_date, 40);
  const goals = cleanText(req.body.goals, 1200);

  if (!fullName || !email || !phoneOrTelegram || !serviceType) {
    res.status(400).json({ error: 'Please complete all required booking fields.' });
    return;
  }

  const info = db
    .prepare(
      `INSERT INTO consultations (user_id, full_name, email, phone_or_telegram, service_type, preferred_date, goals, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'new')`
    )
    .run(req.authUser?.id || null, fullName, email, phoneOrTelegram, serviceType, preferredDate || 'Flexible', goals);

  res.status(201).json({ id: Number(info.lastInsertRowid), status: 'new' });
});

// Testimonials submission -> always enters 'pending'
app.post('/api/testimonials', (req: AuthedRequest, res: Response) => {
  const authorName = cleanText(req.body.author_name, 120);
  const authorRoleFa = cleanText(req.body.author_role_fa, 140) || 'زبان‌آموز StarDust';
  const authorRoleEn = cleanText(req.body.author_role_en, 140) || 'StarDust Learner';
  const contentFa = cleanText(req.body.content_fa, 1000);
  const contentEn = cleanText(req.body.content_en, 1000) || contentFa;
  const rating = Math.max(1, Math.min(5, Number(req.body.rating || 5)));

  if (authorName.length < 2 || contentFa.length < 10) {
    res.status(400).json({ error: 'Please enter your name and a meaningful review (min 10 chars).' });
    return;
  }

  const info = db
    .prepare(
      `INSERT INTO testimonials (user_id, author_name, author_role_fa, author_role_en, rating, content_fa, content_en, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`
    )
    .run(req.authUser?.id || null, authorName, authorRoleFa, authorRoleEn, rating, contentFa, contentEn);

  res.status(201).json({
    id: Number(info.lastInsertRowid),
    status: 'pending',
  });
});

// ---------------- ADMIN PANEL ROUTES ----------------

function listUploadedMedia(): Array<{ folder: string; filename: string; url: string }> {
  const folders = ['banners', 'courses', 'blog', 'achievements'];
  const items: Array<{ folder: string; filename: string; url: string }> = [];
  for (const folder of folders) {
    const dir = path.resolve(process.cwd(), 'uploads', folder);
    if (!fs.existsSync(dir)) continue;
    for (const file of fs.readdirSync(dir)) {
      if (/\.(webp|jpg|jpeg|png)$/i.test(file)) {
        items.push({ folder, filename: file, url: `/uploads/${folder}/${file}` });
      }
    }
  }
  const builtInDir = path.resolve(process.cwd(), 'src', 'assets', 'images');
  if (fs.existsSync(builtInDir)) {
    for (const file of fs.readdirSync(builtInDir)) {
      if (/\.(webp|jpg|jpeg|png)$/i.test(file)) {
        items.push({ folder: 'assets', filename: file, url: `/src/assets/images/${file}` });
      }
    }
  }
  return items;
}

app.get('/api/admin/overview', requireAdmin, (_req: AuthedRequest, res: Response) => {
  const courses = db.prepare('SELECT * FROM courses ORDER BY id DESC').all();
  const blogPosts = db.prepare('SELECT * FROM blog_posts ORDER BY published_at DESC, id DESC').all();
  const videos = db.prepare('SELECT * FROM videos ORDER BY id DESC').all();
  const services = db.prepare('SELECT * FROM services ORDER BY id ASC').all();
  const achievements = db.prepare('SELECT * FROM achievements ORDER BY id DESC').all();
  const testimonials = db
    .prepare("SELECT * FROM testimonials ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, id DESC")
    .all();
  const orders = db.prepare('SELECT * FROM orders ORDER BY created_at DESC LIMIT 50').all();
  const consultations = db.prepare('SELECT * FROM consultations ORDER BY created_at DESC LIMIT 50').all();
  const siteSettings = db.prepare('SELECT * FROM site_settings ORDER BY rowid ASC').all();
  const studentCount = (db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'student'").get() as { c: number }).c;

  res.json({
    stats: {
      courses: courses.length,
      blogPosts: blogPosts.length,
      videos: videos.length,
      pendingTestimonials: testimonials.filter((t: any) => t.status === 'pending').length,
      orders: orders.length,
      consultations: consultations.length,
      students: studentCount,
    },
    courses,
    blogPosts,
    videos,
    services,
    achievements,
    testimonials,
    orders,
    consultations,
    siteSettings,
    mediaLibrary: listUploadedMedia(),
    phpBundle: getPhpBundleFiles(),
  });
});

// Admin Homepage Copy & Brand Settings
app.put('/api/admin/settings', requireAdmin, (req: AuthedRequest, res: Response) => {
  const entries = Array.isArray(req.body.settings) ? req.body.settings : [];
  if (entries.length === 0) {
    res.status(400).json({ error: 'No settings payload provided.' });
    return;
  }

  const updateStmt = db.prepare(
    `UPDATE site_settings
     SET value_fa = ?, value_en = ?, updated_at = datetime('now')
     WHERE setting_key = ?`
  );

  const tx = db.transaction(() => {
    for (const item of entries) {
      const key = cleanText(item?.setting_key, 80);
      const valueFa = cleanText(item?.value_fa, 1500);
      const valueEn = cleanText(item?.value_en, 1500);
      if (key && (valueFa || valueEn)) {
        updateStmt.run(valueFa, valueEn, key);
      }
    }
  });
  tx();

  res.json({
    siteSettings: db.prepare('SELECT * FROM site_settings ORDER BY rowid ASC').all(),
  });
});

app.post('/api/admin/settings/reset', requireAdmin, (_req: AuthedRequest, res: Response) => {
  seedSiteSettings(true);
  res.json({
    siteSettings: db.prepare('SELECT * FROM site_settings ORDER BY rowid ASC').all(),
  });
});

// Admin Password Change
app.put('/api/admin/password', requireAdmin, (req: AuthedRequest, res: Response) => {
  const currentPassword = typeof req.body.current_password === 'string' ? req.body.current_password : '';
  const newPassword = typeof req.body.new_password === 'string' ? req.body.new_password : '';

  if (newPassword.length < 8) {
    res.status(400).json({ error: 'New password must be at least 8 characters.' });
    return;
  }

  const adminRow = db.prepare('SELECT id, password_hash FROM users WHERE id = ?').get(req.authUser!.id) as
    | { id: number; password_hash: string }
    | undefined;

  if (!adminRow || !verifyPassword(currentPassword, adminRow.password_hash)) {
    res.status(400).json({ error: 'Current password is incorrect.' });
    return;
  }

  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), adminRow.id);
  res.json({ ok: true });
});

// Admin WebP / PNG / JPG Upload
app.post('/api/admin/upload', requireAdmin, (req: AuthedRequest, res: Response) => {
  const folder = cleanText(req.body.folder, 32);
  const dataUrl = typeof req.body.dataUrl === 'string' ? req.body.dataUrl : '';
  const allowedFolders = ['courses', 'blog', 'achievements', 'banners'];

  if (!allowedFolders.includes(folder)) {
    res.status(400).json({ error: 'Invalid upload category.' });
    return;
  }

  const match = dataUrl.match(/^data:image\/(webp|png|jpeg|jpg);base64,([A-Za-z0-9+/=]+)$/);
  if (!match) {
    res.status(400).json({ error: 'Only WebP, PNG, or JPG base64 image payloads are accepted.' });
    return;
  }

  const rawExt = match[1] === 'jpeg' ? 'jpg' : match[1];
  const buffer = Buffer.from(match[2], 'base64');
  if (buffer.byteLength > 4 * 1024 * 1024) {
    res.status(400).json({ error: 'Image size exceeds 4MB limit.' });
    return;
  }

  if (rawExt === 'webp') {
    if (buffer.subarray(0, 4).toString('ascii') !== 'RIFF' || buffer.subarray(8, 12).toString('ascii') !== 'WEBP') {
      res.status(400).json({ error: 'Invalid WebP binary signature.' });
      return;
    }
  }

  const filename = `${folder}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}.${rawExt}`;
  const targetDir = path.resolve(process.cwd(), 'uploads', folder);
  fs.mkdirSync(targetDir, { recursive: true });
  fs.writeFileSync(path.join(targetDir, filename), buffer);

  res.status(201).json({ url: `/uploads/${folder}/${filename}`, mediaLibrary: listUploadedMedia() });
});

// Admin Courses CRUD
app.post('/api/admin/courses', requireAdmin, (req: AuthedRequest, res: Response) => {
  const titleFa = cleanText(req.body.title_fa, 220);
  const titleEn = cleanText(req.body.title_en, 220) || titleFa;
  const type = ['online', 'in_person', 'booklet'].includes(req.body.type) ? req.body.type : 'online';
  const level = cleanText(req.body.level, 40) || 'B1 - B2';
  const price = Math.max(0, Number(req.body.price || 0));
  const durationFa = cleanText(req.body.duration_label_fa, 120) || '۸ هفته';
  const durationEn = cleanText(req.body.duration_label_en, 120) || '8 Weeks';
  const instructor = cleanText(req.body.instructor, 120) || 'StarDust Faculty';
  const descFa = cleanText(req.body.description_fa, 1500);
  const descEn = cleanText(req.body.description_en, 1500) || descFa;
  const imageWebp = cleanText(req.body.image_webp, 255) || '/src/assets/images/course_ielts_mastery_1795157697644.jpg';
  const isFeatured = req.body.is_featured ? 1 : 0;

  if (!titleFa || !descFa) {
    res.status(400).json({ error: 'Course title and description are required.' });
    return;
  }

  const info = db
    .prepare(
      `INSERT INTO courses (title_fa, title_en, type, level, price, duration_label_fa, duration_label_en, instructor, description_fa, description_en, image_webp, is_featured)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(titleFa, titleEn, type, level, price, durationFa, durationEn, instructor, descFa, descEn, imageWebp, isFeatured);

  res.status(201).json(db.prepare('SELECT * FROM courses WHERE id = ?').get(Number(info.lastInsertRowid)));
});

app.put('/api/admin/courses/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  const titleFa = cleanText(req.body.title_fa, 220);
  const titleEn = cleanText(req.body.title_en, 220) || titleFa;
  const type = ['online', 'in_person', 'booklet'].includes(req.body.type) ? req.body.type : 'online';
  const level = cleanText(req.body.level, 40) || 'B1 - B2';
  const price = Math.max(0, Number(req.body.price || 0));
  const durationFa = cleanText(req.body.duration_label_fa, 120);
  const durationEn = cleanText(req.body.duration_label_en, 120);
  const instructor = cleanText(req.body.instructor, 120);
  const descFa = cleanText(req.body.description_fa, 1500);
  const descEn = cleanText(req.body.description_en, 1500) || descFa;
  const imageWebp = cleanText(req.body.image_webp, 255);
  const isFeatured = req.body.is_featured ? 1 : 0;

  db.prepare(
    `UPDATE courses SET title_fa=?, title_en=?, type=?, level=?, price=?, duration_label_fa=?, duration_label_en=?, instructor=?, description_fa=?, description_en=?, image_webp=?, is_featured=?
     WHERE id=?`
  ).run(titleFa, titleEn, type, level, price, durationFa, durationEn, instructor, descFa, descEn, imageWebp, isFeatured, id);

  res.json(db.prepare('SELECT * FROM courses WHERE id = ?').get(id));
});

app.delete('/api/admin/courses/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  db.prepare('DELETE FROM courses WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

// Admin Blog CRUD
app.post('/api/admin/blog', requireAdmin, (req: AuthedRequest, res: Response) => {
  const titleFa = cleanText(req.body.title_fa, 220);
  const titleEn = cleanText(req.body.title_en, 220) || titleFa;
  const catFa = cleanText(req.body.category_fa, 80) || 'آموزشی';
  const catEn = cleanText(req.body.category_en, 80) || 'Academic';
  const readTime = cleanText(req.body.read_time, 40) || '۵ دقیقه مطالعه';
  const excerptFa = cleanText(req.body.excerpt_fa, 500);
  const excerptEn = cleanText(req.body.excerpt_en, 500) || excerptFa;
  const contentFa = cleanText(req.body.content_fa, 8000);
  const contentEn = cleanText(req.body.content_en, 8000) || contentFa;
  const imageWebp = cleanText(req.body.image_webp, 255) || '/src/assets/images/blog_study_strategy_1795157698426.jpg';

  if (!titleFa || !contentFa) {
    res.status(400).json({ error: 'Article title and content are required.' });
    return;
  }

  const info = db
    .prepare(
      `INSERT INTO blog_posts (title_fa, title_en, category_fa, category_en, read_time, excerpt_fa, excerpt_en, content_fa, content_en, image_webp)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(titleFa, titleEn, catFa, catEn, readTime, excerptFa || contentFa.slice(0, 140), excerptEn || contentEn.slice(0, 140), contentFa, contentEn, imageWebp);

  res.status(201).json(db.prepare('SELECT * FROM blog_posts WHERE id = ?').get(Number(info.lastInsertRowid)));
});

app.put('/api/admin/blog/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  const titleFa = cleanText(req.body.title_fa, 220);
  const titleEn = cleanText(req.body.title_en, 220) || titleFa;
  const catFa = cleanText(req.body.category_fa, 80);
  const catEn = cleanText(req.body.category_en, 80);
  const readTime = cleanText(req.body.read_time, 40);
  const excerptFa = cleanText(req.body.excerpt_fa, 500);
  const excerptEn = cleanText(req.body.excerpt_en, 500) || excerptFa;
  const contentFa = cleanText(req.body.content_fa, 8000);
  const contentEn = cleanText(req.body.content_en, 8000) || contentFa;
  const imageWebp = cleanText(req.body.image_webp, 255);

  db.prepare(
    `UPDATE blog_posts SET title_fa=?, title_en=?, category_fa=?, category_en=?, read_time=?, excerpt_fa=?, excerpt_en=?, content_fa=?, content_en=?, image_webp=? WHERE id=?`
  ).run(titleFa, titleEn, catFa, catEn, readTime, excerptFa, excerptEn, contentFa, contentEn, imageWebp, id);

  res.json(db.prepare('SELECT * FROM blog_posts WHERE id = ?').get(id));
});

app.delete('/api/admin/blog/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  db.prepare('DELETE FROM blog_posts WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

// Admin Free YouTube Videos CRUD (Add, Edit, Delete)
app.post('/api/admin/videos', requireAdmin, (req: AuthedRequest, res: Response) => {
  const titleFa = cleanText(req.body.title_fa, 220);
  const titleEn = cleanText(req.body.title_en, 220) || titleFa;
  const category = cleanText(req.body.category, 80) || 'General';
  const youtubeId = extractYoutubeId(String(req.body.youtube_input || req.body.youtube_id || ''));
  const durationLabel = cleanText(req.body.duration_label, 20) || '10:00';
  const descFa = cleanText(req.body.description_fa, 800);
  const descEn = cleanText(req.body.description_en, 800) || descFa;

  if (!titleFa || !youtubeId) {
    res.status(400).json({ error: 'Valid YouTube video URL/ID and title are required.' });
    return;
  }

  const info = db
    .prepare(
      `INSERT INTO videos (title_fa, title_en, category, youtube_id, duration_label, description_fa, description_en)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(titleFa, titleEn, category, youtubeId, durationLabel, descFa, descEn);

  res.status(201).json(db.prepare('SELECT * FROM videos WHERE id = ?').get(Number(info.lastInsertRowid)));
});

app.put('/api/admin/videos/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  const titleFa = cleanText(req.body.title_fa, 220);
  const titleEn = cleanText(req.body.title_en, 220) || titleFa;
  const category = cleanText(req.body.category, 80) || 'General';
  const youtubeId = extractYoutubeId(String(req.body.youtube_input || req.body.youtube_id || ''));
  const durationLabel = cleanText(req.body.duration_label, 20) || '10:00';
  const descFa = cleanText(req.body.description_fa, 800);
  const descEn = cleanText(req.body.description_en, 800) || descFa;

  if (!titleFa || !youtubeId) {
    res.status(400).json({ error: 'Valid YouTube video URL/ID and title are required.' });
    return;
  }

  db.prepare(
    `UPDATE videos SET title_fa=?, title_en=?, category=?, youtube_id=?, duration_label=?, description_fa=?, description_en=? WHERE id=?`
  ).run(titleFa, titleEn, category, youtubeId, durationLabel, descFa, descEn, id);

  res.json(db.prepare('SELECT * FROM videos WHERE id = ?').get(id));
});

app.delete('/api/admin/videos/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  db.prepare('DELETE FROM videos WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

// Admin Services CRUD (Add, Edit, Delete)
app.post('/api/admin/services', requireAdmin, (req: AuthedRequest, res: Response) => {
  const titleFa = cleanText(req.body.title_fa, 200);
  const titleEn = cleanText(req.body.title_en, 200) || titleFa;
  const category = cleanText(req.body.category, 60) || 'special';
  const summaryFa = cleanText(req.body.summary_fa, 800);
  const summaryEn = cleanText(req.body.summary_en, 800) || summaryFa;
  const delivFa = cleanText(req.body.deliverable_fa, 180) || 'برنامه اختصاصی';
  const delivEn = cleanText(req.body.deliverable_en, 180) || delivFa;
  const priceFa = cleanText(req.body.price_label_fa, 100) || 'توافقی';
  const priceEn = cleanText(req.body.price_label_en, 100) || priceFa;

  if (!titleFa || !summaryFa) {
    res.status(400).json({ error: 'Service title and summary are required.' });
    return;
  }

  const info = db
    .prepare(
      `INSERT INTO services (title_fa, title_en, category, summary_fa, summary_en, deliverable_fa, deliverable_en, price_label_fa, price_label_en)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(titleFa, titleEn, category, summaryFa, summaryEn, delivFa, delivEn, priceFa, priceEn);

  res.status(201).json(db.prepare('SELECT * FROM services WHERE id = ?').get(Number(info.lastInsertRowid)));
});

app.put('/api/admin/services/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  const titleFa = cleanText(req.body.title_fa, 200);
  const titleEn = cleanText(req.body.title_en, 200) || titleFa;
  const category = cleanText(req.body.category, 60) || 'special';
  const summaryFa = cleanText(req.body.summary_fa, 800);
  const summaryEn = cleanText(req.body.summary_en, 800) || summaryFa;
  const delivFa = cleanText(req.body.deliverable_fa, 180);
  const delivEn = cleanText(req.body.deliverable_en, 180) || delivFa;
  const priceFa = cleanText(req.body.price_label_fa, 100);
  const priceEn = cleanText(req.body.price_label_en, 100) || priceFa;

  db.prepare(
    `UPDATE services SET title_fa=?, title_en=?, category=?, summary_fa=?, summary_en=?, deliverable_fa=?, deliverable_en=?, price_label_fa=?, price_label_en=? WHERE id=?`
  ).run(titleFa, titleEn, category, summaryFa, summaryEn, delivFa, delivEn, priceFa, priceEn, id);

  res.json(db.prepare('SELECT * FROM services WHERE id = ?').get(id));
});

app.delete('/api/admin/services/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  db.prepare('DELETE FROM services WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

// Admin Achievements CRUD (Add, Edit, Delete)
app.post('/api/admin/achievements', requireAdmin, (req: AuthedRequest, res: Response) => {
  const studentName = cleanText(req.body.student_name, 120);
  const examType = cleanText(req.body.exam_type, 80) || 'IELTS Academic';
  const scoreBefore = cleanText(req.body.score_before, 20) || '5.5';
  const scoreAfter = cleanText(req.body.score_after, 20) || '7.5';
  const timeframeFa = cleanText(req.body.timeframe_fa, 100) || '۱۰ هفته';
  const timeframeEn = cleanText(req.body.timeframe_en, 100) || '10 Weeks';
  const storyFa = cleanText(req.body.story_fa, 800);
  const storyEn = cleanText(req.body.story_en, 800) || storyFa;
  const imageWebp = cleanText(req.body.image_webp, 255) || '/src/assets/images/course_ielts_mastery_1795157697644.jpg';

  if (!studentName || !storyFa) {
    res.status(400).json({ error: 'Student name and achievement story are required.' });
    return;
  }

  const info = db
    .prepare(
      `INSERT INTO achievements (student_name, exam_type, score_before, score_after, timeframe_fa, timeframe_en, story_fa, story_en, image_webp)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(studentName, examType, scoreBefore, scoreAfter, timeframeFa, timeframeEn, storyFa, storyEn, imageWebp);

  res.status(201).json(db.prepare('SELECT * FROM achievements WHERE id = ?').get(Number(info.lastInsertRowid)));
});

app.put('/api/admin/achievements/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  const studentName = cleanText(req.body.student_name, 120);
  const examType = cleanText(req.body.exam_type, 80);
  const scoreBefore = cleanText(req.body.score_before, 20);
  const scoreAfter = cleanText(req.body.score_after, 20);
  const timeframeFa = cleanText(req.body.timeframe_fa, 100);
  const timeframeEn = cleanText(req.body.timeframe_en, 100);
  const storyFa = cleanText(req.body.story_fa, 800);
  const storyEn = cleanText(req.body.story_en, 800) || storyFa;
  const imageWebp = cleanText(req.body.image_webp, 255);

  db.prepare(
    `UPDATE achievements SET student_name=?, exam_type=?, score_before=?, score_after=?, timeframe_fa=?, timeframe_en=?, story_fa=?, story_en=?, image_webp=? WHERE id=?`
  ).run(studentName, examType, scoreBefore, scoreAfter, timeframeFa, timeframeEn, storyFa, storyEn, imageWebp, id);

  res.json(db.prepare('SELECT * FROM achievements WHERE id = ?').get(id));
});

app.delete('/api/admin/achievements/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  db.prepare('DELETE FROM achievements WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

// Admin Orders Status & Consultations Status
app.patch('/api/admin/orders/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  const status = ['pending_telegram', 'confirmed', 'cancelled'].includes(req.body.status)
    ? req.body.status
    : 'pending_telegram';
  db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, id);
  res.json(db.prepare('SELECT * FROM orders WHERE id = ?').get(id));
});

app.patch('/api/admin/consultations/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  const status = ['new', 'scheduled', 'completed'].includes(req.body.status) ? req.body.status : 'scheduled';
  db.prepare('UPDATE consultations SET status = ? WHERE id = ?').run(status, id);
  res.json(db.prepare('SELECT * FROM consultations WHERE id = ?').get(id));
});

// Admin Testimonial Moderation
app.patch('/api/admin/testimonials/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  const status = req.body.status === 'approved' ? 'approved' : 'rejected';
  db.prepare('UPDATE testimonials SET status = ? WHERE id = ?').run(status, id);
  res.json(db.prepare('SELECT * FROM testimonials WHERE id = ?').get(id));
});

app.delete('/api/admin/testimonials/:id', requireAdmin, (req: AuthedRequest, res: Response) => {
  db.prepare('DELETE FROM testimonials WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

// Admin Downloadable PHP 8+ & MySQL Shared Hosting ZIP
app.get('/api/admin/php-bundle.zip', requireAdmin, async (_req: AuthedRequest, res: Response) => {
  const zipBuffer = await buildPhpBundleZip();
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename="stardust-cpanel-php8-mysql.zip"');
  res.send(zipBuffer);
});

app.use('/api', (err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  console.error('API Error:', err);
  const message = err instanceof Error ? err.message : 'Internal server error.';
  if (!res.headersSent) {
    res.status(500).json({ error: message });
  }
});

async function startServer(): Promise<void> {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`StarDust server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
