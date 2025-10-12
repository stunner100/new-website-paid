import { Hono } from 'hono'
import bcrypt from 'bcryptjs'
import { neon } from '@neondatabase/serverless'
// Note: Avoid AWS SDK in Workers runtime to prevent DOMParser issues
import * as jose from 'jose'

// Cloudflare Pages Functions binding types
export type Bindings = {
  DATABASE_URL: string
  JWT_SECRET: string
  R2_ENDPOINT: string
  R2_ACCESS_KEY_ID: string
  R2_SECRET_ACCESS_KEY: string
  R2_BUCKET: string
  STREAM_PRESIGN?: string
  CLOUDFLARE_ACCOUNT_ID?: string
  // R2 bucket binding; typed as any locally to avoid workers-types dependency
  VIDEOS: any
}

function guessContentType(key: string): string | null {
  const k = key.toLowerCase();
  if (k.endsWith('.jpg') || k.endsWith('.jpeg')) return 'image/jpeg';
  if (k.endsWith('.png')) return 'image/png';
  if (k.endsWith('.webp')) return 'image/webp';
  if (k.endsWith('.gif')) return 'image/gif';
  if (k.endsWith('.mp4')) return 'video/mp4';
  if (k.endsWith('.webm')) return 'video/webm';
  if (k.endsWith('.mov')) return 'video/quicktime';
  if (k.endsWith('.mkv')) return 'video/x-matroska';
  if (k.endsWith('.avi')) return 'video/x-msvideo';
  if (k.endsWith('.mpeg') || k.endsWith('.mpg')) return 'video/mpeg';
  return null;
}

async function streamViaBinding(c: any, key: string) {
  const method = c.req.method
  const head = await c.env.VIDEOS.head(key)
  if (!head) return json(c, 404, { detail: 'Not found in R2', code: 'R2_NOT_FOUND' })
  const totalSize = head.size ?? undefined
  const ct = head.httpMetadata?.contentType || guessContentType(key) || 'application/octet-stream'
  const cacheHeaders = {
    'Cache-Control': 'public, max-age=0, s-maxage=86400',
  }

  const range = c.req.header('range') || c.req.header('Range') || ''
  const m = /^bytes=(\d+)-(\d+)?$/.exec(range)
  if (!m || !totalSize || method === 'HEAD') {
    const headers = new Headers()
    headers.set('Content-Type', ct)
    if (totalSize != null) headers.set('Content-Length', String(totalSize))
    headers.set('Accept-Ranges', 'bytes')
    Object.entries(cacheHeaders).forEach(([k, v]) => headers.set(k, v))
    if (method === 'HEAD') return new Response(null, { status: 200, headers })
    const obj = await c.env.VIDEOS.get(key)
    if (!obj) return json(c, 404, { detail: 'Not found in R2', code: 'R2_NOT_FOUND' })
    return new Response(obj.body, { status: 200, headers })
  }

  // Byte range requested
  const start = Number(m[1])
  const end = m[2] ? Number(m[2]) : (totalSize - 1)
  if (Number.isNaN(start) || Number.isNaN(end) || start > end || (totalSize && start >= totalSize)) {
    return json(c, 416, { detail: 'Invalid range', code: 'BAD_RANGE' })
  }
  const length = end - start + 1
  const obj = await c.env.VIDEOS.get(key, { range: { offset: start, length } })
  if (!obj) return json(c, 404, { detail: 'Not found in R2', code: 'R2_NOT_FOUND' })
  const headers = new Headers()
  headers.set('Content-Type', ct)
  headers.set('Content-Range', `bytes ${start}-${end}/${totalSize}`)
  headers.set('Content-Length', String(length))
  headers.set('Accept-Ranges', 'bytes')
  Object.entries(cacheHeaders).forEach(([k, v]) => headers.set(k, v))
  return new Response(obj.body, { status: 206, headers })
}

async function streamThumbnail(c: any, key: string) {
  const head = await c.env.VIDEOS.head(key)
  if (!head) return json(c, 404, { detail: 'Not found in R2', code: 'R2_NOT_FOUND' })
  const ct = head.httpMetadata?.contentType || guessContentType(key) || 'image/jpeg'
  const obj = await c.env.VIDEOS.get(key)
  if (!obj) return json(c, 404, { detail: 'Not found in R2', code: 'R2_NOT_FOUND' })
  const headers = new Headers()
  headers.set('Content-Type', ct)
  if (head.size != null) headers.set('Content-Length', String(head.size))
  headers.set('Cache-Control', 'public, max-age=31536000, immutable')
  headers.set('Accept-Ranges', 'none')
  return new Response(obj.body, { status: 200, headers })
}

const app = new Hono<{ Bindings: Bindings }>()

// Memoize schema setup per worker instance to avoid DDL on hot paths
let __schemaReady = false

// Utilities
function getClientIp(c: any): string {
  const h = (name: string) => c.req.header(name) || c.req.header(name.toLowerCase()) || ''
  const ip = h('cf-connecting-ip') || h('x-forwarded-for')?.split(',')[0].trim() || ''
  return ip
}

function corsOrigin(c: any): string {
  const origin = c.req.header('origin') || ''
  if (!origin) return '*'
  try {
    const u = new URL(origin)
    const host = u.host
    if (host === 'bluefilmx.com' || host === 'www.bluefilmx.com' || host.endsWith('.bluefilmx.pages.dev')) return origin
  } catch {}
  return 'https://bluefilmx.com'
}

const json = (c: any, status: number, body: any, headers: Record<string, string> = {}) =>
  c.json(body, status, {
    'content-type': 'application/json',
    'Access-Control-Allow-Origin': corsOrigin(c),
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Vary': 'Origin',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    ...headers,
  })

// Public-cache helper for GET JSON endpoints to improve TTFB from edge
function jsonCached(c: any, status: number, body: any, seconds: number, extra: Record<string,string> = {}) {
  return json(c, status, body, {
    'Cache-Control': `public, max-age=0, s-maxage=${Math.max(0, seconds)}`,
    // Use wildcard to maximize cache shareability; safe for GET JSON
    'Access-Control-Allow-Origin': '*',
    // Avoid fragmenting cache by origin
    'Vary': 'Accept-Encoding',
    ...extra,
  })
}

// Admin: list users
app.get('/api/admin/users', async (c) => {
  await ensureSchema(c)
  try { await requireAdmin(c) } catch (e: any) {
    const code = e?.message === 'Unauthorized' ? 401 : 403
    return json(c, code, { detail: e?.message || 'Forbidden' })
  }
  const db = sql(c)
  const rows = await db`select id, email, name, age_verified, is_admin, is_approved, created_at from users order by created_at desc`
  return json(c, 200, rows)
})

// Admin: approve user
app.post('/api/admin/users/:id/approve', async (c) => {
  await ensureSchema(c)
  try { await requireAdmin(c) } catch (e: any) {
    const code = e?.message === 'Unauthorized' ? 401 : 403
    return json(c, code, { detail: e?.message || 'Forbidden' })
  }
  const id = Number(c.req.param('id'))
  if (!id || Number.isNaN(id)) return json(c, 400, { detail: 'Invalid id' })
  const db = sql(c)
  await db`update users set is_approved=true where id=${id}`
  return json(c, 200, { ok: true })
})

// Admin: make user admin
app.post('/api/admin/users/:id/make-admin', async (c) => {
  await ensureSchema(c)
  try { await requireAdmin(c) } catch (e: any) {
    const code = e?.message === 'Unauthorized' ? 401 : 403
    return json(c, code, { detail: e?.message || 'Forbidden' })
  }
  const id = Number(c.req.param('id'))
  if (!id || Number.isNaN(id)) return json(c, 400, { detail: 'Invalid id' })
  const db = sql(c)
  await db`update users set is_admin=true where id=${id}`
  return json(c, 200, { ok: true })
})

app.use('/api/*', async (c, next) => {
  if (c.req.method === 'OPTIONS') return json(c, 200, {})
  await next()
})

// Receive direct PUT to our API and stream into R2 via binding (fallback path)
app.put('/api/uploads/put', async (c) => {
  try {
    await ensureSchema(c)
    await requireAuth(c) // token may come via query string
    const url = new URL(c.req.url)
    const key = url.searchParams.get('key') || ''
    if (!key) return json(c, 400, { detail: 'Missing key' })
    const ct = c.req.header('content-type') || 'application/octet-stream'
    const req = c.req.raw as Request
    if (!req.body) return json(c, 400, { detail: 'Missing body' })
    await c.env.VIDEOS.put(key, req.body, { httpMetadata: { contentType: ct } })
    return json(c, 200, { ok: true, storageKey: key })
  } catch (e: any) {
    const code = e?.message === 'Unauthorized' ? 401 : e?.message === 'Forbidden' ? 403 : 500
    return json(c, code, { detail: e?.message || 'Upload PUT failed' })
  }
})

const encoder = new TextEncoder()
const getKey = (secret: string) => crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])

async function signToken(secret: string, payload: any) {
  const key = await getKey(secret)
  return await new jose.SignJWT(payload).setProtectedHeader({ alg: 'HS256' }).setExpirationTime('7d').sign(key)
}

async function verifyToken(secret: string, token: string) {
  const key = await getKey(secret)
  const { payload } = await jose.jwtVerify(token, key)
  return payload
}

// SigV4 helpers for R2 presign (Workers Web Crypto)
const encoder2 = new TextEncoder()
async function hmac(key: CryptoKey | ArrayBuffer, data: string | ArrayBuffer): Promise<ArrayBuffer> {
  const k = key instanceof CryptoKey ? key : await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const bytes = typeof data === 'string' ? encoder2.encode(data) : data
  return crypto.subtle.sign('HMAC', k, bytes)
}
async function getSigningKey(secret: string, date: string, region: string, service: string): Promise<ArrayBuffer> {
  const kDate = await hmac(encoder2.encode('AWS4' + secret), date)
  const kRegion = await hmac(kDate, region)
  const kService = await hmac(kRegion, service)
  return hmac(kService, 'aws4_request')
}
function toHex(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('')
}
async function sha256Hex(data: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', encoder2.encode(data))
  return toHex(hash)
}
function canonicalUri(bucket: string, key: string): string {
  // Encode each path segment but preserve '/'
  return `/${bucket}/` + key.split('/').map(encodeURIComponent).join('/')
}
function buildQuery(params: Record<string, string>): string {
  return Object.keys(params).sort().map(k => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`).join('&')
}
async function presignR2Url(c: any, method: 'PUT'|'GET', key: string, expiresSeconds: number): Promise<string> {
  let endpointStr = (c.env.R2_ENDPOINT || '').toString().trim()
  if (!endpointStr || !/^https?:\/\//i.test(endpointStr)) {
    const acct = (c.env.CLOUDFLARE_ACCOUNT_ID || '').toString().trim()
    if (acct && /^[a-f0-9]{32}$/i.test(acct)) {
      endpointStr = `https://${acct}.r2.cloudflarestorage.com`
    }
  }
  if (!endpointStr || !/^https?:\/\//i.test(endpointStr)) throw new Error('R2_ENDPOINT invalid')
  let endpoint: URL
  try { endpoint = new URL(endpointStr) } catch { throw new Error('R2_ENDPOINT invalid') }
  const host = endpoint.hostname
  const bucket = (c.env.R2_BUCKET || '').toString().trim()
  if (!bucket) throw new Error('R2_BUCKET missing')
  const accessKeyId = (c.env.R2_ACCESS_KEY_ID || '').toString().trim()
  if (!accessKeyId) throw new Error('R2_ACCESS_KEY_ID missing')
  const secretAccessKey = (c.env.R2_SECRET_ACCESS_KEY || '').toString().trim()
  if (!secretAccessKey) throw new Error('R2_SECRET_ACCESS_KEY missing')
  const now = new Date()
  const y = now.getUTCFullYear()
  const m = String(now.getUTCMonth()+1).padStart(2,'0')
  const d = String(now.getUTCDate()).padStart(2,'0')
  const hh = String(now.getUTCHours()).padStart(2,'0')
  const mm = String(now.getUTCMinutes()).padStart(2,'0')
  const ss = String(now.getUTCSeconds()).padStart(2,'0')
  const shortDate = `${y}${m}${d}`
  const amzDate = `${shortDate}T${hh}${mm}${ss}Z`
  const region = 'auto'
  const service = 's3'
  const credential = `${accessKeyId}/${shortDate}/${region}/${service}/aws4_request`
  const signedHeaders = 'host'
  const queryParams: Record<string,string> = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': credential,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresSeconds),
    'X-Amz-SignedHeaders': signedHeaders,
  }
  const canonicalQuery = buildQuery(queryParams)
  const canonicalHeaders = `host:${host}\n`
  const canonicalRequest = [
    method,
    canonicalUri(bucket, key),
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    'UNSIGNED-PAYLOAD',
  ].join('\n')
  const hashedCanonical = await sha256Hex(canonicalRequest)
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    `${shortDate}/${region}/${service}/aws4_request`,
    hashedCanonical,
  ].join('\n')
  const signingKey = await getSigningKey(secretAccessKey, shortDate, region, service)
  const signature = toHex(await hmac(signingKey, stringToSign))
  const url = `${endpoint.origin}${canonicalUri(bucket, key)}?${canonicalQuery}&X-Amz-Signature=${signature}`
  return url
}

function sql(c: any) {
  return neon(c.env.DATABASE_URL)
}

async function ensureSchema(c: any) {
  if (__schemaReady) return
  const db = sql(c)
  await db`create table if not exists users (
    id bigserial primary key,
    email text unique not null,
    name text not null,
    password_hash text not null,
    age_verified boolean default false,
    is_admin boolean default false,
    is_approved boolean default false,
    created_at timestamptz default now()
  )`
  // Ensure case-insensitive uniqueness on emails
  await db`create unique index if not exists users_email_lower_idx on users (lower(email))`
  await db`create table if not exists videos (
    id bigserial primary key,
    title text not null,
    description text not null,
    category text not null,
    tags text[] default '{}',
    status text not null default 'pending',
    views bigint not null default 0,
    uploader_id bigint references users(id) on delete set null,
    storage_key text not null,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
  )`
  // Add optional thumbnail field for custom thumbnails
  await db`alter table videos add column if not exists thumbnail_key text`
  // Helpful indexes for hot queries
  try { await db`create index if not exists videos_status_created_at_idx on videos (status, created_at desc)` } catch {}
  try { await db`create index if not exists videos_category_status_created_at_idx on videos (category, status, created_at desc)` } catch {}
  // Track login attempts per IP+email for rate limiting
  await db`create table if not exists login_attempts (
    email_lower text not null,
    ip text not null,
    attempts int not null default 0,
    last_attempt timestamptz default now(),
    locked_until timestamptz,
    primary key (email_lower, ip)
  )`
  __schemaReady = true
}

async function requireAuth(c: any) {
  const auth = c.req.header('authorization') || c.req.header('Authorization') || ''
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : (new URL(c.req.url).searchParams.get('token') || undefined)
  if (!token) throw new Error('Unauthorized')
  const payload: any = await verifyToken(c.env.JWT_SECRET, token)
  const userId = Number(payload.sub)
  if (!userId) throw new Error('Unauthorized')
  const db = sql(c)
  const rows = await db`select id, email, name, age_verified, is_admin, is_approved from users where id=${userId}`
  const user = (rows as any)[0]
  if (!user) throw new Error('Unauthorized')
  return { userId, is_admin: !!user.is_admin, user }
}

async function requireAdmin(c: any) {
  const u = await requireAuth(c)
  if (!u.is_admin) throw new Error('Forbidden')
  return u
}

function sanitizeFilename(name: string) {
  return name.replace(/[^a-zA-Z0-9._-]/g, '_')
}

// Health
app.get('/api/health', async (c) => {
  try {
    const db = sql(c)
    const rows = await db`select 1 as db`
    return json(c, 200, { ok: true, db: (rows as any)[0]?.db === 1 })
  } catch (e: any) {
    console.error('health db error:', e?.message || e)
    return json(c, 200, { ok: true, db: false, error: e?.message || String(e) })
  }
})

// Auth
app.post('/api/auth/register', async (c) => {
  await ensureSchema(c)
  const body = await c.req.json().catch(() => ({}))
  const { email, name, password, age_verified } = body || {}
  const emailNorm = (email || '').toString().trim().toLowerCase()
  if (!emailNorm || !name || !password) return json(c, 400, { detail: 'Missing fields', code: 'MISSING_FIELDS' })
  if (password.length < 8) return json(c, 400, { detail: 'Password must be at least 8 characters', code: 'WEAK_PASSWORD' })
  const db = sql(c)
  try {
    const password_hash = await bcrypt.hash(password, 10)
    const rows = await db`insert into users (email, name, password_hash, age_verified, is_admin, is_approved)
       values (${emailNorm}, ${name}, ${password_hash}, ${!!age_verified}, ${false}, ${false})
       returning id, email, name, age_verified, is_admin, is_approved`
    const user = (rows as any)[0]
    const token = await signToken(c.env.JWT_SECRET, { sub: user.id })
    return json(c, 200, { access_token: token, token_type: 'bearer', user })
  } catch (e: any) {
    if (e.code === '23505') return json(c, 400, { detail: 'Email already registered', code: 'EMAIL_EXISTS' })
    return json(c, 500, { detail: 'Registration failed' })
  }
})

app.post('/api/auth/login', async (c) => {
  try {
    await ensureSchema(c)
    const body = await c.req.json().catch(() => ({}))
    const { password } = body || {}
    const emailNorm = (body?.email || '').toString().trim().toLowerCase()
    if (!emailNorm || !password) return json(c, 400, { detail: 'Missing fields', code: 'MISSING_FIELDS' })
    // Rate limiting: block on too many attempts per IP+email
    const ip = getClientIp(c)
    const db = sql(c)
    const rowsRL = await db(
      'select attempts, last_attempt, locked_until from login_attempts where email_lower=$1 and ip=$2',
      [emailNorm, ip]
    )
    const rl = (rowsRL as any)[0]
    const now = new Date()
    if (rl?.locked_until && new Date(rl.locked_until) > now) {
      const waitMin = Math.ceil((new Date(rl.locked_until).getTime() - now.getTime()) / 60000)
      return json(c, 429, { detail: `Too many attempts. Try again in ${waitMin} minute(s).`, code: 'TOO_MANY_ATTEMPTS' })
    }
    const rows = await db`select id, email, name, password_hash, age_verified, is_admin, is_approved from users where lower(email) = ${emailNorm}`
    const u = (rows as any)[0]
    if (!u || !u.password_hash) {
      // invalid credentials path
      await db(
        `insert into login_attempts (email_lower, ip, attempts, last_attempt, locked_until)
         values ($1,$2,1,now(),null)
         on conflict (email_lower, ip)
         do update set 
           attempts = case when login_attempts.last_attempt > now() - interval '15 minutes' then login_attempts.attempts + 1 else 1 end,
           last_attempt = now(),
           locked_until = case when (case when login_attempts.last_attempt > now() - interval '15 minutes' then login_attempts.attempts + 1 else 1 end) >= 5 then now() + interval '15 minutes' else null end`,
        [emailNorm, ip]
      )
      return json(c, 400, { detail: 'Invalid email or password', code: 'INVALID_CREDENTIALS' })
    }
    const ok = await bcrypt.compare(password, u.password_hash)
    if (!ok) {
      await db(
        `insert into login_attempts (email_lower, ip, attempts, last_attempt, locked_until)
         values ($1,$2,1,now(),null)
         on conflict (email_lower, ip)
         do update set 
           attempts = case when login_attempts.last_attempt > now() - interval '15 minutes' then login_attempts.attempts + 1 else 1 end,
           last_attempt = now(),
           locked_until = case when (case when login_attempts.last_attempt > now() - interval '15 minutes' then login_attempts.attempts + 1 else 1 end) >= 5 then now() + interval '15 minutes' else null end`,
        [emailNorm, ip]
      )
      return json(c, 400, { detail: 'Invalid email or password', code: 'INVALID_CREDENTIALS' })
    }
    const { password_hash, ...user } = u
    const token = await signToken(c.env.JWT_SECRET, { sub: user.id })
    // reset attempts on success
    try { await db`delete from login_attempts where email_lower=${emailNorm} and ip=${ip}` } catch {}
    return json(c, 200, { access_token: token, token_type: 'bearer', user })
  } catch (e: any) {
    console.error('login error:', e?.message || e)
    return json(c, 500, { detail: 'Login failed', code: 'LOGIN_ERROR', error: e?.message || String(e) })
  }
})

app.get('/api/auth/profile', async (c) => {
  try {
    const auth = c.req.header('authorization') || ''
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : undefined
    if (!token) return json(c, 401, { detail: 'Invalid token' })
    const payload: any = await verifyToken(c.env.JWT_SECRET, token)
    const db = sql(c)
    const rows = await db`select id, email, name, age_verified, is_admin, is_approved from users where id=${payload.sub}`
    const user = (rows as any)[0]
    if (!user) return json(c, 401, { detail: 'User not found' })
    return json(c, 200, user)
  } catch {
    return json(c, 401, { detail: 'Invalid token' })
  }
})

// Presign for direct-to-R2
app.post('/api/uploads/presign', async (c) => {
  try {
    await ensureSchema(c)
    const { userId } = await requireAuth(c)
    const body = await c.req.json().catch(() => ({}))
    const rawName = (body.filename || 'upload.mp4').toString()
    const safeName = sanitizeFilename(rawName)
    const storageKey = `${userId}/${crypto.randomUUID()}_${safeName}`

    let uploadUrl: string
    const preferBinding = String(body?.preferBinding || '').toLowerCase() === 'true'
    if (preferBinding) {
      const token = await signToken(c.env.JWT_SECRET, { sub: userId })
      const origin = new URL(c.req.url).origin
      uploadUrl = `${origin}/api/uploads/put?token=${encodeURIComponent(token)}&key=${encodeURIComponent(storageKey)}`
    } else {
      try {
        uploadUrl = await presignR2Url(c, 'PUT', storageKey, 600)
      } catch (e: any) {
        console.error('presign failed, using binding PUT:', e?.message || e)
        const token = await signToken(c.env.JWT_SECRET, { sub: userId })
        const origin = new URL(c.req.url).origin
        uploadUrl = `${origin}/api/uploads/put?token=${encodeURIComponent(token)}&key=${encodeURIComponent(storageKey)}`
      }
    }
    return json(c, 200, { uploadUrl, storageKey })
  } catch (e: any) {
    const code = e?.message === 'Unauthorized' ? 401 : e?.message === 'Forbidden' ? 403 : 500
    return json(c, code, { detail: e?.message || 'Failed to presign' })
  }
})

// Upload via server (fallback, <=10MB recommended)
app.post('/api/videos/upload', async (c) => {
  try {
    await ensureSchema(c)
    const { userId } = await requireAdmin(c)
    const form = await c.req.formData()
    const file = form.get('file') as File | null
    const title = String(form.get('title') || '')
    const description = String(form.get('description') || '')
    const category = String(form.get('category') || '')
    const tagsStr = String(form.get('tags') || '')
    if (!file || !title || !description || !category) return json(c, 400, { detail: 'Missing fields' })

    const safeName = sanitizeFilename(file.name || 'upload.mp4')
    const storageKey = `${userId}/${crypto.randomUUID()}_${safeName}`
    // Put into R2
    await c.env.VIDEOS.put(storageKey, file.stream(), { httpMetadata: { contentType: file.type || 'application/octet-stream' } })

    const tags = tagsStr
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean)
    const tagsArray = `{${tags.map((t) => '"' + t.replace(/"/g, '\\"') + '"').join(',')}}`

    const db = sql(c)
    const rows = await db`insert into videos (title, description, category, tags, status, uploader_id, storage_key)
       values (${title}, ${description}, ${category}, ${tagsArray}::text[], ${'pending'}, ${userId}, ${storageKey})
       returning id, title, description, category, tags, status, views`
    return json(c, 200, (rows as any)[0])
  } catch (e: any) {
    const code = e?.message === 'Unauthorized' ? 401 : e?.message === 'Forbidden' ? 403 : 500
    return json(c, code, { detail: e?.message || 'Upload error' })
  }
})

// Create record after direct upload
app.post('/api/videos', async (c) => {
  try {
    await ensureSchema(c)
    const { userId } = await requireAdmin(c)
    const body = await c.req.json().catch(() => ({}))
    const { title, description, category, tags = [], storageKey, thumbnailKey } = body
    if (!title || !description || !category || !storageKey) return json(c, 400, { detail: 'Missing fields' })

    const tagsArray = Array.isArray(tags)
      ? `{${tags.map((t: string) => '"' + String(t).replace(/"/g, '\\"') + '"').join(',')}}`
      : `{${String(tags)
          .split(',')
          .map((t: string) => '"' + t.trim().replace(/"/g, '\\"') + '"')
          .filter(Boolean)
          .join(',')}}`

    const db = sql(c)
    const rows = await db(
      `insert into videos (title, description, category, tags, status, uploader_id, storage_key, thumbnail_key)
       values ($1,$2,$3,$4::text[],$5,$6,$7,$8)
       returning id, title, description, category, tags, status, views, thumbnail_key`,
      [title, description, category, tagsArray, 'pending', userId, storageKey, thumbnailKey || null]
    )
    return json(c, 200, (rows as any)[0])
  } catch (e: any) {
    const code = e?.message === 'Unauthorized' ? 401 : e?.message === 'Forbidden' ? 403 : 500
    return json(c, code, { detail: e?.message || 'Failed to create record' })
  }
})

// List videos
app.get('/api/videos', async (c) => {
  await ensureSchema(c)
  let isAdmin = false
  try { const auth = await requireAuth(c); isAdmin = !!auth.is_admin } catch {}
  const url = new URL(c.req.url)
  const status = url.searchParams.get('status') || undefined
  const category = url.searchParams.get('category') || undefined
  const limitQ = Number(url.searchParams.get('limit') || '0')
  const offsetQ = Number(url.searchParams.get('offset') || '0')
  const limit = Number.isFinite(limitQ) && limitQ > 0 ? Math.min(limitQ, 100) : 0
  const offset = Number.isFinite(offsetQ) && offsetQ >= 0 ? offsetQ : 0
  const db = sql(c)

  // Build where clause
  const whereParts: string[] = []
  const params: any[] = []
  let idx = 1
  if (!isAdmin) {
    whereParts.push(`status='approved'`)
  } else if (status && status !== 'all') {
    whereParts.push(`status=$${idx++}`); params.push(status)
  }
  if (category) { whereParts.push(`category=$${idx++}`); params.push(category) }
  const where = whereParts.length ? `where ${whereParts.join(' and ')}` : ''

  // total count
  const totalRows = await db(`select count(*) as c from videos ${where}`, params)
  const total = Number((totalRows as any)[0]?.c || 0)

  // query rows
  let sqlText = `select id, title, description, category, tags, status, views, thumbnail_key from videos ${where} order by created_at desc`
  if (limit) sqlText += ` limit ${limit} offset ${offset}`
  const rows: any[] = await db(sqlText, params)
  return jsonCached(c, 200, rows, 120, { 'X-Total-Count': String(total) })
})

// Fetch single video metadata
app.get('/api/videos/:id', async (c) => {
  await ensureSchema(c)
  let isAdmin = false
  try { const a = await requireAuth(c); isAdmin = !!a.is_admin } catch {}
  const id = Number(c.req.param('id'))
  if (!id || Number.isNaN(id)) return json(c, 400, { detail: 'Invalid id' })
  const db = sql(c)
  let rows: any[] = []
  if (isAdmin) {
    rows = await db`select id, title, description, category, tags, status, views, thumbnail_key from videos where id=${id}`
  } else {
    rows = await db`select id, title, description, category, tags, status, views, thumbnail_key from videos where id=${id} and status='approved'`
  }
  const v = (rows as any)[0]
  if (!v) return json(c, 404, { detail: 'Not found' })
  return json(c, 200, v)
})

// Record a view (anonymous allowed). Does not validate uniqueness; keep simple.
app.post('/api/videos/:id/view', async (c) => {
  try {
    await ensureSchema(c)
    const id = Number(c.req.param('id'))
    if (!id || Number.isNaN(id)) return json(c, 400, { detail: 'Invalid id' })
    const db = sql(c)
    const rows = await db`update videos set views = views + 1, updated_at = now() where id=${id} and status='approved' returning id, views`
    const v = (rows as any)[0]
    if (!v) return json(c, 404, { detail: 'Not found' })
    return json(c, 200, { ok: true, id: v.id, views: v.views })
  } catch (e: any) {
    return json(c, 500, { detail: 'Failed to record view', error: e?.message || String(e) })
  }
})

// Stream custom thumbnail for a video (if present)
app.get('/api/videos/:id/thumbnail', async (c) => {
  try {
    await ensureSchema(c)
    const id = Number(c.req.param('id'))
    if (!id || Number.isNaN(id)) return json(c, 400, { detail: 'Invalid id' })
    const db = sql(c)
    const rows = await db`select thumbnail_key from videos where id=${id}`
    const key = (rows as any)[0]?.thumbnail_key as string | undefined
    if (!key) return json(c, 404, { detail: 'No thumbnail' })
    // Long-cache thumbnails (immutable by key)
    return await streamThumbnail(c, key)
  } catch (e: any) {
    return json(c, 500, { detail: 'Thumbnail error', error: e?.message || String(e) })
  }
})

// Admin: set or replace thumbnail for a video
app.put('/api/videos/:id/thumbnail', async (c) => {
  try {
    await ensureSchema(c)
    await requireAdmin(c)
    const id = Number(c.req.param('id'))
    if (!id || Number.isNaN(id)) return json(c, 400, { detail: 'Invalid id' })
    const body = await c.req.json().catch(() => ({}))
    const thumbnailKey = (body?.thumbnailKey || '').toString().trim()
    const db = sql(c)
    const rows = await db`select thumbnail_key from videos where id=${id}`
    const oldKey = (rows as any)[0]?.thumbnail_key as string | undefined
    if (!thumbnailKey) {
      if (oldKey) await c.env.VIDEOS.delete(oldKey)
      await db`update videos set thumbnail_key=null, updated_at=now() where id=${id}`
      return json(c, 200, { ok: true, thumbnail_key: null })
    }
    await db`update videos set thumbnail_key=${thumbnailKey}, updated_at=now() where id=${id}`
    if (oldKey && oldKey !== thumbnailKey) {
      await c.env.VIDEOS.delete(oldKey)
    }
    return json(c, 200, { ok: true, thumbnail_key: thumbnailKey })
  } catch (e: any) {
    const code = e?.message === 'Unauthorized' ? 401 : e?.message === 'Forbidden' ? 403 : 500
    return json(c, code, { detail: e?.message || 'Failed to set thumbnail' })
  }
})

// Approve / Reject
app.post('/api/videos/:id/:action', async (c) => {
  const id = Number(c.req.param('id'))
  const action = c.req.param('action')
  if (!['approve', 'reject'].includes(action)) return json(c, 404, { detail: 'Not found' })
  await ensureSchema(c)
  try {
    await requireAdmin(c)
  } catch (e: any) {
    const code = e?.message === 'Unauthorized' ? 401 : 403
    return json(c, code, { detail: e?.message })
  }
  const newStatus = action === 'approve' ? 'approved' : 'rejected'
  const db = sql(c)
  await db`update videos set status=${newStatus}, updated_at=now() where id=${id}`
  return json(c, 200, { ok: true })
})

// Admin: update video metadata (title/description/category/tags)
app.put('/api/videos/:id', async (c) => {
  await ensureSchema(c)
  try { await requireAdmin(c) } catch (e: any) {
    const code = e?.message === 'Unauthorized' ? 401 : 403
    return json(c, code, { detail: e?.message || 'Forbidden' })
  }
  const id = Number(c.req.param('id'))
  if (!id || Number.isNaN(id)) return json(c, 400, { detail: 'Invalid id' })
  const body = await c.req.json().catch(() => ({}))
  const title = body.title != null ? String(body.title) : undefined
  const description = body.description != null ? String(body.description) : undefined
  const category = body.category != null ? String(body.category) : undefined
  const tags = body.tags
  if (title !== undefined && !title.trim()) return json(c, 400, { detail: 'Title cannot be empty' })
  if (description !== undefined && !description.trim()) return json(c, 400, { detail: 'Description cannot be empty' })
  const sets: string[] = []
  const params: any[] = []
  let idx = 1
  if (title !== undefined) { sets.push(`title=$${idx++}`); params.push(title) }
  if (description !== undefined) { sets.push(`description=$${idx++}`); params.push(description) }
  if (category !== undefined) { sets.push(`category=$${idx++}`); params.push(category) }
  if (tags !== undefined) {
    if (Array.isArray(tags)) {
      const tagsArray = `{${tags.map((t: string) => '"' + String(t).replace(/"/g, '\\"') + '"').join(',')}}`
      sets.push(`tags=$${idx++}::text[]`); params.push(tagsArray)
    } else {
      const tagsArray = `{${String(tags).split(',').map((t: string) => '"' + t.trim().replace(/"/g, '\\"') + '"').filter(Boolean).join(',')}}`
      sets.push(`tags=$${idx++}::text[]`); params.push(tagsArray)
    }
  }
  if (!sets.length) return json(c, 400, { detail: 'No changes provided' })
  sets.push(`updated_at=now()`)
  const db = sql(c)
  const sqlText = `update videos set ${sets.join(', ')} where id=$${idx} returning id, title, description, category, tags, status, views, thumbnail_key`
  params.push(id)
  const rows: any[] = await db(sqlText, params)
  const v = (rows as any)[0]
  if (!v) return json(c, 404, { detail: 'Not found' })
  return json(c, 200, v)
})

// Delete
app.delete('/api/videos/:id', async (c) => {
  const id = Number(c.req.param('id'))
  await ensureSchema(c)
  try {
    await requireAdmin(c)
  } catch (e: any) {
    const code = e?.message === 'Unauthorized' ? 401 : 403
    return json(c, code, { detail: e?.message })
  }
  const db = sql(c)
  const rows = await db`select storage_key, thumbnail_key from videos where id=${id}`
  const key = (rows as any)[0]?.storage_key as string | undefined
  const tkey = (rows as any)[0]?.thumbnail_key as string | undefined
  if (key) await c.env.VIDEOS.delete(key)
  if (tkey) await c.env.VIDEOS.delete(tkey)
  await db`delete from videos where id=${id}`
  return json(c, 200, { ok: true })
})

// Stream (redirect to signed URL for both GET and HEAD)
app.all('/api/videos/:id/stream', async (c) => {
  try {
    if (!['GET', 'HEAD'].includes(c.req.method)) return json(c, 405, { detail: 'Method not allowed' })
    await ensureSchema(c)
    let isAdmin = false
    try { const a = await requireAuth(c); isAdmin = !!a.is_admin } catch {}
    const id = Number(c.req.param('id'))
    if (!id || Number.isNaN(id)) return json(c, 400, { detail: 'Invalid id', code: 'BAD_ID' })
    const db = sql(c)
    const rows = await db`select status, storage_key from videos where id=${id}`
    const v = (rows as any)[0]
    if (!v) return json(c, 404, { detail: 'Not found', code: 'VIDEO_NOT_FOUND' })
    if (!v.storage_key) return json(c, 500, { detail: 'Video is missing storage_key', code: 'MISSING_STORAGE_KEY' })
    if (v.status !== 'approved' && !isAdmin) return json(c, 403, { detail: 'Forbidden', code: 'NOT_APPROVED' })
    // Prefer binding streaming by default; enable presign via env flag
    // Default to presigned direct R2 URL for faster TTFB, allow opt-out via env STREAM_PRESIGN=false
    const usePresign = String(c.env.STREAM_PRESIGN ?? 'false').toLowerCase() !== 'false'
    if (usePresign) {
      try {
        const signed = await presignR2Url(c, 'GET', v.storage_key, 3600)
        return new Response(null, { status: 302, headers: { Location: signed } })
      } catch (e: any) {
        console.error('presign error, falling back to binding stream:', e?.message || e)
        return await streamViaBinding(c, v.storage_key)
      }
    }
    return await streamViaBinding(c, v.storage_key)
  } catch (e: any) {
    console.error('stream error:', e?.message || e)
    return json(c, 500, { detail: 'Stream failed', code: 'STREAM_ERROR', error: e?.message || String(e) })
  }
})

// Dev: Inspect R2 env (auth required, no secrets leaked)
app.get('/api/dev/r2-status', async (c) => {
  try {
    // require any auth to reduce exposure
    await requireAuth(c)
    const endpointEnv = (c.env.R2_ENDPOINT || '').toString().trim()
    const acct = (c.env.CLOUDFLARE_ACCOUNT_ID || '').toString().trim()
    let computedEndpoint = endpointEnv
    if ((!computedEndpoint || !/^https?:\/\//i.test(computedEndpoint)) && acct && /^[a-f0-9]{32}$/i.test(acct)) {
      computedEndpoint = `https://${acct}.r2.cloudflarestorage.com`
    }
    let computedHost: string | null = null
    try { if (computedEndpoint) computedHost = new URL(computedEndpoint).hostname } catch {}
    const bucket = (c.env.R2_BUCKET || '').toString().trim()
    const hasAK = !!(c.env.R2_ACCESS_KEY_ID && String(c.env.R2_ACCESS_KEY_ID).length)
    const hasSK = !!(c.env.R2_SECRET_ACCESS_KEY && String(c.env.R2_SECRET_ACCESS_KEY).length)
    return json(c, 200, {
      endpointEnvPresent: !!endpointEnv,
      endpointEnvLooksUrl: /^https?:\/\//i.test(endpointEnv || ''),
      fallbackUsed: !endpointEnv && !!acct,
      computedEndpointPresent: !!computedEndpoint,
      computedHost,
      bucketPresent: !!bucket,
      bucket,
      hasAccessKeyId: hasAK,
      hasSecretAccessKey: hasSK,
    })
  } catch (e: any) {
    return json(c, 500, { detail: 'R2 status error', error: e?.message || String(e) })
  }
})

// Categories
app.get('/api/categories', async (c) => {
  await ensureSchema(c)
  const db = sql(c)
  const rows = await db`select distinct category from videos where status='approved' order by category asc`
  const categories = (rows as any).map((r: any) => r.category)
  return jsonCached(c, 200, { categories }, 300)
})

// Search
app.post('/api/search', async (c) => {
  await ensureSchema(c)
  const url = new URL(c.req.url)
  const qLimit = Number(url.searchParams.get('limit') || '0')
  const qOffset = Number(url.searchParams.get('offset') || '0')
  const limit = Number.isFinite(qLimit) && qLimit > 0 ? Math.min(qLimit, 100) : 0
  const offset = Number.isFinite(qOffset) && qOffset >= 0 ? qOffset : 0
  const body = await c.req.json().catch(() => ({}))
  const query = (body.query || '').toString()
  const category = body.category ? body.category.toString() : undefined
  const db = sql(c)
  const like = `%${query}%`
  const whereParts: string[] = ["status='approved'"]
  const params: any[] = []
  let idx = 1
  if (query) { whereParts.push(`(title ilike $${idx} or description ilike $${idx})`); params.push(like) }
  if (category) { whereParts.push(`category=$${idx++}`); params.push(category) }
  const where = `where ${whereParts.join(' and ')}`
  const totalRows = await db(`select count(*) as c from videos ${where}`, params)
  const total = Number((totalRows as any)[0]?.c || 0)
  let sqlText = `select id, title, description, category, tags, status, views, thumbnail_key from videos ${where} order by created_at desc`
  if (limit) sqlText += ` limit ${limit} offset ${offset}`
  const rows: any[] = await db(sqlText, params)
  return json(c, 200, rows, { 'X-Total-Count': String(total) })
})

// Dynamic sitemap for approved videos (root path)
app.get('/sitemap.xml', async (c) => {
  try {
    await ensureSchema(c)
    const db = sql(c)
    const rows: any[] = await db`select id, updated_at from videos where status='approved' order by updated_at desc limit 1000`
    const base = 'https://bluefilmx.com'
    const urls = [
      { loc: `${base}/`, changefreq: 'hourly', priority: '0.8' },
      { loc: `${base}/blue-film`, changefreq: 'weekly', priority: '0.6' },
      { loc: `${base}/bluefilm`, changefreq: 'weekly', priority: '0.6' },
      { loc: `${base}/porn`, changefreq: 'weekly', priority: '0.6' },
    ]
    for (const r of rows) {
      urls.push({ loc: `${base}/video/${r.id}`, lastmod: (r.updated_at || new Date()).toISOString(), changefreq: 'weekly', priority: '0.6' })
    }
    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` +
      urls.map(u => {
        return `<url>` +
          `<loc>${u.loc}</loc>` +
          (u.lastmod ? `<lastmod>${u.lastmod}</lastmod>` : '') +
          (u.changefreq ? `<changefreq>${u.changefreq}</changefreq>` : '') +
          (u.priority ? `<priority>${u.priority}</priority>` : '') +
        `</url>`
      }).join('') +
      `</urlset>`
    return new Response(xml, { status: 200, headers: {
      'content-type': 'application/xml; charset=utf-8',
      'cache-control': 'public, max-age=0, s-maxage=3600'
    }})
  } catch (e: any) {
    return new Response('<!-- sitemap error -->', { status: 200, headers: { 'content-type': 'application/xml' } })
  }
})

export const onRequest = (context: any) => {
  const url = new URL(context.request.url)
  if (url.pathname === '/sitemap.xml') {
    return app.fetch(context.request, context.env, context)
  }
  if (!url.pathname.startsWith('/api/')) {
    // Let Pages serve static files and SPA routes
    return context.next()
  }
  return app.fetch(context.request, context.env, context)
}
export default app
