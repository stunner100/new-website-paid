import { Hono } from 'hono'
import bcrypt from 'bcryptjs'
import { neon } from '@neondatabase/serverless'
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import * as jose from 'jose'

// Cloudflare Pages Functions binding types
export type Bindings = {
  DATABASE_URL: string
  JWT_SECRET: string
  R2_ENDPOINT: string
  R2_ACCESS_KEY_ID: string
  R2_SECRET_ACCESS_KEY: string
  R2_BUCKET: string
  // R2 bucket binding; typed as any locally to avoid workers-types dependency
  VIDEOS: any
}

const app = new Hono<{ Bindings: Bindings }>()

// Utilities
const json = (c: any, status: number, body: any, headers: Record<string, string> = {}) =>
  c.json(body, status, {
    'content-type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    ...headers,
  })

app.use('/api/*', async (c, next) => {
  if (c.req.method === 'OPTIONS') return json(c, 200, {})
  await next()
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

function s3(c: any) {
  return new S3Client({
    region: 'auto',
    endpoint: c.env.R2_ENDPOINT,
    forcePathStyle: true,
    credentials: {
      accessKeyId: c.env.R2_ACCESS_KEY_ID,
      secretAccessKey: c.env.R2_SECRET_ACCESS_KEY,
    },
  } as any)
}

function sql(c: any) {
  const client = neon(c.env.DATABASE_URL)
  return (text: string, params?: any[]) => (client as any).unsafe(text, params)
}

async function ensureSchema(c: any) {
  const db = sql(c)
  await db(`create table if not exists users (
    id bigserial primary key,
    email text unique not null,
    name text not null,
    password_hash text not null,
    age_verified boolean default false,
    is_admin boolean default false,
    is_approved boolean default false,
    created_at timestamptz default now()
  )`)
  await db(`create table if not exists videos (
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
  )`)
}

async function requireAuth(c: any) {
  const auth = c.req.header('authorization') || c.req.header('Authorization') || ''
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : (new URL(c.req.url).searchParams.get('token') || undefined)
  if (!token) throw new Error('Unauthorized')
  const payload: any = await verifyToken(c.env.JWT_SECRET, token)
  const userId = Number(payload.sub)
  if (!userId) throw new Error('Unauthorized')
  const db = sql(c)
  const rows = await db(`select id, email, name, age_verified, is_admin, is_approved from users where id=$1`, [userId])
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
    const rows = await db('select 1 as db')
    return json(c, 200, { ok: true, db: (rows as any)[0]?.db === 1 })
  } catch {
    return json(c, 200, { ok: true, db: false })
  }
})

// Auth
app.post('/api/auth/register', async (c) => {
  await ensureSchema(c)
  const body = await c.req.json().catch(() => ({}))
  const { email, name, password, age_verified } = body || {}
  if (!email || !name || !password) return json(c, 400, { detail: 'Missing fields' })
  const db = sql(c)
  try {
    const password_hash = await bcrypt.hash(password, 10)
    const rows = await db(
      `insert into users (email, name, password_hash, age_verified, is_admin, is_approved)
       values ($1,$2,$3,$4,$5,$6)
       returning id, email, name, age_verified, is_admin, is_approved`,
      [email, name, password_hash, !!age_verified, false, false]
    )
    const user = (rows as any)[0]
    const token = await signToken(c.env.JWT_SECRET, { sub: user.id })
    return json(c, 200, { access_token: token, token_type: 'bearer', user })
  } catch (e: any) {
    if (e.code === '23505') return json(c, 400, { detail: 'Email already registered' })
    return json(c, 500, { detail: 'Registration failed' })
  }
})

app.post('/api/auth/login', async (c) => {
  await ensureSchema(c)
  const body = await c.req.json().catch(() => ({}))
  const { email, password } = body || {}
  if (!email || !password) return json(c, 400, { detail: 'Missing fields' })
  const db = sql(c)
  const rows = await db(`select id, email, name, password_hash, age_verified, is_admin, is_approved from users where email=$1`, [email])
  const u = (rows as any)[0]
  if (!u) return json(c, 400, { detail: 'Invalid credentials' })
  const ok = await bcrypt.compare(password, u.password_hash)
  if (!ok) return json(c, 400, { detail: 'Invalid credentials' })
  const { password_hash, ...user } = u
  const token = await signToken(c.env.JWT_SECRET, { sub: user.id })
  return json(c, 200, { access_token: token, token_type: 'bearer', user })
})

app.get('/api/auth/profile', async (c) => {
  try {
    const auth = c.req.header('authorization') || ''
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : undefined
    if (!token) return json(c, 401, { detail: 'Invalid token' })
    const payload: any = await verifyToken(c.env.JWT_SECRET, token)
    const db = sql(c)
    const rows = await db(`select id, email, name, age_verified, is_admin, is_approved from users where id=$1`, [payload.sub])
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
    const { userId } = await requireAdmin(c)
    const body = await c.req.json().catch(() => ({}))
    const rawName = (body.filename || 'upload.mp4').toString()
    const safeName = sanitizeFilename(rawName)
    const storageKey = `${userId}/${crypto.randomUUID()}_${safeName}`

    const client = s3(c)
    const cmd = new PutObjectCommand({ Bucket: c.env.R2_BUCKET, Key: storageKey })
    const uploadUrl = await getSignedUrl(client, cmd, { expiresIn: 60 * 10 })
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
    const rows = await db(
      `insert into videos (title, description, category, tags, status, uploader_id, storage_key)
       values ($1,$2,$3,$4::text[],$5,$6,$7)
       returning id, title, description, category, tags, status, views`,
      [title, description, category, tagsArray, 'pending', userId, storageKey]
    )
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
    const { title, description, category, tags = [], storageKey } = body
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
      `insert into videos (title, description, category, tags, status, uploader_id, storage_key)
       values ($1,$2,$3,$4::text[],$5,$6,$7)
       returning id, title, description, category, tags, status, views`,
      [title, description, category, tagsArray, 'pending', userId, storageKey]
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
  try {
    const auth = await requireAuth(c)
    isAdmin = !!auth.is_admin
  } catch {}
  const url = new URL(c.req.url)
  const status = url.searchParams.get('status') || undefined
  const category = url.searchParams.get('category') || undefined

  const where: string[] = []
  const params: any[] = []
  if (!isAdmin) {
    where.push("status='approved'")
  } else if (status && status !== 'all') {
    params.push(status)
    where.push(`status=$${params.length}`)
  }
  if (category) {
    params.push(category)
    where.push(`category=$${params.length}`)
  }
  const whereSql = where.length ? `where ${where.join(' and ')}` : ''
  const db = sql(c)
  const rows = await db(`select id, title, description, category, tags, status, views from videos ${whereSql} order by created_at desc`, params)
  return json(c, 200, rows)
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
  await db(`update videos set status=$1, updated_at=now() where id=$2`, [newStatus, id])
  return json(c, 200, { ok: true })
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
  const rows = await db(`select storage_key from videos where id=$1`, [id])
  const key = (rows as any)[0]?.storage_key as string | undefined
  if (key) {
    await c.env.VIDEOS.delete(key)
  }
  await db(`delete from videos where id=$1`, [id])
  return json(c, 200, { ok: true })
})

// Stream (redirect to signed URL for both GET and HEAD)
app.all('/api/videos/:id/stream', async (c) => {
  if (!['GET', 'HEAD'].includes(c.req.method)) return json(c, 405, { detail: 'Method not allowed' })
  await ensureSchema(c)
  let authInfo: { userId: number; is_admin: boolean } | null = null
  try { authInfo = await requireAuth(c) } catch {}
  const id = Number(c.req.param('id'))
  const db = sql(c)
  const rows = await db(`select status, storage_key from videos where id=$1`, [id])
  const v = (rows as any)[0]
  if (!v) return json(c, 404, { detail: 'Not found' })
  if (v.status !== 'approved' && !authInfo?.is_admin) return json(c, 403, { detail: 'Forbidden' })
  const client = s3(c)
  const signed = await getSignedUrl(client, new GetObjectCommand({ Bucket: c.env.R2_BUCKET, Key: v.storage_key }), { expiresIn: 60 * 60 })
  return new Response(null, { status: 302, headers: { Location: signed } })
})

// Categories
app.get('/api/categories', async (c) => {
  await ensureSchema(c)
  const db = sql(c)
  const rows = await db(`select distinct category from videos where status='approved' order by category asc`)
  const categories = (rows as any).map((r: any) => r.category)
  return json(c, 200, { categories })
})

// Search
app.post('/api/search', async (c) => {
  await ensureSchema(c)
  const body = await c.req.json().catch(() => ({}))
  const query = (body.query || '').toString()
  const category = body.category ? body.category.toString() : undefined
  const params: any[] = []
  let where = "where status='approved'"
  if (query) {
    params.push(`%${query}%`)
    where += ` and (title ilike $${params.length} or description ilike $${params.length})`
  }
  if (category) {
    params.push(category)
    where += ` and category=$${params.length}`
  }
  const db = sql(c)
  const rows = await db(`select id, title, description, category, tags, status, views from videos ${where} order by created_at desc`, params)
  return json(c, 200, rows)
})

export const onRequest = (context: any) => {
  const url = new URL(context.request.url)
  if (!url.pathname.startsWith('/api/')) {
    // Let Pages serve static files and SPA routes
    return context.next()
  }
  return app.fetch(context.request, context)
}
export default app
