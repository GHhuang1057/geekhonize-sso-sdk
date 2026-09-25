/*!
 * GeekHonize SSO SDK · 服务端（Node 18+ / Cloudflare Workers / Deno，零依赖 ESM）
 *
 * 面向「有后端的网站」（机密客户端）：
 *   1. buildAuthorizeUrl()  生成跳转（带 state；可选再叠加 PKCE）
 *   2. parseCallback()      回调路由里解析 ?code=&state=
 *   3. exchangeCode()       服务端用 client_secret 换访问令牌
 *   4. me()                 调 SSO 复核身份（HS256 令牌无法本地验签，必须走这步）
 *   5. signSession()/verifySession()  自签 httpOnly 会话 cookie（无状态，不落库）
 *
 * 关键提醒（Cloudflare Workers 同 zone 部署者必读）：
 *   同 zone 内一个 Worker 用 fetch() 访问另一个挂在 Route 上的 Worker 会被
 *   Cloudflare 拒绝（error 1042），拿到的是 HTML 错误页而不是 JSON。
 *   解法：给 createSsoClient 传 fetcher（[[services]] Service Binding），
 *   即 env.SSO.fetch —— host 随便填，绑定已指定目标 service。
 *   https://developers.cloudflare.com/workers/configuration/routing/custom-domains/#worker-to-worker-communication
 */

const DEFAULT_BASE = 'https://auth.geekhonize.top';
const API_PREFIX = '/api/v1/auth';
const encoder = new TextEncoder();

/* ------------------------------------------------------------------ 基础 */

function b64urlEncode(text) {
  let s = '';
  const bytes = encoder.encode(text);
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(text) {
  const pad = text.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(pad + '='.repeat((4 - (pad.length % 4)) % 4));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

async function hmacSign(payload, secret) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  let s = '';
  const bytes = new Uint8Array(sig);
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function hmacVerify(payload, signature, secret) {
  const expected = await hmacSign(payload, secret);
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  return diff === 0;
}

/** 无状态签名载荷：base64url(json).sig —— 与官网 / 账号中心同格式，可跨服务互认。 */
export async function signPayload(data, secret) {
  const body = b64urlEncode(JSON.stringify(data));
  return `${body}.${await hmacSign(body, secret)}`;
}

export async function verifyPayload(token, secret, maxAgeCheck = true) {
  const idx = token.lastIndexOf('.');
  if (idx <= 0) return null;
  const body = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  if (!(await hmacVerify(body, sig, secret))) return null;
  try {
    const data = JSON.parse(b64urlDecode(body));
    if (maxAgeCheck && typeof data.exp === 'number' && data.exp < Math.floor(Date.now() / 1000)) return null;
    return data;
  } catch {
    return null;
  }
}

export function randomToken(hexLen = 32) {
  const bytes = new Uint8Array(Math.ceil(hexLen / 2));
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('').slice(0, hexLen);
}

/* --------------------------------------------------------------- cookie */

export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

export function serializeCookie(name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${opts.path ?? '/'}`];
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  if (opts.secure !== false) parts.push('Secure');
  parts.push(`SameSite=${opts.sameSite ?? 'Lax'}`);
  return parts.join('; ');
}

export function clearCookie(name) {
  return serializeCookie(name, '', { maxAge: 0 });
}

/* ------------------------------------------------------------ SSO 客户端 */

/**
 * @param {Object} o
 * @param {string} o.clientId         开发者平台登记的 client_id
 * @param {string} [o.clientSecret]   机密客户端密钥（公开客户端不传）
 * @param {string} [o.ssoBase]        默认 https://auth.geekhonize.top
 * @param {Function} [o.fetcher]      注入 fetch（Workers 传 env.SSO.fetch 以走 Service Binding）
 * @param {string} [o.sessionSecret]  自签会话 cookie 用的 HMAC 密钥（与 SSO 无关，本站私有）
 * @param {string} [o.cookieName]     默认 gh_sso_session
 * @param {number} [o.sessionTtl]     会话秒数，默认 8 小时
 */
export function createSsoClient(o) {
  if (!o || !o.clientId) throw new Error('sso-sdk: clientId 必填');
  const clientId = o.clientId;
  const clientSecret = o.clientSecret || '';
  const ssoBase = (o.ssoBase || DEFAULT_BASE).replace(/\/+$/, '');
  const fetcher = o.fetcher || ((input, init) => fetch(input, init));
  const sessionSecret = o.sessionSecret || '';
  const cookieName = o.cookieName || 'gh_sso_session';
  const sessionTtl = Number(o.sessionTtl || 28800);

  /** 调 SSO API 并解包 {ok,msg}；非 JSON（1042 错误页等）单独归类。 */
  async function call(path, { method = 'POST', body, token, query } = {}) {
    let url = ssoBase + API_PREFIX + path;
    if (query) {
      const u = new URL(url);
      for (const k of Object.keys(query)) u.searchParams.set(k, query[k]);
      url = u.toString();
    }
    const headers = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (token) headers['authorization'] = `Bearer ${token}`;
    const res = await fetcher(url, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    const text = await res.text();
    let j = null;
    try { j = JSON.parse(text); } catch {
      const err = new Error(`SSO 返回非 JSON（HTTP ${res.status}）——同 zone 部署请检查 Service Binding（error 1042）`);
      err.code = 'sso_bad_response';
      err.status = res.status;
      throw err;
    }
    if (!res.ok || !j.ok) {
      const err = new Error(j.msg || `SSO 请求失败（HTTP ${res.status}）`);
      err.code = 'sso_error';
      err.status = res.status;
      throw err;
    }
    return j;
  }

  return {
    /** 生成授权跳转 URL。state 由调用方生成并存进签名 cookie / session（防 CSRF）。 */
    buildAuthorizeUrl({ redirectUri, state, scope, codeChallenge, codeChallengeMethod }) {
      const u = new URL(ssoBase + '/authorize');
      u.searchParams.set('client_id', clientId);
      u.searchParams.set('redirect_uri', redirectUri);
      if (state) u.searchParams.set('state', state);
      u.searchParams.set('scope', scope || 'openid profile');
      if (codeChallenge) {
        u.searchParams.set('code_challenge', codeChallenge);
        u.searchParams.set('code_challenge_method', codeChallengeMethod || 'S256');
      }
      return u.toString();
    },

    /** 回调 URL 解析（不校验 state —— 校验逻辑属调用方会话层）。 */
    parseCallback(rawUrl) {
      const u = new URL(rawUrl);
      return {
        code: u.searchParams.get('code') || '',
        state: u.searchParams.get('state') || '',
        error: u.searchParams.get('error') || '',
      };
    },

    /** 授权码换令牌。机密客户端自动带 client_secret；带 PKCE 时传 codeVerifier。 */
    exchangeCode({ code, codeVerifier }) {
      const body = { client_id: clientId, code };
      if (clientSecret) body.client_secret = clientSecret;
      if (codeVerifier) body.code_verifier = codeVerifier;
      return call('/exchange', { body, query: { client_id: clientId } }).then((j) => ({
        access_token: j.access_token,
        token_type: j.token_type,
        expires_in: j.expires_in,
        scope: j.scope,
        user: j.user,
      }));
    },

    /** 复核身份。HS256 令牌无法本地验签，这是唯一的权威校验。 */
    me(token) {
      return call('/me', { method: 'GET', token, query: { client_id: clientId } }).then((j) => j.data);
    },

    /** 轮换访问令牌（会话续期用）。 */
    refresh(token) {
      return call('/refresh', { token, query: { client_id: clientId } }).then((j) => ({
        access_token: j.access_token,
        expires_in: j.expires_in,
        user: j.user,
      }));
    },

    /** 无状态登出：SSO 侧不追踪令牌，客户端丢弃即可。 */
    logout(token) {
      return call('/logout', { token, query: { client_id: clientId } }).then(() => true);
    },

    /* ---- 自签会话 cookie（本站私有格式，与 SSO 令牌无关） ---- */

    async signSession(payload) {
      if (!sessionSecret) throw new Error('sso-sdk: 未配置 sessionSecret');
      const data = { ...payload, exp: Math.floor(Date.now() / 1000) + sessionTtl };
      return signPayload(data, sessionSecret);
    },

    async readSession(cookieHeader) {
      if (!sessionSecret) throw new Error('sso-sdk: 未配置 sessionSecret');
      const raw = parseCookies(cookieHeader)[cookieName];
      if (!raw) return null;
      return verifyPayload(raw, sessionSecret);
    },

    sessionCookie(value) {
      return serializeCookie(cookieName, value, { maxAge: sessionTtl, sameSite: 'Lax' });
    },

    clearSessionCookie() {
      return clearCookie(cookieName);
    },

    /** 便捷入口：把 {code, state} 的交换结果直接变成会话 cookie。 */
    async establishSession({ code, codeVerifier, extra = {} }) {
      const t = await this.exchangeCode({ code, codeVerifier });
      const session = {
        uid: Number(t.user?.uid ?? t.user?.id ?? 0),
        username: t.user?.username || '',
        display_name: t.user?.display_name || t.user?.username || '',
        email: t.user?.email || '',
        roles: Array.isArray(t.user?.roles) ? t.user.roles : [],
        token: t.access_token,
        ...extra,
      };
      return { session, cookie: this.sessionCookie(await this.signSession(session)), token: t };
    },

    /**
     * 需要时手动透传原始 fetch（如 Service Binding 探针）。
     * Workers 同 zone 记得传 fetcher = (input, init) => env.SSO.fetch(input, init)。
     */
    rawCall: call,
  };
}

export default createSsoClient;
