/*!
 * GeekHonize SSO SDK · 浏览器端（零依赖，IIFE，挂 window.GHSSO）
 *
 * 面向「纯前端 / SPA / 静态站」的公开客户端集成：PKCE（S256）授权码流程，
 * 全程不出现 client_secret，令牌通过 CORS 白名单直连 SSO 换取与校验。
 *
 * 典型用法：
 *   <script src="https://platform.geekhonize.top/sdk/gh-sso.min.js"></script>
 *   GHSSO.config({ clientId: 'gh_xxxx', redirectUri: location.origin + '/cb' });
 *   GHSSO.login();                       // 跳转 SSO 授权
 *   // 回调页（?code=&state=）：
 *   const r = await GHSSO.handleCallback();
 *   if (r.ok) render(r.user);
 *
 * 安全边界（务必阅读）：
 *   · token 存在浏览器本地（默认 sessionStorage）。XSS 即失窃，请配 CSP。
 *   · 换到的 access_token 是 HS256 JWT，第三方无法本地验签——要核实身份
 *     必须调 GHSSO.me()（服务端 /me 复核），浏览器端同样适用。
 *   · code 交换与 /me 依赖 SSO 对你站点 origin 的 CORS 放行；在开发者平台
 *     的应用设置里登记回调地址即可（留空 cors_origins 时按回调 origin 回落）。
 */
(function () {
  'use strict';

  var DEFAULT_BASE = 'https://auth.geekhonize.top';
  var API_PREFIX = '/api/v1/auth';

  var cfg = {
    clientId: '',
    redirectUri: '',
    ssoBase: DEFAULT_BASE,
    scope: 'openid profile',
    storage: 'session',          // session | local | memory
    storageKey: 'gh_sso',
    autoCallback: true,
    fetch: null                  // 可注入（测试 / 代理场景）
  };

  /* ------------------------------------------------------------------ 工具 */

  function doFetch(input, init) {
    var f = cfg.fetch || (typeof fetch === 'function' ? fetch.bind(globalThis) : null);
    if (!f) throw new Error('GHSSO: 当前环境没有 fetch');
    return f(input, init);
  }

  function b64url(buf) {
    var bin = '';
    var bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function randomToken(hexLen) {
    var n = Math.ceil(hexLen / 2);
    var bytes = new Uint8Array(n);
    crypto.getRandomValues(bytes);
    var hex = '';
    for (var i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
    return hex.slice(0, hexLen);
  }

  /* ------------------------------------------------------------------ 存储 */

  var memStore = {};
  function backend() {
    try {
      if (cfg.storage === 'session' && window.sessionStorage) { window.sessionStorage.getItem('__gh_probe'); return window.sessionStorage; }
      if (cfg.storage === 'local' && window.localStorage) { window.localStorage.getItem('__gh_probe'); return window.localStorage; }
    } catch (e) { /* 隐私模式下抛异常 */ }
    return {
      getItem: function (k) { return Object.prototype.hasOwnProperty.call(memStore, k) ? memStore[k] : null; },
      setItem: function (k, v) { memStore[k] = String(v); },
      removeItem: function (k) { delete memStore[k]; }
    };
  }
  function sget(key) { try { return backend().getItem(cfg.storageKey + '.' + key); } catch (e) { return null; } }
  function sset(key, val) { try { backend().setItem(cfg.storageKey + '.' + key, val); } catch (e) { /* 存不下就只活在内存 */ } }
  function sdel(key) { try { backend().removeItem(cfg.storageKey + '.' + key); } catch (e) { /* ignore */ } }

  /* ------------------------------------------------------------------ 事件 */

  var listeners = {};
  function on(evt, fn) {
    (listeners[evt] || (listeners[evt] = [])).push(fn);
    return function () { off(evt, fn); };
  }
  function off(evt, fn) {
    var arr = listeners[evt] || [];
    var i = arr.indexOf(fn);
    if (i >= 0) arr.splice(i, 1);
  }
  function emit(evt, detail) {
    (listeners[evt] || []).slice().forEach(function (fn) {
      try { fn(detail); } catch (e) { /* 单个监听器异常不影响其它 */ }
    });
  }

  /* ------------------------------------------------------------------ PKCE */

  function createVerifier() {
    var bytes = new Uint8Array(48); // 48 字节 → 64 位 base64url，落在 43–128 区间
    crypto.getRandomValues(bytes);
    return b64url(bytes);
  }
  function challengeFor(verifier) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)).then(function (d) {
      return b64url(d);
    });
  }
  function createPkce() {
    var verifier = createVerifier();
    return challengeFor(verifier).then(function (challenge) {
      return { verifier: verifier, challenge: challenge, method: 'S256' };
    });
  }

  /* ------------------------------------------------------------ API 调用核 */

  /** 统一解包 {ok,msg,…} 信封；失败抛出带 status/code 的 Error。 */
  function api(path, opts) {
    var method = (opts && opts.method) || 'POST';
    var url = cfg.ssoBase + API_PREFIX + path;
    if (opts && opts.query) {
      var us = new URL(url);
      Object.keys(opts.query).forEach(function (k) { us.searchParams.set(k, opts.query[k]); });
      url = us.toString();
    }
    var headers = {};
    if (opts && opts.body !== undefined) headers['content-type'] = 'application/json';
    if (opts && opts.auth !== false && token()) headers['authorization'] = 'Bearer ' + token();
    return doFetch(url, {
      method: method,
      headers: headers,
      body: opts && opts.body !== undefined ? JSON.stringify(opts.body) : undefined
    }).then(function (res) {
      return res.text().then(function (text) {
        var j = null;
        try { j = JSON.parse(text); } catch (e) { /* Cloudflare 错误页等非 JSON 响应 */ }
        if (j && j.ok) return j;
        var err = new Error((j && j.msg) || ('SSO 响应异常（HTTP ' + res.status + '）'));
        err.status = res.status;
        if (j && j.msg) err.code = 'sso_error';
        else err.code = 'bad_response';
        throw err;
      });
    });
  }

  /* ------------------------------------------------------------ 令牌存取 */

  function token() { return sget('token'); }
  function setToken(t, expiresIn) {
    sset('token', t);
    sset('exp', String(Math.floor(Date.now() / 1000) + (Number(expiresIn) || 604800)));
  }
  function clearSession() {
    sdel('token'); sdel('exp'); sdel('user');
  }
  function getUser() {
    try { return JSON.parse(sget('user') || 'null'); } catch (e) { return null; }
  }
  function saveUser(u) { sset('user', JSON.stringify(u || null)); }
  function isAuthenticated() {
    var t = token();
    if (!t) return false;
    var exp = Number(sget('exp') || 0);
    if (exp && exp <= Math.floor(Date.now() / 1000)) { emit('token:expired', {}); return false; }
    return true;
  }
  function tokenExpiresIn() {
    var exp = Number(sget('exp') || 0);
    return exp ? exp - Math.floor(Date.now() / 1000) : 0;
  }

  /* ------------------------------------------------------------ 登录流程 */

  function login(opts) {
    var o = opts || {};
    var redirectUri = o.redirectUri || cfg.redirectUri || location.origin + location.pathname;
    if (!cfg.clientId) throw new Error('GHSSO: 请先 config({ clientId })');
    if (!/^https?:$/.test(location.protocol)) throw new Error('GHSSO: 请在 http(s) 页面中使用');
    if (location.protocol === 'http:' && !/^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname)) {
      throw new Error('GHSSO: 非本地环境必须使用 https（PKCE 依赖 WebCrypto 安全上下文）');
    }
    var state = randomToken(32);
    return createPkce().then(function (pkce) {
      sset('state', state);
      sset('verifier', pkce.verifier);
      if (o.returnTo !== undefined) sset('return', o.returnTo);
      else sdel('return');
      emit('login:start', { state: state });
      var url = cfg.ssoBase + '/authorize'
        + '?client_id=' + encodeURIComponent(cfg.clientId)
        + '&redirect_uri=' + encodeURIComponent(redirectUri)
        + '&state=' + encodeURIComponent(state)
        + '&scope=' + encodeURIComponent(o.scope || cfg.scope)
        + '&code_challenge=' + encodeURIComponent(pkce.challenge)
        + '&code_challenge_method=S256';
      location.assign(url);
    });
  }

  /** 回调页调用：校验 state → 用 code_verifier 换令牌。返回 Promise<{ok,user}|{ok:false,error}>。 */
  function handleCallback(opts) {
    var o = opts || {};
    var url = new URL(o.url || location.href);
    var code = url.searchParams.get('code') || '';
    var state = url.searchParams.get('state') || '';
    var error = url.searchParams.get('error') || '';

    function done(result) {
      if (result.ok && o.cleanUrl !== false && typeof history !== 'undefined' && history.replaceState) {
        url.searchParams.delete('code'); url.searchParams.delete('state'); url.searchParams.delete('error');
        history.replaceState(null, '', url.pathname + (url.search || '') + url.hash);
      }
      if (result.ok) emit('login:success', { user: result.user });
      else emit('login:error', result);
      return result;
    }

    if (error) return Promise.resolve(done({ ok: false, error: error, message: url.searchParams.get('error_description') || '授权被拒绝' }));
    if (!code) return Promise.resolve(done({ ok: false, error: 'code_missing' }));

    var savedState = sget('state');
    sdel('state');
    if (!savedState || savedState !== state) return Promise.resolve(done({ ok: false, error: 'state_mismatch' }));
    var verifier = sget('verifier');
    sdel('verifier');
    if (!verifier) return Promise.resolve(done({ ok: false, error: 'verifier_missing' }));

    return api('/exchange', {
      auth: false,
      query: { client_id: cfg.clientId },
      body: { client_id: cfg.clientId, code: code, code_verifier: verifier }
    }).then(function (j) {
      setToken(j.access_token, j.expires_in);
      saveUser(j.user || null);
      var returnTo = sget('return');
      sdel('return');
      if (o.redirect && returnTo) { location.href = returnTo; }
      return done({ ok: true, user: j.user || null, token: j.access_token, expires_in: j.expires_in });
    }).catch(function (e) {
      return done({ ok: false, error: 'exchange_failed', message: e.message, status: e.status });
    });
  }

  function hasPendingCallback() {
    try {
      var q = new URL(location.href).searchParams;
      return !!(q.get('code') || q.get('error'));
    } catch (e) { return false; }
  }

  /* ------------------------------------------------------------ 会话 API */

  function me(opts) {
    return api('/me', { method: 'GET', query: { client_id: cfg.clientId }, auth: !(opts && opts.token) }).then(function (j) {
      if (j.data) saveUser(j.data);
      return j.data;
    }).catch(function (e) {
      if (e.status === 401) { emit('token:expired', {}); }
      throw e;
    });
  }

  function refresh() {
    return api('/refresh', { query: { client_id: cfg.clientId } }).then(function (j) {
      setToken(j.access_token, j.expires_in);
      if (j.user) saveUser(j.user);
      emit('session:revalidated', { user: j.user || getUser() });
      return j.user || getUser();
    });
  }

  function logout(opts) {
    var o = opts || {};
    clearSession();
    emit('logout', o);
    if (o.federated) location.assign(cfg.ssoBase + '/');
    else if (o.redirectTo) location.href = o.redirectTo;
  }

  /* ------------------------------------------------------------ 配置与自启 */

  function config(next) {
    var prevAuto = cfg.autoCallback;
    Object.keys(next || {}).forEach(function (k) { if (k in cfg) cfg[k] = next[k]; });
    if (cfg.ssoBase) cfg.ssoBase = cfg.ssoBase.replace(/\/+$/, '');
    if (cfg.autoCallback && prevAuto && !window.GHSSO__BOOTED) {
      window.GHSSO__BOOTED = true;
      tryStartCallback();
    }
    return api_readonlyView();
  }
  function api_readonlyView() {
    return { clientId: cfg.clientId, ssoBase: cfg.ssoBase, scope: cfg.scope, storage: cfg.storage };
  }

  /** autoCallback 模式下，页面加载若带着 ?code=/?error= 就自动消化一次。 */
  function tryStartCallback() {
    if (!cfg.clientId || !hasPendingCallback()) return;
    handleCallback().then(function (r) {
      if (!r.ok) emit('login:error', r);
    });
  }

  window.GHSSO = {
    config: config,
    login: login,
    handleCallback: handleCallback,
    hasPendingCallback: hasPendingCallback,
    me: me,
    refresh: refresh,
    logout: logout,
    getToken: token,
    setToken: setToken,
    getUser: getUser,
    clearSession: clearSession,
    isAuthenticated: isAuthenticated,
    tokenExpiresIn: tokenExpiresIn,
    on: on,
    off: off,
    PKCE: { createVerifier: createVerifier, challengeFor: challengeFor, create: createPkce },
    randomToken: randomToken
  };

  if (typeof window.GHSSO__BOOTED === 'undefined') {
    window.GHSSO__BOOTED = true;
    // DOMContentLoaded 前 config 一般来不及，这里只在已有 clientId 时尝试
    tryStartCallback();
  }
})();
