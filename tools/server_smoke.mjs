#!/usr/bin/env node
/**
 * @geekhonize/sso-sdk 服务端冒烟测试（对本地 wrangler dev 的 SSO 跑真实链路）
 *
 * 前置：geekhonize-sso 已 `wrangler dev --port 8787`，.dev.vars 里
 *   CAPTCHA_MODE=off、REQUIRE_VERIFIED_APP_CREATE=0。
 *
 * 用法：node tools/server_smoke.mjs [base]
 *
 * 覆盖：buildAuthorizeUrl 形状、parseCallback、exchangeCode（带 secret）、
 * me、refresh、signSession/readSession 往返、clearCookie、logout、错误分类。
 */

import { createSsoClient, signPayload, verifyPayload, parseCookies, serializeCookie, randomToken } from '../dist/gh-sso-server.mjs';

const BASE = (process.argv[2] || 'http://127.0.0.1:8787').replace(/\/+$/, '');
let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log(`  ok  ${name}`); }
  else { failed++; console.log(`FAIL  ${name}${extra !== undefined ? '  -> ' + JSON.stringify(extra) : ''}`); }
}

async function raw(path, body, token) {
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  const r = await fetch(BASE + '/api/v1/auth' + path, { method: 'POST', headers, body: JSON.stringify(body) });
  return r.json();
}

async function main() {
  console.log(`目标：${BASE}\n`);

  // 0. 工具函数自洽
  {
    const secret = 'test-secret-' + randomToken(8);
    const signed = await signPayload({ hello: '世界', exp: Math.floor(Date.now() / 1000) + 60 }, secret);
    const back = await verifyPayload(signed, secret);
    check('signPayload/verifyPayload 往返（中文载荷）', back?.hello === '世界', back);
    check('篡改签名被拒', (await verifyPayload(signed + 'x', secret)) === null);
    check('过期载荷被拒', (await verifyPayload(await signPayload({ exp: 1 }, secret), secret)) === null);
    const cookie = serializeCookie('a', 'b c');
    check('serialize/parseCookie 往返（值带空格）', parseCookies(cookie).a === 'b c', cookie);
  }

  // 1. 准备：注册用户 + 机密应用
  const uname = `sdk_${Date.now().toString(36)}`;
  const reg = await raw('/register', { username: uname, password: 'supersecret123' });
  check('注册用户', reg.ok, reg);
  const userToken = reg.access_token;
  const cf = await raw('/apps', {
    display_name: 'SDK冒烟-机密应用', homepage: 'https://demo.example.com',
    redirect_uris: ['https://demo.example.com/cb'], client_type: 'confidential',
  }, userToken);
  check('创建机密应用', cf.ok, cf);
  const clientId = cf.data.app.client_id;
  const clientSecret = cf.data.client_secret;

  // 2. createSsoClient 全链路
  const sso = createSsoClient({
    clientId,
    clientSecret,
    ssoBase: BASE,
    sessionSecret: 'local-session-secret',
    cookieName: 'gh_smoke_session',
  });

  const authorizeUrl = sso.buildAuthorizeUrl({ redirectUri: 'https://demo.example.com/cb', state: 'st-42' });
  {
    const u = new URL(authorizeUrl);
    check('buildAuthorizeUrl 端点与参数', u.pathname === '/authorize'
      && u.searchParams.get('client_id') === clientId
      && u.searchParams.get('state') === 'st-42'
      && u.searchParams.get('redirect_uri') === 'https://demo.example.com/cb'
      && u.searchParams.get('scope') === 'openid profile', authorizeUrl);
  }

  // 模拟授权页签发授权码（真实流程里由账号中心同意后调用）
  const az = await raw('/authorize', { client_id: clientId, redirect_uri: 'https://demo.example.com/cb', state: 'st-42' }, userToken);
  check('签发授权码', az.ok && az.data.code, az);
  const parsed = sso.parseCallback('https://demo.example.com/cb?code=' + az.data.code + '&state=st-42');
  check('parseCallback', parsed.code === az.data.code && parsed.state === 'st-42' && !parsed.error);

  const tok = await sso.exchangeCode({ code: parsed.code });
  check('exchangeCode（secret）', !!tok.access_token && tok.user?.username === uname, tok.user);

  const who = await sso.me(tok.access_token);
  check('me 复核身份', who?.username === uname, who);

  const refreshed = await sso.refresh(tok.access_token);
  // 同一秒内重签的 HS256 载荷完全相同，不能断言字符串不等——改为验证新令牌可用
  check('refresh 返回可用令牌', !!(refreshed.access_token && (await sso.me(refreshed.access_token))?.username === uname));

  check('logout（无状态）', (await sso.logout(refreshed.access_token)) === true);

  // 3. establishSession + 会话 cookie 往返
  {
    // 授权码单次使用：先签一个新码，再走 establishSession（内部完成 exchange + 签发会话）
    const az3 = await raw('/authorize', { client_id: clientId, redirect_uri: 'https://demo.example.com/cb' }, userToken);
    const { session, cookie } = await sso.establishSession({ code: az3.data.code });
    check('establishSession 产出会话与 cookie', !!session?.uid && session.username === uname && cookie.includes('gh_smoke_session='), session);
    // serializeCookie 产出的 Set-Cookie 串本身就是 "name=value; attrs" 形状，可直接喂给 parseCookies
    const readBack = await sso.readSession(cookie.split(';')[0]);
    check('readSession 从 cookie 还原会话', readBack?.username === uname, readBack);
    check('readSession 篡改被拒', (await sso.readSession('gh_smoke_session=' + 'x'.repeat(20))) === null);
  }

  // 4. 错误分类
  {
    let err = null;
    try { await sso.exchangeCode({ code: 'nonexistent' }); } catch (e) { err = e; }
    check('坏授权码 → sso_error', err?.code === 'sso_error' && /授权码无效/.test(err?.message), err?.message);

    err = null;
    const bad = createSsoClient({ clientId, clientSecret: 'wrong'.repeat(16), ssoBase: BASE });
    const az2 = await raw('/authorize', { client_id: clientId, redirect_uri: 'https://demo.example.com/cb' }, userToken);
    try { await bad.exchangeCode({ code: az2.data.code }); } catch (e) { err = e; }
    check('错 secret → sso_error(401)', err?.code === 'sso_error' && err.status === 401, err?.message);

    // 1042 场景归类：指向一个返回 HTML 的"服务"
    err = null;
    const htmlish = createSsoClient({ clientId, clientSecret, ssoBase: 'https://httpbin.org/html', fetcher: async () => ({ status: 403, text: async () => '<html>error 1042</html>' }) });
    try { await htmlish.exchangeCode({ code: 'x' }); } catch (e) { err = e; }
    check('非 JSON 响应 → sso_bad_response（1042 提示）', err?.code === 'sso_bad_response' && /1042|Service Binding/.test(err?.message), err?.message);
  }

  console.log(`\n结果：${passed} 通过 / ${failed} 失败`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error('冒烟异常：', e); process.exit(1); });
