/**
 * GeekHonize SSO · Node（Express 风格）示例 —— 只依赖 Node 18+ 标准库
 *
 *   node examples/node/server.mjs
 *   浏览器打开 http://localhost:3000/login
 *
 * 前提：在开发者平台建「有后端」应用，回调白名单加 http://localhost:3000/auth/callback，
 * 把 client_id / client_secret 填进下面的 CONFIG（生产请走环境变量）。
 */

import http from 'node:http';
import { createSsoClient } from '../../dist/gh-sso-server.mjs';

const CONFIG = {
  clientId: process.env.SSO_CLIENT_ID || 'gh_xxxxxxxx',
  clientSecret: process.env.SSO_CLIENT_SECRET || '把密钥填进来',
  ssoBase: process.env.SSO_BASE || 'https://auth.geekhonize.top',
  sessionSecret: process.env.SESSION_SECRET || 'change-me-to-a-long-random-string',
  publicUrl: 'http://localhost:3000',
};

const sso = createSsoClient(CONFIG);

const users = new Map(); // 演示用内存会话表；生产用你已有的会话存储

function setSession(res, id, session) {
  users.set(id, session);
  res.setHeader('set-cookie', `sid=${id}; Path=/; HttpOnly; SameSite=Lax`);
}
function getSession(req) {
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || '');
  return m ? users.get(m[1]) : null;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, CONFIG.publicUrl);

  try {
    if (url.pathname === '/login') {
      const state = await sso.signSession({ s: 'demo' });
      return res.writeHead(302, { location: sso.buildAuthorizeUrl({ redirectUri: `${CONFIG.publicUrl}/auth/callback`, state }) }).end();
    }

    if (url.pathname === '/auth/callback') {
      const { code, error } = sso.parseCallback(url.toString());
      if (error || !code) { res.writeHead(400); return res.end('授权失败'); }
      const { session } = await sso.establishSession({ code });
      setSession(res, crypto.randomUUID(), session);
      res.writeHead(302, { location: '/me' });
      return res.end();
    }

    if (url.pathname === '/me') {
      const session = getSession(req);
      if (!session) { res.writeHead(401); return res.end('未登录'); }
      const me = await sso.me(session.token); // HS256 令牌只能这样复核
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify(me, null, 2));
    }

    if (url.pathname === '/logout') {
      const sid = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || '')?.[1];
      if (sid) users.delete(sid);
      res.writeHead(302, { location: '/', 'set-cookie': 'sid=; Path=/; Max-Age=0' });
      return res.end();
    }

    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end('<p><a href="/login">用 GeekHonize 登录</a></p>');
  } catch (e) {
    res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('错误：' + e.message);
  }
});

server.listen(3000, () => console.log('http://localhost:3000'));
