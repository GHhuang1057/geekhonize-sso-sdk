/**
 * GeekHonize SSO · Cloudflare Workers 示例（机密客户端，有后端）
 *
 * 与部署在同 zone 的 auth.geekhonize.top 通信必须走 Service Binding：
 * 同 zone 内 Worker→Worker 的公网 fetch 会被 Cloudflare 拒绝（error 1042，
 * 返回 HTML 错误页而不是 JSON）。wrangler.toml 里声明：
 *
 *   [[services]]
 *   binding = "SSO"
 *   service = "geekhonize-sso"
 *
 * 用法：
 *   import { createSsoClient } from '@geekhonize/sso-sdk/server';
 *   然后按下面 fetch() 里的流程接三条路由：/login、/auth/callback、/logout。
 */

import { createSsoClient } from '../../dist/gh-sso-server.mjs';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const sso = createSsoClient({
      clientId: env.SSO_CLIENT_ID,
      clientSecret: env.SSO_CLIENT_SECRET,
      ssoBase: env.SSO_BASE || 'https://auth.geekhonize.top',
      sessionSecret: env.SESSION_SECRET,
      // Workers 同 zone：注入 Service Binding 的 fetch —— 关键一行
      fetcher: env.SSO ? (input, init) => env.SSO.fetch(input, init) : undefined,
    });

    const cb = `${env.PUBLIC_URL || url.origin}/auth/callback`;

    if (url.pathname === '/login') {
      const state = crypto.randomUUID().replace(/-/g, '');
      // 生产环境把 state 写进签名 cookie，回调时校验；示例直接回带（仅演示）
      const redirect = sso.buildAuthorizeUrl({ redirectUri: cb, state });
      return Response.redirect(redirect + `&demo_state=${state}`, 302);
    }

    if (url.pathname === '/auth/callback') {
      const { code, state, error } = sso.parseCallback(url.toString());
      if (error || !code) return new Response('授权失败：' + (error || 'missing code'), { status: 400 });
      // demo：校验 state 省略；真实接入请按 README 的会话流程处理
      const { session, cookie } = await sso.establishSession({ code });
      return new Response(
        `登录成功：${session.display_name}（uid=${session.uid}，roles=${session.roles.join('/')}）<br>
         <a href="/me">查看 /me 复核</a> · <a href="/logout">退出</a>`,
        { headers: { 'content-type': 'text/html; charset=utf-8', 'set-cookie': cookie } },
      );
    }

    if (url.pathname === '/me') {
      const session = await sso.readSession(request.headers.get('cookie') || '');
      if (!session) return new Response('未登录', { status: 401 });
      const me = await sso.me(session.token);
      return Response.json(me);
    }

    if (url.pathname === '/logout') {
      return new Response('已退出', { headers: { 'set-cookie': sso.clearSessionCookie() } });
    }

    return new Response('GeekHonize SSO Workers 示例 —— 访问 /login 开始', { status: 200 });
  },
};
