# @geekhonize/sso-sdk

GeekHonize SSO 接入 SDK。零依赖，两个构建产物各管一个场景：

| 你的站点 | 用哪个 | 客户端类型 |
|---|---|---|
| 纯前端 / SPA / 静态站，**没有后端** | `dist/gh-sso.min.js`（`window.GHSSO`） | 公开客户端（PKCE S256，无 secret） |
| 有服务端（Node / Cloudflare Workers / 任何后端） | `dist/gh-sso-server.mjs`（ESM） | 机密客户端（client_secret 只待在服务端） |

协议底座与完整端点参考见 SSO 仓库的 [docs/api.md](https://github.com/GHhuang1057/geekhonize-sso/blob/main/docs/api.md)（§10）。

## 三步接入

1. 在 **[platform.geekhonize.top](https://platform.geekhonize.top)** 用 GeekHonize 账号登录，创建一个应用，
   按上表选类型，登记回调地址，拿到 `client_id`（机密客户端另拿到只显示一次的 `client_secret`）。
2. 引入 SDK（见下）。
3. 把回调地址里的 `?code=&state=` 交给 SDK，其余它来管。

CDN：

```html
<script src="https://platform.geekhonize.top/sdk/v0.1.0/gh-sso.min.js"></script>
```

npm：

```bash
npm install @geekhonize/sso-sdk
```

```js
import { createSsoClient } from '@geekhonize/sso-sdk/server';
```

静态拷贝进项目（不引 npm、不走 CDN）：

```bash
npx geekhonize-sso-sync --out public/sdk --versioned
```

## 浏览器端（公开客户端 / PKCE）

```html
<script src="https://platform.geekhonize.top/sdk/gh-sso.min.js"></script>
<script>
  GHSSO.config({
    clientId: 'gh_xxxxxxxx',
    redirectUri: location.origin + '/cb',
  });

  // 未登录：点按钮时
  GHSSO.login();                       // 生成 state + PKCE，跳转 SSO

  // 回调页：页面加载即处理（autoCallback 默认开启）
  const r = await GHSSO.handleCallback(); // 或 GHSSO.me() 走已登录路径
  if (r.ok) console.log(r.user.username);

  GHSSO.isAuthenticated();              // 有没有会话
  GHSSO.me();                           // 向 SSO 复核身份（推荐进页就调一次）
  GHSSO.logout({ federated: true });    // 清本地；federated 同时跳回 SSO
</script>
```

完整 API：

| 方法 | 说明 |
|---|---|
| `config({clientId, redirectUri, ssoBase, scope, storage, storageKey, autoCallback, fetch})` | 配置；除 clientId 外都有默认值 |
| `login({returnTo, scope, redirectUri})` | 跳转授权。`returnTo` 登录完成后回跳 |
| `handleCallback({url, redirect, cleanUrl})` | 校验 state、换令牌、清地址栏的 code |
| `hasPendingCallback()` | 当前 URL 是否带着回调参数 |
| `me()` / `refresh()` | 复核 / 续期（refresh 需 SSO 接受当前令牌） |
| `getToken() / setToken(t, ttl) / getUser() / clearSession()` | 本地会话读写 |
| `isAuthenticated() / tokenExpiresIn()` | 会话状态 |
| `logout({federated, redirectTo})` | 登出 |
| `on(evt, fn) / off(evt, fn)` | 事件：`login:start / login:success / login:error / token:expired / logout` |
| `GHSSO.PKCE` | 底层原语：`create / createVerifier / challengeFor` |

### 安全边界（公开客户端必须知道）

- 令牌存在浏览器本地（默认 `sessionStorage`，可 `storage: 'local'` 或 `'memory'`）。
  **XSS 即令牌失窃**，接入方请配 CSP；对安全敏感的站点建议改用「有后端」模式。
- 换到的 `access_token` 是 HS256 JWT，**第三方无法本地验签**。浏览器端同理：想确认身份
  只能 `GHSSO.me()`。这是 SSO 的设计（共享密钥 + 免费档 CPU 预算），不是缺陷。
- 没有 refresh_token 概念。令牌 7 天过期，过期后重新走 `login()`。
- `handleCallback` 校验失败（`state_mismatch` / `verifier_missing`）不会重试，直接报错——
  让用户重新点登录即可。

## 服务端（机密客户端）

```js
import { createSsoClient } from '@geekhonize/sso-sdk/server';

const sso = createSsoClient({
  clientId: process.env.SSO_CLIENT_ID,
  clientSecret: process.env.SSO_CLIENT_SECRET,
  sessionSecret: process.env.SESSION_SECRET, // 自签会话 cookie 用，和 SSO 无关
});

// /login —— 生成跳转（state 自己生成并写进签名 cookie）
res.redirect(sso.buildAuthorizeUrl({ redirectUri: 'https://app.example.com/auth/callback', state }));

// /auth/callback —— 换令牌 + 建立本站会话（一条链）
const { code, state, error } = sso.parseCallback(req.url);
const { session, cookie } = await sso.establishSession({ code });
res.setHeader('set-cookie', cookie); // session: { uid, username, display_name, email, roles, token, exp }

// 之后每个请求：
const session = await sso.readSession(req.headers.cookie);
// 建议每 ~30 分钟复核一次（封号即时生效的关键）：
const me = await sso.me(session.token);

// 其它：sso.exchangeCode({code}) / sso.refresh(token) / sso.logout(token)
// 工具：signPayload/verifyPayload/parseCookies/serializeCookie/clearCookie/randomToken
```

### Cloudflare Workers 同 zone 必读

如果你的 Worker 和 `auth.geekhonize.top` 在同一个 zone，**服务端用 `fetch()` 调 SSO 公网域名
会被 Cloudflare 拒绝（error 1042），返回 HTML 错误页**。解法是 Service Binding，SDK 原生支持注入：

```toml
# wrangler.toml
[[services]]
binding = "SSO"
service = "geekhonize-sso"
```

```js
const sso = createSsoClient({
  clientId: env.SSO_CLIENT_ID,
  clientSecret: env.SSO_CLIENT_SECRET,
  sessionSecret: env.SESSION_SECRET,
  fetcher: env.SSO ? (input, init) => env.SSO.fetch(input, init) : undefined,
});
```

忘传 `fetcher` 时 SDK 抛的错误信息会直接点名 1042，方便排查。

### 复核策略

会话 cookie 是 SDK 自签的（HMAC，`sessionSecret`），只防篡改不验过期。令牌真值必须回源：
按 `mainsite` 的实践，会话建立后每 30 分钟调一次 `sso.me()`，401/403 就清会话。
这样 SSO 侧封号/降权最迟半小时内在你的站点生效。

## 目录

```
src/browser/gh-sso.js     浏览器端源码（IIFE）
src/server/index.mjs      服务端源码（ESM）
dist/                     构建产物（提交进仓库）
bin/sync.mjs              静态拷贝 CLI（--out / --versioned）
examples/static-pkce/     纯前端完整示例（npx serve 即跑）
examples/node/            Node 无框架示例
examples/workers/         Workers + Service Binding 示例
tools/server_smoke.mjs    服务端冒烟测试（对本地 wrangler dev 跑真实链路）
docs/                     分场景接入文档（平台站同源引用）
```

构建：`node build.mjs`（零依赖，保守压缩，不动语义）。

## 排错速查

| 现象 | 原因 |
|---|---|
| 授权页报「回调地址不在白名单内」 | redirect_uri 与平台登记的不是逐字符相同（端口、尾斜杠、hash 都算） |
| 浏览器控制台 CORS 报错 | origin 未命中白名单；公开客户端默认回落到回调地址的 origin 集合 |
| 换令牌 400「授权码已被使用」 | 回调处理跑了两遍（autoCallback + 手动调用）——去掉手动调用即可 |
| `state_mismatch` | 用户在授权页停留过久 / 开了新标签页；重新登录即可 |
| Workers 返回非 JSON | 忘了 Service Binding（error 1042），见上文 |
