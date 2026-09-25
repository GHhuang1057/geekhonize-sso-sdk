#!/usr/bin/env node
/**
 * GeekHonize SSO SDK 构建脚本（零依赖，纯 Node 标准库；照 @geekhonize/ui 的做法）
 *
 *   node build.mjs
 *
 * 产出 dist/：
 *   gh-sso.js          浏览器端（IIFE，挂 window.GHSSO）
 *   gh-sso.min.js      保守压缩版
 *   gh-sso.esm.js      浏览器端 ESM 包装（打包器用户 import 用）
 *   gh-sso-server.mjs  服务端（Node 18+ / Workers / Deno，ESM）
 *   version.json       版本清单（平台站 CDN 同步时读取）
 */

import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = join(__dirname, 'src');
const DIST = join(__dirname, 'dist');

const pkg = JSON.parse(await readFile(join(__dirname, 'package.json'), 'utf8'));

const BANNER = `/*!
 * @geekhonize/sso-sdk v${pkg.version}
 * GeekHonize SSO 接入 SDK · 浏览器端（PKCE 公开客户端）+ 服务端（授权码机密客户端）
 * 由 geekhonize-sso-sdk/build.mjs 生成，请勿直接编辑 dist/ 下的文件。
 */\n`;

/** 保守压缩 JS：去掉整行/块注释与行尾空白，保留所有语义（绝不动字符串内容） */
function minifyJs(js) {
  return js
    .replace(/^[ \t]*\/\*(?!\!)[\s\S]*?\*\/[ \t]*$/gm, '')
    .replace(/^[ \t]*\/\/.*$/gm, '')
    .split('\n')
    .map((l) => l.replace(/\s+$/, ''))
    .filter((l) => l.trim().length > 0)
    .join('\n');
}

async function main() {
  await mkdir(DIST, { recursive: true });

  /* ---------- 1. 浏览器端 ---------- */
  const browser = await readFile(join(SRC, 'browser', 'gh-sso.js'), 'utf8');
  await writeFile(join(DIST, 'gh-sso.js'), BANNER + browser, 'utf8');
  await writeFile(join(DIST, 'gh-sso.min.js'), BANNER + minifyJs(browser), 'utf8');

  // ESM 包装：在假 window 上跑 IIFE，再把 window.GHSSO 导出。
  // 打包器用户 import 后仍需 GHSSO.config(...)；不依赖真实 DOM 环境。
  const esm = `${BANNER}
const __win = (typeof window !== 'undefined') ? window : {};
(() => {
  const window = __win;
  ${minifyJs(browser)}
})();
export default __win.GHSSO;
`;
  await writeFile(join(DIST, 'gh-sso.esm.js'), esm, 'utf8');

  /* ---------- 2. 服务端 ---------- */
  const server = await readFile(join(SRC, 'server', 'index.mjs'), 'utf8');
  await writeFile(join(DIST, 'gh-sso-server.mjs'), BANNER + server, 'utf8');

  /* ---------- 3. 版本清单 ---------- */
  await writeFile(join(DIST, 'version.json'), JSON.stringify({
    name: pkg.name,
    version: pkg.version,
    files: ['gh-sso.js', 'gh-sso.min.js', 'gh-sso.esm.js', 'gh-sso-server.mjs'],
    built_at: new Date().toISOString(),
  }, null, 2) + '\n', 'utf8');

  /* ---------- 报告 ---------- */
  const files = await readdir(DIST);
  const sizes = [];
  for (const f of files.sort()) {
    const buf = await readFile(join(DIST, f));
    sizes.push(`  ${f.padEnd(24)} ${(buf.length / 1024).toFixed(1)} KB`);
  }
  console.log(`\n✅ @geekhonize/sso-sdk v${pkg.version} 构建完成\n` + sizes.join('\n') + '\n');
}

main().catch((err) => {
  console.error('构建失败：', err);
  process.exit(1);
});
