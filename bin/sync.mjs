#!/usr/bin/env node
/**
 * geekhonize-sso-sync —— 把 @geekhonize/sso-sdk 的产物同步进宿主项目
 *
 * 用法（在宿主项目根目录执行）：
 *   node node_modules/@geekhonize/sso-sdk/bin/sync.mjs
 *   node node_modules/@geekhonize/sso-sdk/bin/sync.mjs --out public/sdk
 *
 * 参数：
 *   --out <dir>      输出目录（默认 public/sdk）
 *   --versioned      额外产出不可变的 <out>/v<version>/ 副本（给 CDN 长缓存用）
 *   --quiet          仅输出错误
 *
 * 同步的文件（全部来自包内 dist/）：
 *   gh-sso.js / gh-sso.min.js / gh-sso.esm.js / gh-sso-server.mjs / version.json
 *
 * 开发者平台（platform.geekhonize.top）用 --out public/sdk --versioned，
 * 并在 Worker 里给带版本号的 SDK 目录打 immutable 缓存头。
 */

import { readFile, writeFile, mkdir, copyFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, isAbsolute, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, '..');
const DIST = join(PKG_ROOT, 'dist');

const FILES = [
  'gh-sso.js',
  'gh-sso.min.js',
  'gh-sso.esm.js',
  'gh-sso-server.mjs',
  'version.json',
];

function parseArgs(argv) {
  const out = { assets: 'public/sdk', versioned: false, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') out.assets = argv[++i];
    else if (a === '--versioned') out.versioned = true;
    else if (a === '--quiet') out.quiet = true;
  }
  return out;
}

function abs(p) {
  return isAbsolute(p) ? p : resolve(process.cwd(), p);
}

async function copySet(srcDir, dstDir) {
  await mkdir(dstDir, { recursive: true });
  const copied = [];
  for (const f of FILES) {
    await copyFile(join(srcDir, f), join(dstDir, f));
    copied.push(f);
  }
  return copied;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const log = (...m) => { if (!args.quiet) console.log(...m); };

  let version = '';
  try {
    version = JSON.parse(await readFile(join(DIST, 'version.json'), 'utf8')).version || '';
  } catch {
    version = JSON.parse(await readFile(join(PKG_ROOT, 'package.json'), 'utf8')).version;
  }

  const assetsDir = abs(args.assets);
  const copied = await copySet(DIST, assetsDir);
  log(`✅ 已同步 ${copied.length} 个文件 → ${assetsDir}`);

  if (args.versioned && version) {
    const verDir = join(assetsDir, `v${version}`);
    await copySet(DIST, verDir);
    log(`✅ 已产出不可变副本 → ${verDir}（配 immutable 缓存头）`);
  }
  // 顶层再写一份 version.json，方便平台页脚展示当前版本号
  await writeFile(join(assetsDir, 'version.json'), JSON.stringify({ version, synced_at: new Date().toISOString() }, null, 2) + '\n', 'utf8');
}

main().catch((err) => {
  console.error('同步失败：', err);
  process.exit(1);
});
