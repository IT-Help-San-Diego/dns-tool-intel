#!/usr/bin/env node
import { readFileSync, existsSync } from 'fs';

const CONFIG_PATH = 'scripts/pipeline-config.json';
const VERSION_RE = /Version\s*=\s*"([^"]+)"/;

function getVersion() {
  try {
    const src = readFileSync('go-server/internal/config/config.go', 'utf8');
    const m = src.match(VERSION_RE);
    return m ? m[1] : 'unknown';
  } catch { return 'unknown'; }
}

function loadConfig() {
  return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
}

function getToken() {
  const token = process.env.MIRO_API_TOKEN;
  if (!token) {
    console.error('\n  [ERROR] MIRO_API_TOKEN secret not set.');
    console.error('  Generate one at: https://miro.com/app/settings/user-profile/apps');
    console.error('  Then add it as a Replit secret.\n');
    process.exit(1);
  }
  return token;
}

async function miroApi(path, options = {}) {
  const token = getToken();
  const url = `https://api.miro.com/v2${path}`;
  const headers = {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/json',
    ...options.headers,
  };
  const resp = await fetch(url, { ...options, headers });
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`Miro API ${resp.status}: ${resp.statusText} — ${body}`);
  }
  return resp.json();
}

async function uploadSvgToBoard(boardId, svgPath, title, position) {
  const token = getToken();
  const url = `https://api.miro.com/v2/boards/${boardId}/images`;

  const svgContent = readFileSync(svgPath);
  const base64 = svgContent.toString('base64');
  const dataUrl = `data:image/svg+xml;base64,${base64}`;

  const payload = {
    data: {
      title: title,
      url: dataUrl,
    },
    position: {
      x: position.x,
      y: position.y,
      origin: 'center',
    },
  };

  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`Miro image upload ${resp.status}: ${resp.statusText} — ${body}`);
  }

  return resp.json();
}

async function main() {
  const config = loadConfig();
  const version = getVersion();
  const boardId = config.miro.board_id;

  console.log(`\n  Mermaid → Miro Sync`);
  console.log(`  Version: ${version}`);
  console.log(`  Board: ${boardId}`);
  console.log(`${'='.repeat(55)}\n`);

  const diagrams = config.miro.diagrams;
  let synced = 0;
  let failed = 0;
  let yOffset = 0;

  for (const [name, info] of Object.entries(diagrams)) {
    const svgPath = info.svg_output;

    if (!existsSync(svgPath)) {
      console.log(`  [SKIP] ${name} — SVG not found at ${svgPath}`);
      console.log(`         Run: bash scripts/render-diagrams.sh`);
      failed++;
      continue;
    }

    try {
      const result = await uploadSvgToBoard(boardId, svgPath, `${info.miro_title} (v${version})`, {
        x: 5000,
        y: yOffset,
      });
      console.log(`  [OK] ${name} → Miro image ${result.id}`);
      synced++;
      yOffset += 800;
    } catch (err) {
      console.log(`  [FAIL] ${name}: ${err.message}`);
      failed++;
    }
  }

  console.log(`\n${'='.repeat(55)}`);
  console.log(`  Result: ${synced} synced, ${failed} failed`);
  console.log(`${'='.repeat(55)}\n`);

  process.exit(failed > 0 ? 1 : 0);
}

main();
