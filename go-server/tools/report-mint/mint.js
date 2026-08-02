// Skeleton mint: renders skeleton.html to PDF through headless Chromium.
// Engine proof for the report-mint plan (REPORT-IA-CONTRACT.md); the future
// /analysis/:id/pdf route drives the same Page.printToPDF surface server-side.
//
// Usage: node mint.js [out.pdf]
// Chromium resolution: $MINT_CHROMIUM, else Playwright's headless shell, else
// Chrome. On this project's dev Mac, full Chrome hangs in headless mode under
// managed policies — the Playwright headless shell is the binary that works.
const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer-core');

const CANDIDATES = [
  process.env.MINT_CHROMIUM,
  `${process.env.HOME}/Library/Caches/ms-playwright/chromium_headless_shell-1194/chrome-mac/headless_shell`,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean);

// Running footer: the provenance line as page furniture. Chromium print does
// not support CSS @page margin-boxes; header/footer templates are the
// mechanism the real mint will use too.
const FOOTER = `
  <div style="width:100%; font-size:6.5pt; color:#9ca3af; text-align:center; letter-spacing:.02em;">
    Methodology: dnstool.it-help.tech/methodology · DOI: 10.5281/zenodo.19468134 · ORCID: 0009-0000-5237-9065
    &nbsp;—&nbsp; page <span class="pageNumber"></span>/<span class="totalPages"></span> · SKELETON MINT
  </div>`;
const HEADER = `
  <div style="width:100%; font-size:6.5pt; color:#9ca3af; display:flex; justify-content:space-between; padding:0 14mm;">
    <span>DNS Tool — Engineer's Report (skeleton)</span><span>google.com · TLP:AMBER</span>
  </div>`;

(async () => {
  const out = process.argv[2] || 'skeleton-mint.pdf';
  const executablePath = CANDIDATES.find(p => fs.existsSync(p));
  if (!executablePath) {
    console.error('no Chromium found; set MINT_CHROMIUM');
    process.exit(1);
  }

  let html = fs.readFileSync(path.join(__dirname, 'skeleton.html'), 'utf8');
  const owl = fs.readFileSync(
    path.join(__dirname, '../../../static/images/owl-signature-160.png'));
  html = html
    .replace('{{OWL_DATA_URI}}', `data:image/png;base64,${owl.toString('base64')}`)
    .replace('{{MINT_TIME}}', new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC');

  const browser = await puppeteer.launch({ executablePath, headless: true, args: ['--disable-gpu'] });
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    await page.pdf({
      path: out,
      printBackground: true,
      preferCSSPageSize: true,
      displayHeaderFooter: true,
      headerTemplate: HEADER,
      footerTemplate: FOOTER,
    });
    console.log('WROTE', out);
  } finally {
    await browser.close();
  }
})().catch(e => { console.error('FAIL', e.message); process.exit(1); });
