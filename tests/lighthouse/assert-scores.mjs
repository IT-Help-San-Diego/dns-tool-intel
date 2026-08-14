#!/usr/bin/env node
// Assert Lighthouse category scores meet the project's regression floor.
//
// This is the CI companion to `lighthouse.yml`. It reads the JSON report produced
// by `npx lighthouse --preset=desktop --output=json` and fails (exit 1) if any
// category drops below its floor. The floors are REGRESSION guards — the minimum
// the project will tolerate — not the A+ target. They are tightened upward as the
// site improves, never raised to match a regression.
//
// A "fair test" here means the desktop preset: no mobile network throttling, no
// mobile viewport, the page measured as a real desktop browser would measure it.
import fs from "node:fs";

const reportPath = process.argv[2] || "lighthouse-report.json";
let report;
try {
  report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
} catch (err) {
  console.error(`Could not read Lighthouse report at ${reportPath}: ${err.message}`);
  process.exit(2);
}

const categories = report.categories ?? {};

// Regression floors (0..1). Calibrated 2026-08-13 against PageSpeed Insights
// (pagespeed.web.dev, Google's hosted Lighthouse 13.4.1): DESKTOP = 99/100/100/100,
// MOBILE = 97/100/100/100. Floors sit below the real baseline with margin for the
// CI container's hardware variance (chiefly Total Blocking Time, which is
// machine-sensitive). a11y/best-practices/SEO are code-deterministic (100) so they
// are floored tighter. Tighten upward as the site improves — never raise to match a
// regression.
const floors = {
  performance: 0.9,
  accessibility: 0.95,
  "best-practices": 0.95,
  seo: 0.9,
};

let failed = false;
for (const [key, floor] of Object.entries(floors)) {
  const category = categories[key];
  const score = category?.score ?? 0;
  const pct = Math.round(score * 100);
  const mark = score >= floor ? "PASS" : "FAIL";
  console.log(`${mark.padEnd(4)} ${key.padEnd(15)} ${pct} / ${Math.round(floor * 100)}`);
  if (score < floor) {
    failed = true;
  }
}

if (failed) {
  console.error("\nLighthouse regression floor not met. Fix the regression, do not raise the floor.");
  process.exit(1);
}
console.log("\nLighthouse regression floor met.");
