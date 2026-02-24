#!/usr/bin/env node
// DNS Tool — Notion Roadmap Sync
// Creates/syncs a kanban-style roadmap database in Notion
// Integration: Replit Notion connector (connection:conn_notion_01KJ83GM6TZV44W76ZEQ0C2TN8)

import { Client } from '@notionhq/client';

let connectionSettings;

async function getAccessToken() {
  if (connectionSettings && connectionSettings.settings.expires_at && new Date(connectionSettings.settings.expires_at).getTime() > Date.now()) {
    return connectionSettings.settings.access_token;
  }
  const hostname = process.env.REPLIT_CONNECTORS_HOSTNAME;
  const xReplitToken = process.env.REPL_IDENTITY
    ? 'repl ' + process.env.REPL_IDENTITY
    : process.env.WEB_REPL_RENEWAL
    ? 'depl ' + process.env.WEB_REPL_RENEWAL
    : null;
  if (!xReplitToken) throw new Error('X-Replit-Token not found');
  connectionSettings = await fetch(
    'https://' + hostname + '/api/v2/connection?include_secrets=true&connector_names=notion',
    { headers: { 'Accept': 'application/json', 'X-Replit-Token': xReplitToken } }
  ).then(r => r.json()).then(d => d.items?.[0]);
  const accessToken = connectionSettings?.settings?.access_token || connectionSettings?.settings?.oauth?.credentials?.access_token;
  if (!accessToken) throw new Error('Notion not connected');
  return accessToken;
}

async function getNotionClient() {
  const accessToken = await getAccessToken();
  return new Client({ auth: accessToken });
}

const ROADMAP_ITEMS = [
  { title: "Intelligence Confidence Audit Engine (ICAE)", status: "Done", type: "Feature", priority: "High", version: "129 Test Cases" },
  { title: "Intelligence Currency Assurance Engine (ICuAE)", status: "Done", type: "Feature", priority: "High", version: "29 Test Cases" },
  { title: "Email Header Analyzer", status: "Done", type: "Feature", priority: "High", version: "v26.20.0+" },
  { title: "Drift Engine Phases 1–2", status: "Done", type: "Feature", priority: "High", version: "v26.19.40" },
  { title: "Architecture Page", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.77–83" },
  { title: "DKIM Selector Expansion (39→81+)", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.69–70" },
  { title: "Optional Authentication (Google OAuth 2.0 PKCE)", status: "Done", type: "Feature", priority: "High", version: "v26.20.56–57" },
  { title: "Probe Network First Node", status: "Done", type: "Feature", priority: "High", version: "v26.20.0+" },
  { title: "Color Science Page (CIE Scotopic, WCAG)", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.0+" },
  { title: "Badge System (SVG, Shields.io)", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.0+" },
  { title: "Certificate Transparency Resilience", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.76" },
  { title: "Hash Integrity Audit Engine", status: "Done", type: "Feature", priority: "Medium", version: "v26.21.45" },
  { title: "Download Verification (SHA-3-512)", status: "Done", type: "Feature", priority: "Medium", version: "v26.21.49–50" },
  { title: "Glass Badge System (ICAE, Protocol, Section)", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.38–43" },
  { title: "Covert Recon Mode", status: "Done", type: "Feature", priority: "High", version: "v26.20.0+" },
  { title: "Web/DNS/Email Hosting Detection", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.43" },
  { title: "Question Branding System (dt-question)", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.70" },
  { title: "XSS Security Fix (Tooltip Safe DOM)", status: "Done", type: "Security", priority: "High", version: "v26.25.26" },
  { title: "Public Roadmap Page", status: "In Progress", type: "Feature", priority: "Medium", notes: "Kanban view of project progress at /roadmap" },
  { title: "Approach & Methodology Page", status: "In Progress", type: "Feature", priority: "Medium", notes: "Documentation of scientific rigor at /approach" },
  { title: "Visual Cohesion — Top-to-Bottom Consistency", status: "In Progress", type: "Feature", priority: "Medium", notes: "Glass treatment, question branding, token system" },
  { title: "API Access (Programmatic Analysis)", status: "Next Up", type: "Feature", priority: "High", notes: "Rate limiting, authentication, versioning" },
  { title: "CLI App (Homebrew/Binary)", status: "Next Up", type: "Feature", priority: "High", notes: "Terminal app for macOS/Linux" },
  { title: "Probe Network Second Node (Kali)", status: "Next Up", type: "Feature", priority: "High", notes: "Kali OSINT node for SMTP/TLS/DANE" },
  { title: "Multi-Probe Consensus Engine", status: "Next Up", type: "Feature", priority: "High", notes: "Cross-probe agreement analysis" },
  { title: "Personal Analysis History", status: "Backlog", type: "Feature", priority: "Medium", notes: "Per-user session tracking" },
  { title: "Drift Engine Alerts", status: "Backlog", type: "Feature", priority: "Medium", notes: "Webhook/email notifications" },
  { title: "Saved Reports", status: "Backlog", type: "Feature", priority: "Medium", notes: "Snapshot storage and user library" },
  { title: "Drift Engine Phases 3–4", status: "Backlog", type: "Feature", priority: "Medium", notes: "Timeline visualization, scheduled monitoring" },
  { title: "Globalping.io Integration", status: "Backlog", type: "Feature", priority: "Low", notes: "Distributed DNS resolution from 100+ locations" },
  { title: "Zone File Import as Drift Baseline", status: "Backlog", type: "Feature", priority: "Low", notes: "Baseline snapshot comparison" },
  { title: "Raw Intelligence API Access", status: "Backlog", type: "Feature", priority: "Low", notes: "Direct intelligence access" },
];

async function findOrCreateDatabase(notion) {
  const search = await notion.search({ query: "DNS Tool Roadmap", filter: { property: "object", value: "database" } });
  const existing = search.results.find(r => {
    const title = r.title?.[0]?.plain_text;
    return title === "DNS Tool Roadmap";
  });
  if (existing) {
    console.log("Found existing database:", existing.id);
    return existing.id;
  }

  console.log("Creating new database...");
  const db = await notion.databases.create({
    parent: { type: "page_id", page_id: await getParentPageId(notion) },
    title: [{ type: "text", text: { content: "DNS Tool Roadmap" } }],
    is_inline: false,
    properties: {
      "Title": { title: {} },
      "Status": {
        select: {
          options: [
            { name: "Backlog", color: "default" },
            { name: "Next Up", color: "yellow" },
            { name: "In Progress", color: "blue" },
            { name: "Done", color: "green" },
          ]
        }
      },
      "Type": {
        select: {
          options: [
            { name: "Feature", color: "blue" },
            { name: "Security", color: "red" },
            { name: "Bug", color: "orange" },
            { name: "Idea", color: "purple" },
          ]
        }
      },
      "Priority": {
        select: {
          options: [
            { name: "High", color: "red" },
            { name: "Medium", color: "yellow" },
            { name: "Low", color: "gray" },
          ]
        }
      },
      "Version": { rich_text: {} },
      "Notes": { rich_text: {} },
    }
  });
  console.log("Created database:", db.id);
  return db.id;
}

async function getParentPageId(notion) {
  const search = await notion.search({ query: "DNS Tool", filter: { property: "object", value: "page" } });
  if (search.results.length > 0) {
    return search.results[0].id;
  }
  const page = await notion.pages.create({
    parent: { type: "workspace", workspace: true },
    properties: { title: { title: [{ text: { content: "DNS Tool" } }] } },
  });
  console.log("Created parent page:", page.id);
  return page.id;
}

async function populateDatabase(notion, databaseId) {
  const existing = await notion.databases.query({ database_id: databaseId, page_size: 100 });
  const existingTitles = new Set(
    existing.results.map(r => r.properties.Title?.title?.[0]?.plain_text).filter(Boolean)
  );
  console.log(`Database has ${existingTitles.size} existing items`);

  let created = 0;
  for (const item of ROADMAP_ITEMS) {
    if (existingTitles.has(item.title)) continue;

    const properties = {
      "Title": { title: [{ text: { content: item.title } }] },
      "Status": { select: { name: item.status } },
      "Type": { select: { name: item.type } },
      "Priority": { select: { name: item.priority } },
    };
    if (item.version) {
      properties["Version"] = { rich_text: [{ text: { content: item.version } }] };
    }
    if (item.notes) {
      properties["Notes"] = { rich_text: [{ text: { content: item.notes } }] };
    }

    await notion.pages.create({ parent: { database_id: databaseId }, properties });
    created++;
  }
  console.log(`Created ${created} new items (${existingTitles.size} already existed)`);
}

(async () => {
  try {
    const notion = await getNotionClient();
    console.log("Notion connected");
    const databaseId = await findOrCreateDatabase(notion);
    await populateDatabase(notion, databaseId);
    console.log("Roadmap sync complete!");
    console.log(`Database ID: ${databaseId}`);
  } catch (e) {
    console.error("Error:", e.message);
    if (e.body) console.error("Details:", e.body);
    process.exit(1);
  }
})();
