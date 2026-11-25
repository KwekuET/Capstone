// classify.js — rule-based labeling of honeypot traffic.
// Usage: node classify.js        (reads logs/access.log, writes results/)
// Labels: mass_scanning, content_discovery, tech_probing, benign_crawler, site_visit, unknown

const fs = require("fs");

// Your own IPs (your test visits are not attacks). Add more, comma-separated, with MY_IPS=...
const MY_IPS = ["71.31.239.158", "127.0.0.1", "::1"]
  .concat((process.env.MY_IPS || "").split(",").map(s => s.trim()).filter(Boolean));

// ---------- RULES ----------

// Known, self-identified crawlers (user agents can be faked, so this means "claims to be")
const CRAWLER_UA = /(ClaudeBot|Claude-User|Googlebot|bingbot|DuckDuckBot|YandexBot|Baiduspider|Applebot|GPTBot|OAI-SearchBot|PerplexityBot|AhrefsBot|SemrushBot|MJ12bot|DotBot|PetalBot|facebookexternalhit|Twitterbot|LinkedInBot)/i;

// Scanner tools that name themselves
const SCANNER_UA = /(zgrab|masscan|nmap|censys|expanse|paloalto|internet-measurement|l9explore|l9tcpid|httpx|nuclei|zmap|shodan|netcraft|ModatScanner|Go-http-client|python-requests|python-urllib|aiohttp|curl|wget|libwww|okhttp|Java\/|fasthttp)/i;

// Tech probing: software this site does NOT run (it's Node, so any .php is a probe)
const TECH_PATHS = [
  /\.php(\?|$|\/)/i, /\/wp-/i, /wordpress/i, /xmlrpc/i, /phpmyadmin/i, /\/pma\b/i,
  /\/cgi-bin/i, /\/actuator/i, /\/solr/i, /\/vendor\/phpunit/i, /\/boaform/i, /\/HNAP1/i,
  /\/owa\b/i, /\/ecp\b/i, /\/remote\/login/i, /\/geoserver/i, /\/manager\/html/i,
  /jenkins/i, /\/druid/i, /\/telescope/i, /\/console\b/i, /\/autodiscover/i,
  /\/administrator/i, /\/wp-admin/i, /\.aspx?(\?|$)/i, /\.jsp(\?|$)/i, /\/api\/v1\/pods/i,
  /\/developmentserver/i, /\/sdk\b/i, /\/ReportServer/i, /\/Telerik/i
];

// Content discovery: hunting for hidden/sensitive files and folders
const DISCOVERY_PATHS = [
  /\/\.env/i, /\/\.git/i, /\/\.svn/i, /\/\.aws/i, /\/\.ssh/i, /\/\.DS_Store/i, /\/\.htaccess/i,
  /\/\.vscode/i, /\/\.idea/i, /\/backup/i, /\/internal/i, /\/robots\.txt/i, /\/sitemap\.xml/i,
  /\.(sql|bak|old|zip|tar|gz|7z|rar|swp|log|ini|conf|config|yml|yaml|json)(\?|$)/i,
  /\/(admin|config|configs|db|database|dump|private|secret|old|test|tmp|temp|debug|server-status|server-info)\b/i
];

const isRawIpHost = h => !h || /^\[?[0-9a-f.:]+\]?(:\d+)?$/i.test(h);
const pathOnly = p => (p || "").split("?")[0];
const SITE_PAGES = new Set(["/", "/index.html", "/login", "/style.css", "/favicon.ico", "/forgot-password",
  "/forgot-password.html", "/dashboard", "/dashboard.html", "/admin.html", "/billing.html", "/client.html", "/logout"]);

// ---------- READ LOG ----------

const lines = fs.readFileSync(__dirname + "/logs/access.log", "utf8").split("\n").filter(Boolean);
const all = [];
let bad = 0;
for (const line of lines) {
  try { all.push(JSON.parse(line)); } catch { bad++; }
}
const requests = all.filter(e => e.type === "request" && !MY_IPS.includes(e.ip));

// Per-IP behavior (content discovery is often a burst of many paths, mostly 404s)
const perIp = {};
for (const r of requests) {
  const s = (perIp[r.ip] = perIp[r.ip] || { total: 0, paths: new Set(), notFound: 0 });
  s.total++; s.paths.add(pathOnly(r.path)); if (r.status === 404) s.notFound++;
}
const isBurstIp = ip => {
  const s = perIp[ip];
  return s.paths.size >= 8 && s.notFound / s.total >= 0.5;
};

// ---------- LABEL ----------

function label(r) {
  const p = pathOnly(r.path);
  const ua = r.userAgent || "";
  const host = r.headers ? r.headers.host : "";

  if (CRAWLER_UA.test(ua)) return ["benign_crawler", "self-identified crawler user agent"];
  if (TECH_PATHS.some(re => re.test(p))) return ["tech_probing", "path for software this site does not run"];
  if (DISCOVERY_PATHS.some(re => re.test(p))) return ["content_discovery", "hidden or sensitive file/folder path"];
  if (r.status === 404 && isBurstIp(r.ip)) return ["content_discovery", "part of a many-path burst of 404s from one IP"];
  if (p === "/" || p === "") {
    if (SCANNER_UA.test(ua)) return ["mass_scanning", "scanner tool user agent on the root page"];
    if (isRawIpHost(host)) return ["mass_scanning", "root page requested by raw IP (no domain)"];
    if (perIp[r.ip].total <= 2) return ["mass_scanning", "single hit on the root page, then left"];
  }
  if (/(censys|zgrab|masscan|expanse|internet-measurement|shodan|netcraft|ModatScanner|paloalto)/i.test(ua)) return ["mass_scanning", "known internet-wide scanning service"];
  if (SCANNER_UA.test(ua) && isRawIpHost(host)) return ["mass_scanning", "scanner user agent hitting raw IP"];
  if (SITE_PAGES.has(p) && !SCANNER_UA.test(ua)) return ["site_visit", "normal page of the site"];
  return ["unknown", "no rule matched"];
}

const labeled = requests.map(r => {
  const [category, reason] = label(r);
  return {
    time: r.time, ip: r.ip, method: r.method, path: r.path, status: r.status,
    userAgent: r.userAgent, host: r.headers ? r.headers.host : "", category, reason, labeledBy: "rule"
  };
});

// ---------- BREADCRUMB DEPTH (how far each IP followed the trail) ----------

const depth = {};
for (const e of all) {
  if (MY_IPS.includes(e.ip)) continue;
  if (e.type === "bait") depth[e.ip] = Math.max(depth[e.ip] || 0, e.step);
  if (e.type === "login" && e.honeytoken) depth[e.ip] = Math.max(depth[e.ip] || 0, 5);
}
const logins = all.filter(e => e.type === "login" && !MY_IPS.includes(e.ip));

// ---------- SUMMARY ----------

const count = (arr, key) => {
  const m = {};
  arr.forEach(x => (m[key(x)] = (m[key(x)] || 0) + 1));
  return Object.entries(m).sort((a, b) => b[1] - a[1]);
};

const cats = ["mass_scanning", "content_discovery", "tech_probing", "benign_crawler", "site_visit", "unknown"];
const byCat = Object.fromEntries(cats.map(c => [c, labeled.filter(x => x.category === c)]));
const times = labeled.map(x => x.time).sort();

let out = "";
const say = s => (out += s + "\n");
say("HONEYPOT TRAFFIC SUMMARY");
say(`Log lines: ${lines.length} (unreadable: ${bad})   Requests analyzed (own IPs removed): ${labeled.length}`);
say(`Unique IPs: ${Object.keys(perIp).length}   Period: ${times[0] || "-"}  to  ${times[times.length - 1] || "-"}`);
say("");
say("Category              Requests   %      Unique IPs");
for (const c of cats) {
  const n = byCat[c].length;
  const pct = labeled.length ? ((100 * n) / labeled.length).toFixed(1) : "0.0";
  say(`${c.padEnd(20)}  ${String(n).padStart(8)}   ${pct.padStart(5)}  ${String(new Set(byCat[c].map(x => x.ip)).size).padStart(10)}`);
}
for (const c of ["mass_scanning", "content_discovery", "tech_probing"]) {
  say(`\nTop paths — ${c}:`);
  count(byCat[c], x => pathOnly(x.path)).slice(0, 10).forEach(([k, v]) => say(`  ${String(v).padStart(5)}  ${k}`));
}
say("\nTop user agents (all non-own traffic):");
count(labeled, x => (x.userAgent || "(none)").slice(0, 90)).slice(0, 10).forEach(([k, v]) => say(`  ${String(v).padStart(5)}  ${k}`));
say("\nBreadcrumb depth (deepest step reached per IP; 1=robots.txt 3=backup 4=.env 5=honeytoken login 6=internal file):");
count(Object.entries(depth), ([, d]) => "step " + d).sort().forEach(([k, v]) => say(`  ${k}: ${v} IPs`));
say(`\nLogin attempts: ${logins.length}   using a planted honeytoken: ${logins.filter(l => l.honeytoken).length}   successful: ${logins.filter(l => l.success).length}`);

// ---------- WRITE FILES ----------

fs.mkdirSync(__dirname + "/results", { recursive: true });
fs.writeFileSync(__dirname + "/results/labeled.json", JSON.stringify(labeled, null, 2));
fs.writeFileSync(__dirname + "/results/unknown.json", JSON.stringify(byCat.unknown, null, 2));
fs.writeFileSync(__dirname + "/results/summary.txt", out);

// CSV of category counts (for a chart)
fs.writeFileSync(__dirname + "/results/category_counts.csv",
  "category,requests,unique_ips\n" + cats.map(c => `${c},${byCat[c].length},${new Set(byCat[c].map(x => x.ip)).size}`).join("\n") + "\n");

// Random sample for manual checking (step 4: measure accuracy)
const pool = labeled.filter(x => x.category !== "unknown");
const sample = pool.sort(() => Math.random() - 0.5).slice(0, 30);
const esc = v => '"' + String(v || "").replace(/"/g, '""') + '"';
fs.writeFileSync(__dirname + "/results/manual_check.csv",
  "time,ip,method,path,status,userAgent,category,reason,correct(Y/N)\n" +
  sample.map(x => [x.time, x.ip, x.method, x.path, x.status, x.userAgent, x.category, x.reason, ""].map(esc).join(",")).join("\n") + "\n");

console.log(out);
console.log(`Wrote results/summary.txt, labeled.json, unknown.json (${byCat.unknown.length}), category_counts.csv, manual_check.csv`);
