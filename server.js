// Web honeypot: a fake company employee portal (Corvane Cloud Systems) that logs everything visitors do.
// Everything on this site is FAKE. There is no real data on this server.

const express = require("express");
const fs = require("fs");

const app = express();

// Read request bodies of any kind, so every POST body gets logged
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));
app.use(express.text({ type: () => true, limit: "20kb" }));

const fake = JSON.parse(fs.readFileSync(__dirname + "/fake-data.json", "utf8"));

// ---------- LOGGING ----------

fs.mkdirSync(__dirname + "/logs", { recursive: true });
const ACCESS_LOG = __dirname + "/logs/access.log";
const ERROR_LOG = __dirname + "/logs/error.log";

// Shorten long values so attackers can't flood the log
function cut(value) {
  return String(value === undefined || value === null ? "" : value).slice(0, 1000);
}

// The visitor's real IP. Behind Caddy (HTTPS), it's in X-Forwarded-For.
function clientIp(req) {
  const ip = (req.socket.remoteAddress || "").replace("::ffff:", "");
  const forwarded = req.headers["x-forwarded-for"];
  if ((ip === "127.0.0.1" || ip === "::1") && forwarded) {
    return forwarded.split(",").pop().trim();
  }
  return ip;
}

// All headers (attacks like Log4Shell hide in headers, not just the URL)
function headersOf(req) {
  const headers = {};
  Object.keys(req.headers).slice(0, 40).forEach(name => (headers[name] = cut(req.headers[name])));
  return headers;
}

// One line of JSON per event
function log(req, type, extra) {
  const entry = {
    time: new Date().toISOString(),
    type: type,
    ip: clientIp(req),
    method: req.method,
    path: cut(req.originalUrl),
    userAgent: cut(req.headers["user-agent"]),
    ...extra
  };
  fs.appendFileSync(ACCESS_LOG, JSON.stringify(entry) + "\n");
}

// Every request is logged once it finishes, with its status code, headers and body
app.use((req, res, next) => {
  res.on("finish", () => {
    let body = req.body;
    if (body && typeof body === "object") body = Object.keys(body).length ? JSON.stringify(body) : "";
    log(req, "request", { status: res.statusCode, body: cut(body), headers: headersOf(req) });
  });
  next();
});

// ---------- HTML PAGES ----------

// Make text safe to put in a page (injected scripts are shown, not run)
function safe(text) {
  return String(text).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

// Read an HTML file and fill in its {{PLACEHOLDERS}}
function render(file, values = {}) {
  let html = fs.readFileSync(__dirname + "/" + file, "utf8");
  for (const key in values) html = html.split("{{" + key + "}}").join(values[key]);
  return html.replace(/\{\{\w+\}\}/g, ""); // remove any placeholders left empty
}

const errorBox = text => `<p class="error">${text}</p>`;

app.get("/style.css", (req, res) => res.sendFile(__dirname + "/style.css"));

// ---------- HONEYTOKENS ----------
// Each fake credential is planted in ONE place, so a login with it shows which clue was followed.

const HONEYTOKENS = [
  { username: "testuser", password: "Test@1234", source: "html_comment" },        // breadcrumb 2 (index.html)
  { username: "svc_backup", password: "Backup2026!", source: "db_backup.sql" },   // breadcrumb 3
  { username: "portaladmin", password: "Cv4ne-Adm1n-26", source: ".env" }         // breadcrumb 4
];

// Weak default login that brute-force bots might guess
const WEAK_LOGINS = [{ username: "admin", password: "admin123", source: "weak_default" }];

const SESSION = "session=emp_7c41d9";

function isLoggedIn(req) {
  return (req.headers.cookie || "").includes(SESSION);
}

// ---------- LOGIN PORTAL (breadcrumb 5) ----------

app.get(["/", "/index.html", "/login"], (req, res) => res.send(render("index.html")));

function handleLogin(req, res) {
  const body = typeof req.body === "object" ? req.body : {};
  const username = cut(body.username || body.log || body.user || body.pma_username);
  const password = cut(body.password || body.pwd || body.pass || body.pma_password);

  const token = HONEYTOKENS.find(t => t.username === username);
  const match = [...HONEYTOKENS, ...WEAK_LOGINS].find(a => a.username === username && a.password === password);

  log(req, "login", {
    username: username,
    password: password,
    success: Boolean(match),
    honeytoken: token ? token.source : ""   // which planted clue this username came from
  });

  if (match && ["/", "/login", "/index.html"].includes(req.path)) {
    res.setHeader("Set-Cookie", SESSION + "; Path=/; HttpOnly");
    return res.redirect("/dashboard");
  }
  res.status(401).send(render("index.html", { MESSAGE: errorBox("Invalid Company ID or password.") }));
}

app.post(["/", "/index.html", "/login"], handleLogin);

// Forgot password: attackers use these forms to check which accounts exist
app.get(["/forgot-password", "/forgot-password.html"], (req, res) => res.send(render("forgot-password.html")));
app.post(["/forgot-password", "/forgot-password.html"], (req, res) => {
  const account = typeof req.body === "object" ? cut(req.body.account) : "";
  log(req, "reset_request", { account: account });
  res.send(render("forgot-password.html", {
    MESSAGE: '<p class="success">If that account exists, a reset link has been sent.</p>'
  }));
});

// ---------- INSIDE THE PORTAL (what attackers reach after logging in) ----------

app.get(["/dashboard", "/dashboard.html"], (req, res) => {
  if (!isLoggedIn(req)) return res.redirect("/");

  // Search box: a target for SQL injection and script injection
  const search = typeof req.query.q === "string" ? cut(req.query.q) : "";
  if (search) log(req, "search", { query: search });

  const rows = fake.employees
    .filter(e => [e.name, e.title, e.email].join(" ").toLowerCase().includes(search.toLowerCase()))
    .map(e => `<tr><td>${e.id}</td><td>${safe(e.name)}</td><td>${safe(e.title)}</td>` +
              `<td>${safe(e.email)}</td><td>${safe(e.phone)}</td></tr>`)
    .join("\n      ");

  res.send(render("dashboard.html", {
    SEARCH: safe(search),
    ROWS: rows || "<tr><td colspan='5'>No results.</td></tr>"
  }));
});

// Admin panel, billing and client servers: only after login
["admin.html", "billing.html", "client.html"].forEach(file => {
  app.get("/" + file, (req, res) => {
    if (!isLoggedIn(req)) return res.redirect("/");
    res.send(render(file));
  });
});

app.get("/logout", (req, res) => {
  res.setHeader("Set-Cookie", "session=; Path=/; Max-Age=0");
  res.redirect("/");
});

// ---------- BREADCRUMB TRAIL ----------

// Breadcrumb 1: robots.txt "hides" the interesting folders
app.get("/robots.txt", (req, res) => {
  log(req, "bait", { bait: "robots.txt", step: 1 });
  res.type("text/plain").send("User-agent: *\nDisallow: /admin\nDisallow: /backup/\nDisallow: /internal/\n");
});

// Breadcrumb 3: backup files (folder listing + files)
const employeesCsv = "id,name,title,email,phone,salary\n" +
  fake.employees.map(e => [e.id, e.name, e.title, e.email, e.phone, e.salary].join(",")).join("\n") + "\n";

const dbBackup =
  "-- MySQL dump 10.13  Host: 10.0.0.12  Database: portal\n" +
  "CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(100), role VARCHAR(20));\n" +
  "INSERT INTO users VALUES (1,'portaladmin','$2y$10$Qe8fX0aKpZ3m1Lr7sV9uO.Jx2c6b','admin');\n" +
  "INSERT INTO users VALUES (2,'svc_backup','Backup2026!','service');  -- TODO hash this\n";

const BACKUP_FILES = { "db_backup.sql": dbBackup, "employees.csv": employeesCsv };

app.get("/backup", (req, res) => res.redirect("/backup/"));
app.get("/backup/", (req, res) => {
  log(req, "bait", { bait: "backup_listing", step: 3 });
  const links = Object.keys(BACKUP_FILES).map(f => `<li><a href="/backup/${f}">${f}</a></li>`).join("");
  res.send(`<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1><ul>${links}</ul></body></html>`);
});
Object.keys(BACKUP_FILES).forEach(file => {
  app.get("/backup/" + file, (req, res) => {
    log(req, "bait", { bait: file, step: 3 });
    res.type("text/plain").send(BACKUP_FILES[file]);
  });
});

// Breadcrumb 4: .env file with fake database + admin credentials
app.get("/.env", (req, res) => {
  log(req, "bait", { bait: ".env", step: 4 });
  res.type("text/plain").send(
    "APP_ENV=production\nAPP_URL=https://portal." + fake.domain + "\n" +
    "DB_HOST=10.0.0.12\nDB_NAME=portal\nDB_USER=portal_app\nDB_PASSWORD=Corvane#DB2026\n" +
    "ADMIN_USER=portaladmin\nADMIN_PASSWORD=Cv4ne-Adm1n-26\n");
});

// /internal files: only after login (linked from the dashboard and admin panel)
const INTERNAL_FILES = {
  "payroll_2026.csv": employeesCsv,
  "shipments_q3.csv": "shipment_id,client,destination,status\nSH-88120,Millbrook Freight,Columbus OH,Delivered\n" +
    "SH-88121,Bluewater Outfitters,Louisville KY,In transit\n",
  "users_export.csv": "company_id,role,mfa\nportaladmin,Administrator,off\nsvc_backup,Service,off\ntestuser,Staff,off\n",
  "vpn_setup.txt": "VPN server: vpn." + fake.domain + "\nGroup: staff\nTemp password: CVN-vpn-2026\n"
};
app.get(["/internal", "/internal/"], (req, res) => res.redirect(isLoggedIn(req) ? "/dashboard" : "/"));
Object.keys(INTERNAL_FILES).forEach(file => {
  app.get("/internal/" + file, (req, res) => {
    if (!isLoggedIn(req)) return res.redirect("/");
    log(req, "bait", { bait: file, step: 6 });
    res.type("text/plain").send(INTERNAL_FILES[file]);
  });
});

// ---------- COMMON TARGET PATHS (technology probing) ----------

// Fake admin / WordPress / phpMyAdmin logins that show the same login page
const ADMIN_PATHS = ["/admin", "/administrator", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/admin.php"];
app.get(ADMIN_PATHS, (req, res) => res.send(render("index.html")));
app.post(ADMIN_PATHS, handleLogin);

// ---------- EVERYTHING ELSE ----------

app.use((req, res) => res.status(404).send(render("404.html")));

// Error log: anything that crashes a request (bad JSON, too-large bodies, ...)
app.use((err, req, res, next) => {
  fs.appendFileSync(ERROR_LOG, JSON.stringify({
    time: new Date().toISOString(), ip: clientIp(req), path: cut(req.originalUrl), error: cut(err.message)
  }) + "\n");
  res.status(err.status || 500).send(render("404.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Honeypot running on port " + PORT));
