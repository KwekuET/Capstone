# Web-Based Honeypot for Analyzing Common Attack Patterns

A low-interaction web honeypot built with Node.js and Express. It looks like the employee portal of a
fictional cloud hosting company, Corvane Cloud Systems. Every request, login attempt and action is logged.
**All data on this site is fake** (generated with the Faker library).

## Files

| File | What it does |
|------|--------------|
| `server.js` | Runs the website and does all the logging |
| `index.html` | Login page (start page), with the hidden HTML comment |
| `dashboard.html` | Employee directory with a search box (after login) |
| `admin.html`, `billing.html`, `client.html` | Fake admin panel, invoices and client server list (after login) |
| `forgot-password.html` | Password reset form (logs which accounts attackers check) |
| `404.html` | "Page not found" page |
| `style.css` | Styling for every page |
| `fake-data.json` | Fake company and employee data shown on the site |
| `generate-data.js` | Makes new fake employees with Faker (`npm run generate`) |
| `classify.js` | Parses the logs, labels each request with rules, checks bot vs human, saves results (`npm run classify`) |
| `ai-label.js` | Sends the requests the rules couldn't label to an AI model (`npm run ai`) |
| `Caddyfile` | HTTPS setup (free Let's Encrypt certificate) |

## The breadcrumb trail

Each clue leads one step deeper. Each fake login is planted in only one place, so a login with it
shows exactly which clue the attacker followed (honeytokens).

| Step | Bait | Planted credential |
|------|------|--------------------|
| 1 | `/robots.txt` "hides" /admin, /backup, /internal | |
| 2 | HTML comment in the login page source | `testuser` / `Test@1234` |
| 3 | `/backup/` folder with `db_backup.sql` and `employees.csv` | `svc_backup` / `Backup2026!` |
| 4 | `/.env` with fake database + admin credentials | `portaladmin` / `Cv4ne-Adm1n-26` |
| 5 | Login portal: do stolen credentials get tried? | |

Any of these logins (plus the weak default `admin` / `admin123`) lets the attacker in. Inside is a fake
employee directory with a search box (a target for SQL injection), an admin panel, billing, a client
server list and fake shared files.

Common target paths (`/wp-login.php`, `/wp-admin`, `/phpmyadmin`, `/admin`) show the same login page.

## Logs

- `logs/access.log`: one JSON line per event. Every request (`type: "request"`) records the time, IP,
  method, path, **status code**, user agent, **all headers**, and the **request body** (so login attempts
  and POSTed payloads are captured). Extra events: `login`, `reset_request`, `bait`, `search`.
- `logs/error.log`: requests that caused an error.

HTTPS doesn't hide attacks: Caddy ends the encrypted connection on this server and passes each request to
Node, which logs it in plain text.

## Analyzing

```
npm run classify
```

It prints totals, attack categories with percentages, bot vs human counts, how far IPs followed the
breadcrumb trail, which honeytokens were used, top usernames, passwords, paths, user agents and IPs,
and requests per day. It also saves (in `results/`):

- `labeled.csv`: every request with its category (open in Excel to make charts)
- `ips.csv`: one row per IP: bot/human verdict, reasons, and breadcrumb progress
- `unmatched.json`: requests no rule matched, for the AI step
- `sample_for_manual_check.csv`: 50 random requests. Mark each label correct or not to measure accuracy

Rule categories (checked in this order): Exploit (Log4Shell), Command injection, SQL injection,
Path traversal, Credential attack, Post-login activity, Normal browsing, Technology probing,
Content discovery, Mass scanning.

AI step (needs an Anthropic API key):

```
ANTHROPIC_API_KEY=your-key npm run ai
```

It saves `results/ai_labels.csv` with a category and a one-sentence reason for each leftover request.

## Running on the Oracle server

```
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git honeypot
cd honeypot
npm install
npm run generate
sudo npm install -g pm2
pm2 start server.js --name honeypot
pm2 save
pm2 startup        (then run the command it prints, so it restarts after a reboot)
```

The site now runs on port 3000. To put it on the internet with HTTPS:

1. Point your domain's DNS **A record** to the server's public IP.
2. Open ports **80 and 443** in the Oracle security list **and** in the server's firewall:
   ```
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
   sudo netfilter-persistent save
   ```
3. Install Caddy (see caddyserver.com/docs/install, "Debian, Ubuntu"), put your domain in `Caddyfile`, then:
   ```
   sudo cp Caddyfile /etc/caddy/Caddyfile
   sudo systemctl restart caddy
   ```

Watch traffic live with `tail -f logs/access.log`.

## Safety

- Runs on a separate Oracle Cloud server, not on any personal system.
- Low-interaction: attackers only reach fake web pages, never a shell on the server.
- Nothing real to steal: all data and credentials are fake.
- Page output is escaped, so injected scripts are shown, not run.
- Admin access is by SSH key only (port 22 limited to my IP). There is no log dashboard on the internet;
  logs are read over SSH.
- `logs/` and `results/` are in `.gitignore`, so captured data is never pushed to GitHub.
