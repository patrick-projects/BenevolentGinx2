# BenevolentGinx2 (Enhanced Community Edition)

Community-enhanced fork of [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2). Adds REST API, Botguard, notifications, obfuscation, website spoofing, AES-256 encryption, multi-domain support, and named proxy profiles. **Original work by Kuba Gretzky. This project is released under the same [BSD-3-Clause license](LICENSE).**

---

## Setup on Debian

Install dependencies and Go (1.16+ required):

```bash
sudo apt update
sudo apt install -y git build-essential


# Go: use system package on Debian 12, or install from go.dev on older releases
sudo apt install -y golang-go
go version   # must be 1.16 or newer
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc

```

---

## Build and Run

```bash
git clone https://github.com/patrick-projects/BenevolentGinx2.git
cd BenevolentGinx2
make build
./evilginx
```

Type `help` at the prompt for commands.

---

## Configuration and Usage

Use only for authorized testing.

### First-time config

| Step | Command | Example |
|------|--------|--------|
| Base domain | `config domain <domain>` | `config domain yourdomain.com` |
| Server IP | `config ipv4 external <ip>` | `config ipv4 external 203.0.113.10` |
| Unauthorized redirect | `config unauth_url <url>` | `config unauth_url https://example.com` |

Point DNS A records for your hostnames to this server. Then:

```
config autocert on
config
```

### Phishlets

Add `.yaml` phishlet files to the `phishlets/` directory. Then:

```
phishlets
phishlets hostname <name> <host>   # e.g. phishlets hostname o365 login.yourdomain.com
phishlets enable <name>
phishlets
```

### Lures and phishing URL

```
lures create <phishlet>
lures
lures get-url <id>
```

### Sessions

```
sessions
sessions <id>
```

### Optional: Telegram notifications

```
notify create mybot telegram
notify set mybot bot_token <TOKEN>
notify set mybot chat_id <CHAT_ID>
notify enable mybot
notify test mybot
```

Token from [@BotFather](https://t.me/BotFather). Chat ID from `https://api.telegram.org/bot<TOKEN>/getUpdates` after messaging your bot.

### Optional: REST API

```
api key <secret>
api secret_path <path>
api enable
```

Call `https://yourdomain.com/<path>/api/sessions` with header `X-Api-Key: <secret>`. See `help api`.

### Optional: Botguard

```
botguard enable
botguard js_challenge on
```

### Quick reference

| Goal | Command |
|------|--------|
| Config | `config` |
| Phishlets | `phishlets` · `phishlets hostname <name> <host>` · `phishlets enable <name>` |
| Lures | `lures` · `lures create <phishlet>` · `lures get-url <id>` |
| Sessions | `sessions` · `sessions <id>` |
| Help | `help` · `help <command>` |

Phishlets are not included; obtain from community or official sources and place in `phishlets/`. More: [help.evilginx.com](https://help.evilginx.com).

---

## Disclaimer

Evilginx can be used for nefarious purposes. This work is a demonstration of what attackers can do. Use only for legitimate penetration testing with written permission from the to-be-phished parties.

---

## License

Copyright (c) 2018-2023 Kuba Gretzky. All rights reserved.  
Redistribution and use in source and binary forms, with or without modification, are permitted under the terms of the [BSD-3-Clause license](LICENSE).  
**evilginx2** is made by Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky)). This fork retains the same license.
