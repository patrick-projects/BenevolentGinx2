<p align="center">
  <img alt="Evilginx2 Logo" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-logo-512.png" height="160" />
  <p align="center">
    <img alt="Evilginx2 Title" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-title-black-512.png" height="60" />
  </p>
</p>

# BenevolentGinx2 (Enhanced Community Edition)

This repository is a community-enhanced fork of [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2). It adds QoL features (REST API, Botguard, notifications, obfuscation, website spoofing, AES-256 encryption, multi-domain support, named proxy profiles) while remaining fully open source. **Original work by Kuba Gretzky; this project is released under the same [BSD-3-Clause license](LICENSE).**

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

## Evilginx Pro is now available!

This is it! After over two years of development, countless delays, and hundreds of manual company verifications, concluded with multiple hurdles related to export regulations, [Evilginx Pro is finally live!](https://evilginx.com)

<p align="center">
  <a href="https://evilginx.com"><img alt="Evilginx Mastery" src="https://breakdev.org/content/images/size/w2000/2025/03/evilginx_pro_release_cover.png" height="320" /></a>
</p>



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

by other people.

## License

**evilginx2** is made by Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky)) and it's released under BSD-3 license.
