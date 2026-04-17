# Security Dashboard — lalu.dev

Dashboard de monitoreo de seguridad en tiempo real desplegado en infraestructura propia.

🔴 **Live:** [security.lalu.dev](https://security.lalu.dev)

## ¿Qué hace?

Monitorea un servidor Linux en tiempo real detectando:
- Intentos de intrusión SSH con IPs anonimizadas
- Métricas del sistema (CPU, RAM, disco, red)
- Panel interactivo para simular ataques y ver la detección en vivo

## Stack

| Capa | Tecnología |
|------|-----------|
| Backend | Python + FastAPI |
| Frontend | HTML/CSS/JS vanilla |
| Base de datos | PostgreSQL |
| Proxy | Nginx |
| Seguridad | fail2ban + UFW + Cloudflare |
| Infraestructura | Docker + Proxmox + Cloudflare Tunnel |

## Seguridad aplicada

- Rate limiting 30 req/min por IP
- IPs atacantes anonimizadas en vista pública
- Firewall UFW — solo puertos 22 y 80
- PostgreSQL restringido a localhost
- CORS restringido al dominio propio

## Arquitectura

    Internet → Cloudflare (HTTPS) → Nginx → FastAPI → PostgreSQL
                                          ↓
                                      /var/log/auth.log

## Relación con CompTIA Security+

- Domain 1 — Threats: detección de ataques SSH en tiempo real
- Domain 2 — Architecture: segmentación de red, firewall, proxy
- Domain 4 — Operations: monitoreo SIEM básico, logs, alertas

## Autor

Luis Eduardo García Jiménez — Ing. Computación, UNAM 4° semestre
lalu.dev
