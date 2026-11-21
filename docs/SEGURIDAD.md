# Seguridad de PortAlert


## Ya implementado
| Tema | Qué hace |
|---|---|
| **Contraseñas** | Al registrarse: mínimo 8 caracteres, mayúscula, minúscula, número y carácter especial; máximo 72 bytes (límite de bcrypt); sin espacios en los extremos; rechaza contraseñas comunes y las que contienen tu correo. El login no aplica la política, para no bloquear cuentas antiguas. El frontend muestra los requisitos mientras escribes; **quien decide es el servidor**. |
| **Inyección SQL** | Todo el acceso a datos va por SQLAlchemy con parámetros enlazados; las únicas consultas "crudas" son constantes (`SELECT 1`). Los filtros y rutas usan tipos/enums (422 ante valores raros). `tests/test_sql_injection.py` prueba cargas típicas y **falla si alguien agrega SQL armado con cadenas**. |
| **Límite de peticiones** | Ventana deslizante por IP / cuenta / equipo (ver tabla abajo), con `429` + `Retry-After`. El frontend muestra una cuenta regresiva. |
| **Fuerza bruta** | Login: 5 fallos / 15 min por (correo + IP) y 20 por correo desde cualquier IP; 2FA: 5 códigos erróneos / 5 min por usuario (el código tiene solo 6 dígitos). Correo inexistente tarda lo mismo que contraseña mala (no se puede enumerar por tiempo). |
| **Cabeceras** | API: `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`; en producción también HSTS y CSP estricta. Frontend: CSP en el build + cabeceras en `vercel.json`. |
| **CORS** | Solo el origen del frontend; métodos y cabeceras mínimos; expone `Retry-After`. |
| **Tamaños** | Reportes: tope propio. Resto de POST/PUT/PATCH: 100 KB (`MAX_BODY_BYTES`). |
| **Arranque seguro** | `SECRET_KEY` de menos de 32 caracteres impide arrancar. `/docs` y `/openapi.json` se apagan con `APP_ENV=production`. |
| **Auditoría** | Eventos `registro`, `login_ok`, `login_fallido`, `totp_fallido`, `2fa_activado` en el logger `portalert.security` (sin contraseñas, tokens ni códigos; el correo va como huella). |
| **Dependencias** | `cryptography` 46.0.3 → 50.0.2 (13 avisos). Frontend: vite 7 y react-router 7 (`npm audit`: 0). |

### Límites de peticiones (editables en `app/core/ratelimit.py`, dict `LIMITES`)
`global` 300/min por IP · `login` 10/min · `register` 10/hora · `totp` 10/min · `enroll` y `enroll-token` 10/min · `installer` 20/min · `reports` 120/min por equipo · `telegram-test` 3/min · `telegram` 20/min.

## Configuración en producción (variables de entorno del backend)
```
APP_ENV=production
FRONTEND_URL=https://tu-frontend.vercel.app      # CORS y enlaces
ALLOWED_HOSTS=api.tudominio.com                   # rechaza otros Host
CLIENT_IP_HEADER=...                              # IMPORTANTE, ver abajo
```
**La IP real del cliente.** Detrás de un proxy/CDN todas las peticiones llegan con la IP del proxy: sin configurarlo, el límite por IP cuenta a *todos* los usuarios juntos y los bloquea entre sí. Indica de dónde leerla: `CLIENT_IP_HEADER=CF-Connecting-IP` (Cloudflare), `Fly-Client-IP` (Fly.io), o `TRUSTED_PROXY_HOPS=1` (usa `X-Forwarded-For`, tomando la IP que añadió tu proxy). No actives estas opciones si el backend está expuesto directamente: la cabecera se podría falsear.

## Sobre el DDoS: qué cubre y qué no
El límite de la aplicación frena fuerza bruta, scraping y ráfagas de **un** cliente. **No detiene un DDoS volumétrico**: cuando la petición llega a Python, ya consumió ancho de banda y CPU. Además los contadores viven en la memoria de cada proceso (con varios workers cada uno cuenta aparte). Para DDoS de verdad:
1. Pon Cloudflare (plan gratis sirve) delante del API y del frontend, con "Under Attack"/reglas de rate limiting en `/auth/*` y `/reports`.
2. Que el origen solo acepte tráfico del CDN (lista de IPs de Cloudflare o *authenticated origin pulls*).
3. Si usas varias instancias, mueve `SlidingWindow` a Redis (misma interfaz).
4. Vercel ya absorbe la capa del frontend; activa su Firewall/Attack Challenge Mode si lo necesitas.


