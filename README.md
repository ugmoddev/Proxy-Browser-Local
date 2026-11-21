# App 11643 — Network-Accessible Full-Stack Application

Full-stack Node.js + Express + WebSocket (`ws`) application configured to listen on `0.0.0.0:11643` for reliable local, LAN, Cloudflare Tunnel, and ngrok access.

## Configuration

`.env`:
```env
HOST=0.0.0.0
PORT=11643
DEMO_USERNAME=admin
DEMO_PASSWORD=admin123
ALLOWED_HOSTS=
VERBOSE_LOGGING=false
```

## Two origins (security)

- **App origin** `http://<host>:11643`: the browser shell, login, items API, `/ws`.
- **Proxy origin** `http://<host>:11644` (`PROXY_PORT`): proxied third-party sites (`/b/`, `/p/`, `/proxy`, `/proxy-ws`) and the proxy control API (`/api/proxy/*`).

Proxied pages run on the proxy origin, so their JavaScript cannot call the app's authenticated APIs. Both ports must be reachable by the browser.

Optional settings:
- `PROXY_PORT` (default `PORT+1`, i.e. `11644`).
- `PROXY_ORIGIN`: explicit proxy origin, e.g. `https://proxy.example.com` behind a second tunnel. Leave empty for localhost/LAN, where the shell uses the same host with `PROXY_PORT`.
- `APP_ORIGINS`: comma-separated extra origins allowed to use the proxy control API and `/proxy-ws` (for example a tunnel URL of the app).

For LAN access open both ports (`scripts/windows-firewall.ps1` does this). For tunnels, expose the proxy port through its own tunnel and set `PROXY_ORIGIN`.

## Startup

```bash
cd /home/user/app
npm install
npm start
```

## Verification & Tunnel Commands

- Localhost: `http://localhost:11643`
- Loopback: `http://127.0.0.1:11643`
- LAN: `http://<DETECTED_LAN_IP>:11643`
- Cloudflare Tunnel (app): `cloudflared tunnel --url http://127.0.0.1:11643`
- Cloudflare Tunnel (proxy, needed for remote use): `cloudflared tunnel --url http://127.0.0.1:11644`, then set `PROXY_ORIGIN` to that URL
- ngrok: `ngrok http 11643`
- Automated test suite: `npm test`
- Windows Firewall helper (Private profile only, opens 11643 and 11644): `scripts/windows-firewall.ps1`
