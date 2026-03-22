# RAVPN (Remote Access VPN Monitor)

RAVPN is a Flask-based monitoring dashboard for active Cisco FMC VPN sessions. It aggregates session data from one or more FMC instances, enriches results with WAN/country details, and pushes near-real-time updates to the UI over WebSockets.

## What this app does

- Polls FMC active session data every 30 seconds (default).
- Supports multiple FMCs with per-FMC user counts.
- Shows active VPN users with assigned IP, login time, WAN IP, country, and group policy.
- Supports policy display-name mapping via environment variables.
- Provides manual refresh and live updates through Socket.IO.
- Supports authentication modes:
	- OIDC (primary)
	- SAML (optional)
	- Debug mode (auth disabled, local/dev only)

## Project structure

```
ravpn/
├── app.py                # Main Flask + Socket.IO app, FMC polling, API routes
├── auth.py               # OIDC/SAML auth blueprint and authorization logic
├── templates/index.html  # Dashboard UI
├── static/               # Static assets (logo, favicon, etc.)
├── Dockerfile            # Container image build
├── docker-compose.yml    # Local container runtime
├── AUTH_SETUP.md         # Detailed authentication setup guide
├── .env.example          # Production-oriented environment template
├── .env.debug            # Debug/local template
└── run_debug.sh          # Helper script for debug startup
```

## Requirements

- Python 3.12+ (recommended)
- Network connectivity to configured FMC hosts
- Valid FMC API credentials
- (If auth enabled) OIDC or SAML IdP configuration

## Quick start (local debug mode)

Debug mode is the fastest way to validate functionality locally.

1. Create env file:

```bash
cp .env.debug .env
```

2. Edit `.env` and set at least:

```bash
FMC1_HOST=<your-fmc-host>
FMC1_USERNAME=<username>
FMC1_PASSWORD=<password>
```

3. Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

4. Run app:

```bash
python3 app.py
```

Or use helper script:

```bash
chmod +x run_debug.sh
./run_debug.sh
```

5. Open:

- `http://localhost:5001`

## Quick start (Docker Compose)

1. Create and configure `.env` (start from `.env.example` or `.env.debug`).
2. Start stack:

```bash
docker compose up --build -d
```

3. Access app:

- `http://127.0.0.1:5001`

4. View logs:

```bash
docker compose logs -f web
```

5. Stop stack:

```bash
docker compose down
```

## Configuration

### Core variables

| Variable | Required | Description |
|---|---|---|
| `DEBUG_MODE` | No | `True` disables auth + HTTPS requirements for local debugging |
| `SECRET_KEY` | Yes (prod) | Flask session secret; must be strong in production |
| `SSL_VERIFY` | No | `True`, `False`, or path to CA bundle for FMC HTTPS verification |
| `FMC_COUNT` | Yes | Number of FMC instances configured (`FMC1...FMCn`) |

### FMC variables (per FMC)

For each FMC index `i` from `1..FMC_COUNT`:

- `FMC{i}_HOST`
- `FMC{i}_USERNAME`
- `FMC{i}_PASSWORD`
- `FMC{i}_NAME` (optional, defaults to `FMC{i}`)

### Policy name mapping (optional)

Use:

```bash
POLICY_MAP_<InternalPolicyName>=<DisplayName>
```

Example:

```bash
POLICY_MAP_Bru_Okta_Employee=Employee
```

### Authentication variables

See `AUTH_SETUP.md` for full details.

OIDC:
- `OIDC_ENABLED=True`
- `OIDC_CLIENT_ID`
- `OIDC_CLIENT_SECRET`
- `OIDC_DISCOVERY_URL`
- `OIDC_REDIRECT_URI`
- `OIDC_ISSUER` (used for token validation/JWKS)

SAML:
- `SAML_ENABLED=True`
- `SAML_SP_ENTITY_ID`
- `SAML_SP_ASSERTION_CONSUMER_SERVICE_URL`
- `SAML_IDP_ENTITY_ID`
- `SAML_IDP_SSO_URL`
- `SAML_IDP_X509_CERT`

Authorization controls (optional):
- `AUTHORIZED_DOMAINS=example.com,partner.com`
- `AUTHORIZED_GROUPS=group1,group2`

## API endpoints

- `GET /` Dashboard page
- `GET /api/sessions` Returns current cached sessions JSON
- `POST /api/refresh` Triggers immediate data refresh
- `GET /status` Auth/session diagnostic status
- `GET /auth/callback` OIDC callback handler
- `GET /auth/logout` Logout route

WebSocket events:
- `session_update` (server → client)
- `request_update` (client → server)
- `keepalive` / `keepalive_ack`

## Production notes

- Run behind reverse proxy (Nginx, NPM, etc.) with TLS termination.
- Keep `DEBUG_MODE=False` in production.
- Use secure, rotated secrets for `SECRET_KEY`, OIDC/SAML secrets, and FMC credentials.
- Restrict `cors_allowed_origins` in `app.py` from `*` to approved origins.
- Store `.env` outside source control.

## Troubleshooting

- App exits at startup with FMC config error:
	- Check `FMC_COUNT` and required `FMC{i}_*` variables.
- No sessions shown:
	- Verify FMC credentials, FMC API reachability, and certificate settings (`SSL_VERIFY`).
- Auth redirect loops or callback errors:
	- Verify `OIDC_REDIRECT_URI`, issuer/client values, proxy headers, and clock sync.
- Session/WS disconnect behavior:
	- Ensure reverse proxy forwards `X-Forwarded-*` headers and supports WebSocket upgrade.

## Related docs

- `AUTH_SETUP.md` — Identity provider and auth configuration guide.
- `nginx/ravpn.conf` — Example Nginx reverse-proxy + TLS config.
