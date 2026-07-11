# Deploy the demo to Render (permanent URLs)

Goal: stop the cloudflared tunnels from rotting mid-demo. This deploys the three
services to Render, each with a stable `*.onrender.com` URL that never changes.

Everything is pre-wired: `render.yaml` defines all three services, the MCP servers
already bind `0.0.0.0:$PORT`, and the four secrets are marked `sync: false` so Render
prompts for them instead of reading them from git.

## 1. Put this folder in its own Git repo

This directory sits inside the big TrueFoundry repo. Render needs its own repo, and
we are NOT touching the Reva contribution branch. Make a fresh standalone repo from
just this folder and push it to a **private** GitHub repo:

```bash
cd ~/Desktop/TrueFoundry/pm_demo/reva-truefoundry-plugin
git init
git add .
git commit -m "Reva x TrueFoundry demo services for Render"
# create an EMPTY private repo on github.com first, then:
git remote add origin git@github.com:<you>/reva-tf-demo.git
git branch -M main
git push -u origin main
```

`.env` and `.demo-logs/` are gitignored — no secrets get pushed. Double-check:
```bash
git status --porcelain | grep -E "\.env$" && echo "STOP: .env staged" || echo "ok: no .env"
```

## 2. Create the services on Render

1. Render dashboard → **New** → **Blueprint**.
2. Connect the GitHub repo you just pushed. Render finds `render.yaml` and shows
   three services: `reva-plugin`, `billing-mcp`, `external-mcp`.
3. It prompts for the four secrets (from your local `.env`):
   - `REVA_PDP_URL`
   - `REVA_POLICYSTORE_ID`
   - `REVA_AUTH_TOKEN`
   - `TFY_API_KEY`
   Copy each value from `~/Desktop/TrueFoundry/pm_demo/reva-truefoundry-plugin/.env`.
4. **Apply** / **Create**. First build takes a few minutes.

## 3. Grab the three stable URLs

Each service page shows its URL, e.g. `https://reva-plugin-xxxx.onrender.com`.
Confirm the plugin is up:
```bash
curl https://reva-plugin-xxxx.onrender.com/healthz     # -> {"status":"ok"}
```

## 4. Paste them into TrueFoundry — ONE TIME, permanently

- Guardrails → Registry → `reva-authorization` → URL:
  `https://reva-plugin-xxxx.onrender.com/reva/authorize`
- MCP Gateway → MCP Registry → `billing-mcp` → URL:
  `https://billing-mcp-xxxx.onrender.com/mcp`
- MCP Gateway → MCP Registry → `external-mcp` → URL:
  `https://external-mcp-xxxx.onrender.com/mcp`

## 5. Verify

```bash
cd ~/Desktop/TrueFoundry/pm_demo/reva-tf-agent-app && .venv/bin/python smoke.py
```
Same green board as local — but now the URLs never change. You can stop running
`demo_up.sh` and its tunnels entirely.

## Free-plan gotcha: cold starts

A free service sleeps after ~15 min idle and takes ~40s to wake. Before presenting,
warm all three so the first real call isn't slow:
```bash
for s in reva-plugin billing-mcp external-mcp; do curl -s -o /dev/null "https://$s-xxxx.onrender.com/healthz"; done
```
(Replace `-xxxx` with your real subdomains.) If cold starts ever bite during a live
demo, upgrading just `reva-plugin` to Render's cheapest paid tier keeps it always-on.
