# Deploy the live demo (GitHub Pages) — one page

Goal: get the dashboard online at a public URL like
`https://onlycrypto305-debug.github.io/five-surfaces-scanner/web/` — free, no server.

> Replace `onlycrypto305-debug` with your GitHub username or org (e.g. `vectorbreak`). Repo name assumed `five-surfaces-scanner`.

## 1. Create the repo and push (one time)
From inside the `five-surfaces-scanner/` folder:

```bash
git init
git add .
git commit -m "Five Surfaces Scanner — open tier + dashboard"
git branch -M main
# create an empty repo named five-surfaces-scanner on github.com first, then:
git remote add origin https://github.com/onlycrypto305-debug/five-surfaces-scanner.git
git push -u origin main
```
The included `.gitignore` keeps test scaffolding (`node_modules/`, `test.mjs`, `*.sarif`, etc.) out of the repo.

## 2. Turn on GitHub Pages (one time)
1. Repo → **Settings** → **Pages**.
2. **Build and deployment → Source: Deploy from a branch**.
3. **Branch: `main`**, **Folder: `/ (root)`** → **Save**.
4. Wait ~1 minute. Your demo is live at:
   **`https://onlycrypto305-debug.github.io/five-surfaces-scanner/web/`**

That's it. (Pages serves the whole repo; the dashboard lives at `/web/index.html`.)

### Optional — make it the prettier root URL
If you'd rather the demo be at `https://onlycrypto305-debug.github.io/five-surfaces-scanner/` (no `/web/`), copy the dashboard to the repo root:
```bash
cp web/index.html ./index.html
git add index.html && git commit -m "Serve dashboard at root" && git push
```

### Optional — custom domain (e.g. demo.vectorbreak.com)
1. Settings → Pages → **Custom domain** → enter `demo.vectorbreak.com` → Save.
2. At your DNS provider, add a **CNAME** record: `demo` → `onlycrypto305-debug.github.io`.
3. Wait for DNS, then tick **Enforce HTTPS**.

## 3. Update the CTA link
The repo links already point to `onlycrypto305-debug`. Once Pages is live, also point the CTA on vectorbreak.com ("Try the scanner") at your Pages URL.

## 4. Optional — add a screenshot
1. Open the live dashboard, click **Load sample** → **Run Scan**.
2. Screenshot the page and save it as `docs/screenshot.png`.
3. Add `![Five Surfaces Scanner dashboard](docs/screenshot.png)` under the Live demo section of `README.md`, commit, push.

---

### Why this matters
A public, interactive demo is one of the highest-signal assets for both backlinks and AI visibility — it's linkable, embeddable in Show HN / Reddit / dev.to posts, and exactly the kind of page AI assistants cite when asked for MCP-security tools. Ship it, then point every launch post at it.
