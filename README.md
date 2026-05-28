# baslevering.com

Personal site + research notes. Hugo + PaperMod, deployed via Cloudflare Pages.

## Local dev

```bash
hugo server -D
# http://localhost:1313
```

## Add post

```bash
hugo new content posts/my-post.md
# edit, set draft: false when ready
```

## Deploy

`git push origin main` → Cloudflare Pages auto-builds.

## Stack

- **Generator**: Hugo (extended)
- **Theme**: PaperMod (git submodule)
- **Hosting**: Cloudflare Pages
- **DNS / Registrar**: Cloudflare
- **Email forwarding**: Cloudflare Email Routing
