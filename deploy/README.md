# Deploying authcraft to authcraft.accumu.cc

authcraft runs on the shared accumu.cc VPS next to tacto and glossa: Caddy
terminates TLS (`conf.d/authcraft.caddy`) and proxies to the server on
`127.0.0.1:8083`, which runs as a hardened systemd service with
`DynamicUser`. See [ADR 0023](../docs/adr/0023-production-mode.md) and
[ADR 0027](../docs/adr/0027-public-deployment.md).

## One-time setup (on the VPS, as root)

1. **DNS.** Point `authcraft.accumu.cc` at the VPS (same as tacto and
   glossa). Caddy obtains the certificate on first request.
2. **Caddy root.** `/etc/caddy/Caddyfile` must exist and import `conf.d`
   (owned by the accumu.cc repo: `mise run deploy-caddy-root` there).
3. **Resend key.** A sending-only Resend API key for `accumu.cc`:

   ```sh
   install -d -m 755 /etc/authcraft
   install -m 400 /dev/stdin /etc/authcraft/resend-api-key   # paste key, Ctrl-D
   ```

4. **Clients.** Copy `deploy/clients.example.json` to
   `/etc/authcraft/clients.json` (mode 644: it holds only public metadata)
   and put in each relying party's public JWKS. The relying parties generate
   their key pairs themselves; the private keys never leave their own
   servers (see the tacto and glossa READMEs, "Sign in with authcraft").
   Until a relying party is ready, leave it out: authcraft starts with an
   empty `{"clients": []}`.
5. **Admin API (optional).** Off unless you want it:

   ```sh
   head -c 32 /dev/urandom | base64 | tr -d '\n=' | install -m 400 /dev/stdin /etc/authcraft/admin-token
   ```

   then add `LoadCredential=admin-token:/etc/authcraft/admin-token` to the
   unit.

## Deploy (from a checkout, on your machine)

```sh
mise run deploy                    # build, copy binary + unit + conf.d snippet, restart
AUTHCRAFT_HOST=root@host mise run deploy   # another host
```

The task refuses to run if the Caddy root, the Resend key, or the clients
file is missing. It never copies secrets.

## After deploying

```sh
curl -s https://authcraft.accumu.cc/.well-known/openid-configuration | head -c 300
curl -sI https://authcraft.accumu.cc/login | grep -iE 'strict-transport|x-frame|referrer'
journalctl -u authcraft -n 50 --no-pager
```

Sign up at `https://authcraft.accumu.cc/signup` with a real address and check
that the confirmation mail arrives.

## Operations

- **State** is in `/var/lib/private/authcraft`: `signing-key.pk8` (the
  Ed25519 key relying parties trust; back it up with the database) and
  `authcraft.db` (accounts, pending email links, outbox).
- **Backups:** `sqlite3 /var/lib/private/authcraft/authcraft.db ".backup '/root/authcraft-$(date +%F).db'"`
  plus a copy of `signing-key.pk8`, both kept owner-only.
- **Restart behavior:** sessions, refresh tokens, and the access-token
  revocation list are in memory; a restart signs users out of the SSO session
  and relying parties must re-authorize when their refresh tokens fail.
- **Cloudflare:** if the DNS record is proxied through Cloudflare, Caddy sees
  Cloudflare's addresses and per-client rate limits group visitors by
  Cloudflare edge. Either keep the record DNS-only, or configure Caddy
  `trusted_proxies` for Cloudflare's ranges and use `CF-Connecting-IP`.
