# Reverse Proxy Manager

A [Calagopus Panel](https://calagopus.com) extension that lets users put a domain in front of one
of their server's ports through **Nginx Proxy Manager**, with automatic **Let's Encrypt**
certificates. Users add their own domain (or pick a managed subdomain), choose a port, done.

Package name: `dev.caloptreyx.reverseproxy` · Requires panel `>=1.2.2` · Tested with Nginx Proxy
Manager 2.15 (2.10+ supported)

## What your users get

- Custom domains or managed subdomains, pointed at any of the server's allocations
- Automatic HTTPS with Let's Encrypt, or upload their own certificate
- WebSockets, caching, HTTP/2, HSTS, force-HTTPS and exploit blocking per proxy
- Optional custom nginx snippets (admin opt-in)
- Clear status at a glance - *live*, *issuing*, *waiting for DNS* or *failed* with a readable reason
- Retry themselves instead of opening a ticket

## What you get

- Per-server proxy limit (`feature_limits.proxies`), domain allowlist and blocked patterns
- Granular permissions and full activity logging
- Fleet view of every proxy across every server, with a failing count
- Reconcile tool to spot and fix drift between the panel and the proxy
- Per-node forward host overrides for NAT'd nodes
- Let's Encrypt rate-limit protection: DNS is checked before a certificate is requested, attempts
  are capped per hour and per domain, failures back off, and existing certificates (including
  wildcards) are reused - so bad DNS can't burn your quota
- Never touches proxy hosts or certificates it doesn't own: every host it creates carries an
  ownership marker that is checked before any change

## Automated

- A background worker issues certificates one at a time and retries with backoff
- A background sync keeps the proxy in step with the panel, tracks certificate expiry, renews
  certificates NPM failed to renew and cleans up orphans
- Deleted servers take their proxies with them; removed ports disable the proxy until a new port
  is chosen; transfers update the forward target
- Remote deletions that fail are queued and retried

## Subdomain Manager integration

With the [Subdomain Manager](https://github.com/Caloptreyx/Subdomain-Manager) extension
installed, users can create proxies directly on your managed domains. DNS records are created
automatically, Cloudflare zones use DNS-01 validation with the zone's API token, and reserved
names and existing subdomains are respected.

## Installation

Download `dev_caloptreyx_reverseproxy.c7s.zip` from the
[latest release](https://github.com/Caloptreyx/Reverse-Proxy/releases/latest) and either upload it
under **Admin → Extensions** or drop it into your heavy image's `build/extensions/` directory and
`docker compose restart web`. Extensions require the `:heavy` panel image - see the
[Calagopus docs](https://calagopus.com/docs/panel/extensions/installing-extensions).

## Configuration

**Admin → Extensions → Reverse Proxy Manager → Configure**

1. Create a dedicated user in Nginx Proxy Manager with permission to manage proxy hosts and
   certificates. Give it a **real email address** - Let's Encrypt uses it for the account - and
   keep two-factor authentication off for it.
2. Enter the NPM URL as reachable **from the panel** (e.g. `http://npm:81` or a VPN address), the
   user's email and password, and press **Test Connection**.
3. Set the **proxy targets**: the public IP(s) or hostname of the NPM server. Users are told to
   point their domains here, and certificates are only requested once a domain resolves to one of
   them.
4. Give servers a proxy limit (default for new servers in the settings, or per server under
   feature limits).

Tabs:

- **Settings** - connection, domain rules, certificate options and rate limits, defaults, the
  Subdomain Manager integration and the background sync
- **Nodes** - forward host overrides for nodes behind NAT or on a private network
- **Proxies** - every proxy on the panel, with status filter, retry and delete
- **Reconcile** - compare the panel with NPM and fix drift, plus the queue of pending remote
  deletions

Permissions: server `proxies.read|create|update|delete`, admin `proxies.read|manage`.

## API

- `GET|POST /api/client/servers/{server}/reverse-proxies`,
  `PATCH|DELETE .../reverse-proxies/{proxy}`, `POST .../reverse-proxies/{proxy}/retry`
- `GET|PUT /api/admin/extensions/dev.caloptreyx.reverseproxy/settings`,
  `POST .../connection/test`
- `GET .../proxies`, `POST .../proxies/{proxy}/retry`, `DELETE .../proxies/{proxy}`
- `GET .../nodes`, `PUT .../nodes/{node}`
- `GET .../reconcile`, `POST .../reconcile/fix`, `GET .../cleanup`, `DELETE .../cleanup/{task}`

Full schemas are in the panel's OpenAPI document once installed.

## License

MIT
