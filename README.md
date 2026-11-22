# Reverse Proxy Manager

A [Calagopus Panel](https://calagopus.com) extension that lets users put a domain in front of one
of their server's ports through **Nginx Proxy Manager** or **[NPMplus](https://github.com/ZoeyVid/NPMplus)**,
with automatic **Let's Encrypt** certificates. Users add their own domain (or pick a managed
subdomain), choose a port, done.

Package name: `dev.caloptreyx.reverseproxy` · Requires panel `>=1.2.10` · Tested with Nginx Proxy
Manager 2.15 (2.10+ supported) and NPMplus 2026-07-24-r1 plus its September 2026 development
builds (the flavor is detected automatically)

## What your users get

- Custom domains or managed subdomains, pointed at any of the server's allocations
- Automatic HTTPS with Let's Encrypt, their own uploaded certificate, or plain HTTP only
- WebSockets, caching, HTTP/2, HSTS, force-HTTPS and exploit blocking per proxy
- Optional custom nginx snippets (admin opt-in, [allowlisted directives](#custom-nginx-snippets))
- Clear status at a glance - *live*, *issuing*, *waiting for DNS* or *failed* with a readable reason
- Retry themselves instead of opening a ticket

## What you get

- Per-server proxy limit (`feature_limits.proxies`), allowed domain suffixes and blocked patterns
- Granular permissions and full activity logging
- Fleet view of every proxy across every server, with a failing count
- Reconcile tool to spot and fix drift between the panel and the proxy
- Per-node forward host overrides for NAT'd nodes
- Let's Encrypt rate-limit protection: DNS is checked before a certificate is requested, attempts
  are capped (10 per hour, 3 per domain per week), failures back off, and existing certificates
  (including wildcards) can be reused - so bad DNS can't burn your quota
- Never touches proxy hosts or certificates it doesn't own: every host it creates carries an
  ownership marker that is checked before any change

## Automated

- A background worker issues certificates one at a time and retries with backoff
- A background sync keeps the proxy in step with the panel, fixes drift, tracks certificate
  expiry, renews certificates NPM failed to renew and cleans up orphans it owns
- Deleted servers take their proxies with them; removed ports disable the proxy until a new port
  is chosen; transfers update the forward target
- Remote deletions that fail are queued and retried

## Subdomain Manager integration

With the [Subdomain Manager](https://github.com/Caloptreyx/Subdomain-Manager) extension
installed and enabled, users can create proxies directly on your managed domains. DNS records are
created automatically, Cloudflare zones use DNS-01 validation with the zone's API token, and
reserved names and existing subdomains are respected.

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

   **NPMplus:** use an `https://` URL (e.g. `https://npmplus:81`) and turn on **Accept self-signed
   certificate** unless you gave NPMplus a trusted certificate via `DEFAULT_CERT_ID`. New NPMplus
   users start with every permission hidden - set proxy hosts and certificates to *manage* (access
   lists at least *view*). NPMplus registers the Let's Encrypt account with its `ACME_EMAIL`, so
   the user's email doesn't matter. It always enables WebSockets and HTTP/2 and has no caching or
   exploit blocking, so those proxy options have no effect there.
3. Set the **DNS target**: the public IP or hostname of the NPM server. Users are told to point
   their domains here, and HTTP-validated certificates are only requested once a domain resolves
   to it.
4. Give servers a proxy limit (default for new servers in the settings, or per server under
   feature limits).

Tabs:

- **Settings** - connection, certificates, domain rules, user permissions, defaults for new
  proxies and the background sync
- **Nodes** - forward host overrides for nodes behind NAT or on a private network
- **Proxies** - every proxy on the panel, with status filter, retry and delete
- **Reconcile** - compare the panel with NPM and fix drift, plus the queue of pending remote
  deletions

Permissions: server `proxies.read|create|update|delete`, admin `proxies.read|manage`.

### Custom nginx snippets

With **Allow custom nginx configuration** on, users can add a snippet to each proxy. Only these
directives are accepted; anything else is rejected. Snippets can't read or write files on the NPM
host (`root`, `alias`, `include`, `*_store`, `*_log`, `ssl_*`, Lua/JS/Perl, ...), and they can't
send requests anywhere but the server's allocation: `proxy_pass` and the other `*_pass`
directives, `upstream`, `resolver`, subrequests (`mirror`, `auth_request`, `error_page`, SSI) and
`set` (NPM's default location proxies to the `$server`/`$port` variables) are all refused.

- blocks: `location`, `if`
- headers: `add_header`, `add_trailer`, `more_set_headers`, `more_clear_headers`,
  `more_set_input_headers`, `more_clear_input_headers`, `proxy_set_header`, `proxy_hide_header`,
  `proxy_pass_header`, `proxy_ignore_headers`, `proxy_cookie_domain`, `proxy_cookie_path`,
  `proxy_cookie_flags`, `proxy_redirect`, `real_ip_header`, `set_real_ip_from`,
  `real_ip_recursive`, `ignore_invalid_headers`, `underscores_in_headers`, `server_tokens`
- proxying (to the server's allocation only): `proxy_http_version`, `proxy_method`,
  `proxy_set_body`, `proxy_pass_request_body`, `proxy_pass_request_headers`,
  `proxy_intercept_errors`, `proxy_next_upstream`, `proxy_next_upstream_timeout`,
  `proxy_next_upstream_tries`, `proxy_ssl_name`, `proxy_ssl_server_name`
- timeouts and buffering: `proxy_connect_timeout`, `proxy_read_timeout`, `proxy_send_timeout`,
  `proxy_buffering`, `proxy_buffer_size`, `proxy_buffers`, `proxy_busy_buffers_size`,
  `proxy_request_buffering`, `proxy_max_temp_file_size`, `client_max_body_size`,
  `client_body_buffer_size`, `client_body_timeout`, `client_header_buffer_size`,
  `client_header_timeout`, `large_client_header_buffers`, `keepalive_requests`,
  `keepalive_timeout`, `send_timeout`, `chunked_transfer_encoding`
- content: `gzip`, `gzip_comp_level`, `gzip_disable`, `gzip_min_length`, `gzip_proxied`,
  `gzip_types`, `gzip_vary`, `sub_filter`, `sub_filter_once`, `sub_filter_types`,
  `sub_filter_last_modified`, `charset`, `default_type`, `expires`, `etag`, `if_modified_since`
- access and rewrites: `allow`, `deny`, `satisfy`, `return`, `rewrite`, `break`

Snippets are parsed the way nginx parses them, so quoting a directive name or hiding it behind a
comment doesn't get past the check, and a snippet must be complete (closed quotes, braces and
statements). A `location` block in a snippet doesn't proxy (it can't use `proxy_pass`), so it is
only useful for `return` or `deny` rules. Stored snippets that no longer pass (for example ones
with `proxy_pass` or `set`, allowed up to v0.1.5) are left out when the proxy is pushed to NPM.

### Screenshot

![Settings](docs/screenshots/settings.png)

## API

- `GET|POST /api/client/servers/{server}/reverse-proxies`,
  `PATCH|DELETE .../reverse-proxies/{proxy}`, `POST .../reverse-proxies/{proxy}/retry`
- `GET|PUT /api/admin/extensions/dev.caloptreyx.reverseproxy/settings`,
  `POST .../connection/test`
- `GET .../proxies`, `POST .../proxies/{proxy}/retry`, `DELETE .../proxies/{proxy}`
- `GET .../nodes`, `PUT .../nodes/{node}`
- `GET .../reconcile`, `POST .../reconcile/fix`, `GET .../cleanup`, `DELETE .../cleanup/{task}`

Full schemas are in the panel's OpenAPI document once installed.

## Support

Need help or want to request a feature? Join the [Caloptreyx Discord](https://discord.gg/4qjMWU7S8x).

## License

MIT
