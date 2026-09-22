ALTER TABLE servers ADD COLUMN reverse_proxy_limit INTEGER NOT NULL DEFAULT 0;

CREATE TABLE dev_caloptreyx_reverseproxy_proxies (
    uuid uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    server_uuid uuid NOT NULL REFERENCES servers(uuid) ON DELETE CASCADE,
    allocation_uuid uuid REFERENCES server_allocations(uuid) ON DELETE SET NULL,
    domain VARCHAR(253) NOT NULL UNIQUE,
    managed_domain_uuid uuid,
    managed_name VARCHAR(63),
    managed_dns_records JSONB NOT NULL DEFAULT '[]',
    forward_scheme VARCHAR(5) NOT NULL DEFAULT 'http',
    websockets BOOLEAN NOT NULL,
    caching BOOLEAN NOT NULL,
    http2 BOOLEAN NOT NULL,
    hsts BOOLEAN NOT NULL,
    hsts_subdomains BOOLEAN NOT NULL,
    force_https BOOLEAN NOT NULL,
    block_exploits BOOLEAN NOT NULL,
    certificate_mode VARCHAR(15) NOT NULL,
    status VARCHAR(15) NOT NULL,
    status_message TEXT,
    npm_proxy_host_id INTEGER,
    npm_certificate_id INTEGER,
    certificate_owned BOOLEAN NOT NULL DEFAULT false,
    certificate_expires TIMESTAMPTZ,
    issue_attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt TIMESTAMPTZ,
    next_attempt TIMESTAMPTZ,
    last_synced TIMESTAMPTZ,
    created TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX dev_caloptreyx_reverseproxy_proxies_server_uuid_idx
    ON dev_caloptreyx_reverseproxy_proxies (server_uuid);
CREATE INDEX dev_caloptreyx_reverseproxy_proxies_status_idx
    ON dev_caloptreyx_reverseproxy_proxies (status);
CREATE INDEX dev_caloptreyx_reverseproxy_proxies_managed_idx
    ON dev_caloptreyx_reverseproxy_proxies (managed_domain_uuid, managed_name);

CREATE TABLE dev_caloptreyx_reverseproxy_issuances (
    id BIGSERIAL PRIMARY KEY,
    domain VARCHAR(253) NOT NULL,
    success BOOLEAN NOT NULL,
    created TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX dev_caloptreyx_reverseproxy_issuances_domain_created_idx
    ON dev_caloptreyx_reverseproxy_issuances (domain, created);
CREATE INDEX dev_caloptreyx_reverseproxy_issuances_created_idx
    ON dev_caloptreyx_reverseproxy_issuances (created);

CREATE TABLE dev_caloptreyx_reverseproxy_cleanup (
    uuid uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    kind VARCHAR(31) NOT NULL,
    payload JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created TIMESTAMPTZ NOT NULL DEFAULT now()
);
