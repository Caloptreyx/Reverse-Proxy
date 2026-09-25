INSERT INTO settings (key, value)
SELECT 'dev.caloptreyx.reverseproxy::dns_target', COALESCE(value::jsonb ->> 0, '')
FROM settings
WHERE key = 'dev.caloptreyx.reverseproxy::proxy_targets'
ON CONFLICT (key) DO NOTHING;

INSERT INTO settings (key, value)
SELECT 'dev.caloptreyx.reverseproxy::allowed_suffixes', value
FROM settings
WHERE key = 'dev.caloptreyx.reverseproxy::allowed_domains'
ON CONFLICT (key) DO NOTHING;

DELETE FROM settings
WHERE key IN (
    'dev.caloptreyx.reverseproxy::proxy_targets',
    'dev.caloptreyx.reverseproxy::dns_preflight',
    'dev.caloptreyx.reverseproxy::allow_custom_domains',
    'dev.caloptreyx.reverseproxy::allowed_domains',
    'dev.caloptreyx.reverseproxy::max_issuances_per_hour',
    'dev.caloptreyx.reverseproxy::max_issuances_per_domain_per_week',
    'dev.caloptreyx.reverseproxy::subdomain_manager_integration',
    'dev.caloptreyx.reverseproxy::managed_dns_challenge',
    'dev.caloptreyx.reverseproxy::auto_reconcile'
);
