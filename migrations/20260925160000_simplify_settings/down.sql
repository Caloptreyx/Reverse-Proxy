INSERT INTO settings (key, value)
SELECT 'dev.caloptreyx.reverseproxy::proxy_targets',
       CASE WHEN value = '' THEN '[]' ELSE jsonb_build_array(value)::text END
FROM settings
WHERE key = 'dev.caloptreyx.reverseproxy::dns_target'
ON CONFLICT (key) DO NOTHING;

INSERT INTO settings (key, value)
SELECT 'dev.caloptreyx.reverseproxy::allowed_domains', value
FROM settings
WHERE key = 'dev.caloptreyx.reverseproxy::allowed_suffixes'
ON CONFLICT (key) DO NOTHING;

DELETE FROM settings
WHERE key IN (
    'dev.caloptreyx.reverseproxy::dns_target',
    'dev.caloptreyx.reverseproxy::allowed_suffixes'
);
