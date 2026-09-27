import { SimpleGrid } from '@mantine/core';
import Switch from '@/elements/input/Switch.tsx';
import { PROXY_FLAGS, type ProxyFlags } from '../api.ts';
import { useExtTranslations } from '../translations.ts';

/** Flags that only take effect once the proxy has a certificate. */
const TLS_FLAGS: (keyof ProxyFlags)[] = ['http2', 'hsts', 'hstsSubdomains', 'forceHttps'];

export default function FlagSwitches({
  value,
  onChange,
  tls,
}: {
  value: ProxyFlags;
  onChange: (flags: ProxyFlags) => void;
  tls: boolean;
}) {
  const { t: tExt } = useExtTranslations();

  return (
    <SimpleGrid cols={{ base: 1, sm: 2 }} spacing='md'>
      {PROXY_FLAGS.filter((flag) => tls || !TLS_FLAGS.includes(flag)).map((flag) => (
        <Switch
          key={flag}
          label={tExt(`flags.${flag}`, {})}
          description={tExt(`flags.${flag}Description`, {})}
          checked={value[flag]}
          onChange={(e) => onChange({ ...value, [flag]: e.target.checked })}
          disabled={flag === 'hstsSubdomains' && !value.hsts}
        />
      ))}
    </SimpleGrid>
  );
}
