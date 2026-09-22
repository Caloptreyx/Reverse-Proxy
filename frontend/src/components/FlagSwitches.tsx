import { SimpleGrid } from '@mantine/core';
import Switch from '@/elements/input/Switch.tsx';
import { PROXY_FLAGS, type ProxyFlags } from '../api.ts';
import { useExtTranslations } from '../translations.ts';

export default function FlagSwitches({
  value,
  onChange,
  disabled,
}: {
  value: ProxyFlags;
  onChange: (flags: ProxyFlags) => void;
  disabled?: boolean;
}) {
  const { t: tExt } = useExtTranslations();

  return (
    <SimpleGrid cols={{ base: 1, sm: 2 }} spacing='md'>
      {PROXY_FLAGS.map((flag) => (
        <Switch
          key={flag}
          label={tExt(`flags.${flag}`, {})}
          description={tExt(`flags.${flag}Description`, {})}
          checked={value[flag]}
          onChange={(e) => onChange({ ...value, [flag]: e.target.checked })}
          disabled={disabled || (flag === 'hstsSubdomains' && !value.hsts)}
        />
      ))}
    </SimpleGrid>
  );
}
