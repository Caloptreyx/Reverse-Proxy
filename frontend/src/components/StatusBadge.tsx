import Badge from '@/elements/data-display/Badge.tsx';
import Stack from '@/elements/layout/Stack.tsx';
import Tooltip from '@/elements/overlays/Tooltip.tsx';
import type { ReverseProxy } from '../api.ts';
import { useExtTranslations } from '../translations.ts';

const COLORS = {
  pending_dns: 'yellow',
  issuing: 'blue',
  live: 'green',
  failed: 'red',
} as const;

export default function StatusBadge({ proxy }: { proxy: ReverseProxy }) {
  const { t: tExt } = useExtTranslations();

  const badge = <Badge color={COLORS[proxy.status]}>{tExt(`status.${proxy.status}`, {})}</Badge>;
  if (!proxy.statusMessage && !proxy.nextAttempt) {
    return badge;
  }

  return (
    <Tooltip
      multiline
      w={360}
      label={
        <Stack gap={4}>
          {proxy.statusMessage && <span>{proxy.statusMessage}</span>}
          {proxy.nextAttempt && proxy.status !== 'live' && (
            <span>{tExt('pages.server.nextAttempt', { date: proxy.nextAttempt.toLocaleString() })}</span>
          )}
        </Stack>
      }
    >
      {badge}
    </Tooltip>
  );
}
