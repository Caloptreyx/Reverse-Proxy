import { faShieldHalved } from '@fortawesome/free-solid-svg-icons';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { z } from 'zod';
import type { ContextMenuItem } from '@/elements/overlays/ContextMenu.tsx';
import { serverAllocationSchema } from '@/lib/schemas/server/allocations.ts';
import { useServerCan } from '@/plugins/usePermissions.ts';
import { useServerStore } from '@/stores/server.ts';
import { getServerProxies } from '../api.ts';
import ProxyModal from '../pages/server/ProxyModal.tsx';
import { useExtTranslations } from '../translations.ts';

export default function AllocationProxyAction({
  items,
  allocation,
}: {
  items: ContextMenuItem[];
  allocation: z.infer<typeof serverAllocationSchema>;
}) {
  const { t: tExt } = useExtTranslations();
  const { server } = useServerStore();
  const canCreate = useServerCan('proxies.create');
  const [opened, setOpened] = useState(false);

  const { data, refetch } = useQuery({
    queryKey: ['dev.caloptreyx.reverseproxy', 'server', server.uuid, 'proxies'],
    queryFn: () => getServerProxies(server.uuid),
    enabled: canCreate,
  });

  const label = tExt('pages.server.button.create', {});

  const item: ContextMenuItem = {
    type: 'action',
    icon: faShieldHalved,
    label,
    onClick: () => setOpened(true),
    color: 'gray',
    canAccess: canCreate,
    disabled: !data?.configured || data.proxies.length >= data.limit,
  };
  const existing = items.find((entry) => entry.type === 'action' && entry.label === label);

  if (existing) {
    Object.assign(existing, item);
  } else {
    items.push(item);
  }

  if (!data) {
    return null;
  }

  return (
    <ProxyModal
      opened={opened}
      onClose={() => setOpened(false)}
      serverUuid={server.uuid}
      options={data.options}
      allocationUuid={allocation.uuid}
      onSaved={refetch}
    />
  );
}
