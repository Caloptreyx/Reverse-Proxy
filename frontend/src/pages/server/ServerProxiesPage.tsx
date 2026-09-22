import { faPlus } from '@fortawesome/free-solid-svg-icons';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { Center } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { httpErrorToHuman } from '@/api/axios.ts';
import Button from '@/elements/buttons/Button.tsx';
import { ServerCan } from '@/elements/Can.tsx';
import ServerContentContainer from '@/elements/containers/ServerContentContainer.tsx';
import Table from '@/elements/data-display/Table.tsx';
import Alert from '@/elements/feedback/Alert.tsx';
import Stack from '@/elements/layout/Stack.tsx';
import ConditionalTooltip from '@/elements/overlays/ConditionalTooltip.tsx';
import Text from '@/elements/typography/Text.tsx';
import { useServerStore } from '@/stores/server.ts';
import { getServerProxies } from '../../api.ts';
import { useExtTranslations } from '../../translations.ts';
import ProxyModal from './ProxyModal.tsx';
import ProxyRow from './ProxyRow.tsx';

export default function ServerProxiesPage() {
  const { t: tExt } = useExtTranslations();
  const { server } = useServerStore();

  const [createOpen, setCreateOpen] = useState(false);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['dev.caloptreyx.reverseproxy', 'server', server.uuid, 'proxies'],
    queryFn: () => getServerProxies(server.uuid),
    // poll while something is still in progress
    refetchInterval: (query) =>
      query.state.data?.proxies.some((proxy) => proxy.status === 'issuing' || proxy.status === 'pending_dns')
        ? 5000
        : false,
  });

  const count = data?.proxies.length ?? 0;
  const limit = data?.limit ?? 0;
  const noDomainSource = !!data && !data.options.allowCustomDomains && data.options.managedDomains.length === 0;
  const createDisabled = !data?.configured || count >= limit || noDomainSource;

  return (
    <ServerContentContainer
      title={tExt('pages.server.title', {})}
      subtitle={tExt('pages.server.subtitle', { count, limit })}
      contentRight={
        <ServerCan action='proxies.create'>
          <ConditionalTooltip
            enabled={createDisabled}
            label={
              data?.configured
                ? tExt('pages.server.tooltip.limitReached', { limit })
                : tExt('pages.server.notConfigured', {})
            }
          >
            <Button
              disabled={createDisabled}
              onClick={() => setCreateOpen(true)}
              color='blue'
              leftSection={<FontAwesomeIcon icon={faPlus} />}
            >
              {tExt('pages.server.button.create', {})}
            </Button>
          </ConditionalTooltip>
        </ServerCan>
      }
    >
      <Stack gap='md'>
        {data && !data.configured && <Alert color='yellow'>{tExt('pages.server.notConfigured', {})}</Alert>}
        {data?.configured && data.options.allowCustomDomains && data.options.proxyTargets.length > 0 && (
          <Alert color='blue'>{tExt('pages.server.dnsHint', { targets: data.options.proxyTargets.join(', ') })}</Alert>
        )}

        {data && (
          <ProxyModal
            opened={createOpen}
            onClose={() => setCreateOpen(false)}
            serverUuid={server.uuid}
            options={data.options}
            onSaved={refetch}
          />
        )}

        <Table
          columns={[
            tExt('pages.server.table.domain', {}),
            tExt('pages.server.table.target', {}),
            tExt('pages.server.table.status', {}),
            tExt('pages.server.table.certificate', {}),
            tExt('pages.server.table.created', {}),
            '',
          ]}
          loading={isLoading}
          error={error ? httpErrorToHuman(error) : null}
          pagination={{ total: count, perPage: Math.max(count, 1), page: 1, data: data?.proxies ?? [] }}
          empty={
            <Center py='lg'>
              <Text c='dimmed'>{tExt('pages.server.empty', {})}</Text>
            </Center>
          }
        >
          {data?.proxies.map((proxy) => (
            <ProxyRow
              key={proxy.uuid}
              proxy={proxy}
              serverUuid={server.uuid}
              options={data.options}
              onChanged={refetch}
            />
          ))}
        </Table>
      </Stack>
    </ServerContentContainer>
  );
}
