import { faRotateRight, faSearch, faTrash } from '@fortawesome/free-solid-svg-icons';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { Center } from '@mantine/core';
import { useState } from 'react';
import { httpErrorToHuman } from '@/api/axios.ts';
import Badge from '@/elements/data-display/Badge.tsx';
import Table, { TableData, TableRow } from '@/elements/data-display/Table.tsx';
import TableLink from '@/elements/data-display/TableLink.tsx';
import Select from '@/elements/input/Select.tsx';
import TextInput from '@/elements/input/TextInput.tsx';
import Group from '@/elements/layout/Group.tsx';
import ContextMenu, { ContextMenuToggle } from '@/elements/overlays/ContextMenu.tsx';
import FormattedTimestamp from '@/elements/time/FormattedTimestamp.tsx';
import Code from '@/elements/typography/Code.tsx';
import Text from '@/elements/typography/Text.tsx';
import { useSearchablePaginatedTable } from '@/plugins/resource/useSearchablePaginatedTable.ts';
import { useAdminCan } from '@/plugins/usePermissions.ts';
import { useToast } from '@/providers/ToastProvider.tsx';
import { deleteAdminProxy, getAdminProxies, type ProxyStatus, proxyStatusSchema, retryAdminProxy } from '../../api.ts';
import StatusBadge from '../../components/StatusBadge.tsx';
import { useExtTranslations } from '../../translations.ts';

export default function ProxiesTab() {
  const { t: tExt } = useExtTranslations();
  const { addToast } = useToast();
  const canManage = useAdminCan('proxies.manage');

  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [failing, setFailing] = useState(0);

  const { data, loading, error, search, setSearch, setPage, refetch } = useSearchablePaginatedTable({
    queryKey: ['dev.caloptreyx.reverseproxy', 'admin', 'proxies', status],
    deps: [status],
    fetcher: async (page, search) => {
      const result = await getAdminProxies(page, search, status);
      setFailing(result.failing);
      return result.proxies;
    },
    refetchInterval: 15000,
  });

  const run = async (action: () => Promise<void>) => {
    try {
      await action();
      refetch();
    } catch (msg) {
      addToast(httpErrorToHuman(msg), 'error');
    }
  };

  return (
    <>
      <Group justify='space-between' mb='md'>
        <Badge color={failing > 0 ? 'red' : 'green'} size='lg'>
          {tExt('pages.admin.proxies.failing', { count: failing })}
        </Badge>
        <Group>
          <Select
            placeholder={tExt('pages.admin.proxies.allStatuses', {})}
            data={proxyStatusSchema.options.map((value) => ({ value, label: tExt(`status.${value}`, {}) }))}
            value={status}
            onChange={(value) => setStatus(value as ProxyStatus | null)}
            clearable
            w={200}
          />
          <TextInput
            placeholder={tExt('pages.admin.proxies.search', {})}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            leftSection={<FontAwesomeIcon icon={faSearch} />}
            w={260}
          />
        </Group>
      </Group>

      <Table
        columns={[
          tExt('pages.server.table.domain', {}),
          tExt('pages.admin.proxies.server', {}),
          tExt('pages.server.table.target', {}),
          tExt('pages.server.table.status', {}),
          tExt('pages.server.table.certificate', {}),
          tExt('pages.server.table.created', {}),
          '',
        ]}
        loading={loading}
        error={error}
        pagination={data}
        onPageSelect={setPage}
        empty={
          <Center py='lg'>
            <Text c='dimmed'>{tExt('pages.admin.proxies.empty', {})}</Text>
          </Center>
        }
      >
        {data?.data.map((proxy) => (
          <ContextMenu
            key={proxy.uuid}
            items={[
              {
                type: 'action',
                icon: faRotateRight,
                label: tExt('pages.server.button.retry', {}),
                onClick: () => run(() => retryAdminProxy(proxy.uuid)),
                color: 'gray',
                canAccess: canManage && proxy.status !== 'live',
              },
              {
                type: 'action',
                icon: faTrash,
                label: tExt('pages.server.button.delete', {}),
                onClick: () => run(() => deleteAdminProxy(proxy.uuid)),
                color: 'red',
                canAccess: canManage,
              },
            ]}
          >
            {({ items, openMenu }) => (
              <TableRow
                onContextMenu={(e) => {
                  e.preventDefault();
                  openMenu(e.clientX, e.clientY);
                }}
              >
                <TableData>
                  <Code>{proxy.domain}</Code>
                </TableData>
                <TableData>
                  <TableLink to={`/admin/servers/${proxy.server.uuid}`}>{proxy.server.name}</TableLink>
                  <Text size='xs' c='dimmed'>
                    {proxy.server.owner}
                  </Text>
                </TableData>
                <TableData>
                  {proxy.allocation ? (
                    <Code>
                      {proxy.forwardScheme}://{proxy.allocation.ipAlias ?? proxy.allocation.ip}:{proxy.allocation.port}
                    </Code>
                  ) : (
                    '-'
                  )}
                </TableData>
                <TableData>
                  <StatusBadge proxy={proxy} />
                </TableData>
                <TableData>
                  {tExt(`pages.server.certificate.${proxy.certificateMode}`, {})}
                  {proxy.certificateExpires && (
                    <Text size='xs' c='dimmed'>
                      {tExt('pages.server.certificate.expires', {
                        date: proxy.certificateExpires.toLocaleDateString(),
                      })}
                    </Text>
                  )}
                </TableData>
                <TableData>
                  <FormattedTimestamp timestamp={proxy.created} />
                </TableData>
                <ContextMenuToggle items={items} openMenu={openMenu} />
              </TableRow>
            )}
          </ContextMenu>
        ))}
      </Table>
    </>
  );
}
