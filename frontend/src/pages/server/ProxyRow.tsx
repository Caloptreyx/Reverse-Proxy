import { faPen, faRotateRight, faTrash } from '@fortawesome/free-solid-svg-icons';
import { useState } from 'react';
import { httpErrorToHuman } from '@/api/axios.ts';
import CopyOnClick from '@/elements/CopyOnClick.tsx';
import Badge from '@/elements/data-display/Badge.tsx';
import { TableData, TableRow } from '@/elements/data-display/Table.tsx';
import ConfirmationModal from '@/elements/modals/ConfirmationModal.tsx';
import ContextMenu, { ContextMenuToggle } from '@/elements/overlays/ContextMenu.tsx';
import Tooltip from '@/elements/overlays/Tooltip.tsx';
import FormattedTimestamp from '@/elements/time/FormattedTimestamp.tsx';
import Code from '@/elements/typography/Code.tsx';
import Text from '@/elements/typography/Text.tsx';
import { useServerCan } from '@/plugins/usePermissions.ts';
import { useToast } from '@/providers/ToastProvider.tsx';
import { deleteProxy, type ReverseProxy, retryProxy, type ServerProxies } from '../../api.ts';
import StatusBadge from '../../components/StatusBadge.tsx';
import { useExtTranslations } from '../../translations.ts';
import ProxyModal from './ProxyModal.tsx';

export default function ProxyRow({
  proxy,
  serverUuid,
  options,
  onChanged,
}: {
  proxy: ReverseProxy;
  serverUuid: string;
  options: ServerProxies['options'];
  onChanged: () => void;
}) {
  const { t: tExt } = useExtTranslations();
  const { addToast } = useToast();

  const [openModal, setOpenModal] = useState<'edit' | 'delete' | null>(null);
  const canUpdate = useServerCan('proxies.update');
  const canDelete = useServerCan('proxies.delete');

  const doRetry = async () => {
    try {
      await retryProxy(serverUuid, proxy.uuid);
      addToast(tExt('pages.server.toast.retrying', {}), 'success');
      onChanged();
    } catch (msg) {
      addToast(httpErrorToHuman(msg), 'error');
    }
  };

  const doDelete = async () => {
    await deleteProxy(serverUuid, proxy.uuid);
    addToast(tExt('pages.server.toast.deleted', {}), 'success');
    setOpenModal(null);
    onChanged();
  };

  return (
    <>
      <ProxyModal
        opened={openModal === 'edit'}
        onClose={() => setOpenModal(null)}
        serverUuid={serverUuid}
        options={options}
        proxy={proxy}
        onSaved={onChanged}
      />
      <ConfirmationModal
        opened={openModal === 'delete'}
        onClose={() => setOpenModal(null)}
        title={tExt('pages.server.deleteModal.title', {})}
        confirm={tExt('pages.server.button.delete', {})}
        onConfirmed={doDelete}
      >
        {tExt('pages.server.deleteModal.content', { domain: proxy.domain }).md()}
      </ConfirmationModal>

      <ContextMenu
        items={[
          {
            type: 'action',
            icon: faRotateRight,
            label: tExt('pages.server.button.retry', {}),
            onClick: doRetry,
            color: 'gray',
            canAccess: canUpdate && (proxy.status === 'failed' || proxy.status === 'pending_dns'),
          },
          {
            type: 'action',
            icon: faPen,
            label: tExt('pages.server.button.edit', {}),
            onClick: () => setOpenModal('edit'),
            color: 'gray',
            canAccess: canUpdate,
          },
          {
            type: 'action',
            icon: faTrash,
            label: tExt('pages.server.button.delete', {}),
            onClick: () => setOpenModal('delete'),
            color: 'red',
            canAccess: canDelete,
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
              <CopyOnClick content={`https://${proxy.domain}`}>
                <Code>{proxy.domain}</Code>
              </CopyOnClick>
            </TableData>

            <TableData>
              {proxy.allocation ? (
                <Code>
                  {proxy.forwardScheme}://{proxy.allocation.ipAlias ?? proxy.allocation.ip}:{proxy.allocation.port}
                </Code>
              ) : (
                <Tooltip label={tExt('pages.server.tooltip.noAllocation', {})}>
                  <Badge color='yellow'>-</Badge>
                </Tooltip>
              )}
            </TableData>

            <TableData>
              <StatusBadge proxy={proxy} />
            </TableData>

            <TableData>
              {tExt(`pages.server.certificate.${proxy.certificateMode}`, {})}
              <Text size='xs' c='dimmed'>
                {proxy.certificateExpires
                  ? tExt('pages.server.certificate.expires', { date: proxy.certificateExpires.toLocaleDateString() })
                  : tExt('pages.server.certificate.none', {})}
              </Text>
            </TableData>

            <TableData>
              <FormattedTimestamp timestamp={proxy.created} />
            </TableData>

            <ContextMenuToggle items={items} openMenu={openMenu} />
          </TableRow>
        )}
      </ContextMenu>
    </>
  );
}
