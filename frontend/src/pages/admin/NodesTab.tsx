import { Center } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { httpErrorToHuman } from '@/api/axios.ts';
import Button from '@/elements/buttons/Button.tsx';
import { AdminCan } from '@/elements/Can.tsx';
import Table, { TableData, TableRow } from '@/elements/data-display/Table.tsx';
import TextInput from '@/elements/input/TextInput.tsx';
import Group from '@/elements/layout/Group.tsx';
import Stack from '@/elements/layout/Stack.tsx';
import Code from '@/elements/typography/Code.tsx';
import Text from '@/elements/typography/Text.tsx';
import { useAdminCan } from '@/plugins/usePermissions.ts';
import { useToast } from '@/providers/ToastProvider.tsx';
import { getNodes, type NodeOverride, updateNode } from '../../api.ts';
import { useExtTranslations } from '../../translations.ts';
import { adminSettingsQueryKey } from './SettingsTab.tsx';

const nodesQueryKey = ['dev.caloptreyx.reverseproxy', 'admin', 'nodes'] as const;

function NodeRow({ node, onSaved }: { node: NodeOverride; onSaved: () => void }) {
  const { t: tExt } = useExtTranslations();
  const { addToast } = useToast();
  const canManage = useAdminCan('proxies.manage');

  const [value, setValue] = useState(node.forwardHost ?? '');
  const [saving, setSaving] = useState(false);

  useEffect(() => setValue(node.forwardHost ?? ''), [node.forwardHost]);

  const doSave = async () => {
    setSaving(true);
    try {
      await updateNode(node.uuid, value.trim() || null);
      addToast(tExt('pages.admin.nodes.saved', {}), 'success');
      onSaved();
    } catch (msg) {
      addToast(httpErrorToHuman(msg), 'error');
    }
    setSaving(false);
  };

  return (
    <TableRow>
      <TableData>{node.name}</TableData>
      <TableData>{node.publicHost ? <Code>{node.publicHost}</Code> : '-'}</TableData>
      <TableData>
        <Group gap='xs' wrap='nowrap'>
          <TextInput
            placeholder='10.0.0.5'
            value={value}
            onChange={(e) => setValue(e.target.value)}
            disabled={!canManage}
            w={260}
          />
          <AdminCan action='proxies.manage'>
            <Button
              variant='default'
              onClick={doSave}
              loading={saving}
              disabled={value.trim() === (node.forwardHost ?? '')}
            >
              {tExt('pages.admin.settings.save', {})}
            </Button>
          </AdminCan>
        </Group>
      </TableData>
    </TableRow>
  );
}

export default function NodesTab() {
  const { t: tExt } = useExtTranslations();
  const queryClient = useQueryClient();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: nodesQueryKey,
    queryFn: () => getNodes(),
  });

  const onSaved = () => {
    refetch();
    queryClient.invalidateQueries({ queryKey: adminSettingsQueryKey });
  };

  return (
    <Stack gap='md'>
      <Text size='sm' c='dimmed'>
        {tExt('pages.admin.nodes.description', {})}
      </Text>
      <Table
        columns={[
          tExt('pages.admin.nodes.node', {}),
          tExt('pages.admin.nodes.publicHost', {}),
          tExt('pages.admin.nodes.forwardHost', {}),
        ]}
        loading={isLoading}
        error={error ? httpErrorToHuman(error) : null}
        pagination={{ total: data?.length ?? 0, perPage: Math.max(data?.length ?? 0, 1), page: 1, data: data ?? [] }}
        empty={
          <Center py='lg'>
            <Text c='dimmed'>{tExt('pages.admin.nodes.empty', {})}</Text>
          </Center>
        }
      >
        {data?.map((node) => (
          <NodeRow key={node.uuid} node={node} onSaved={onSaved} />
        ))}
      </Table>
    </Stack>
  );
}
