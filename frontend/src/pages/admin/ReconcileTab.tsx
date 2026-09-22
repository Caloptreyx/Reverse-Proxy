import { Center } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { httpErrorToHuman } from '@/api/axios.ts';
import Button from '@/elements/buttons/Button.tsx';
import { AdminCan } from '@/elements/Can.tsx';
import Badge from '@/elements/data-display/Badge.tsx';
import Table, { TableData, TableRow } from '@/elements/data-display/Table.tsx';
import TitleCard from '@/elements/data-display/TitleCard.tsx';
import Alert from '@/elements/feedback/Alert.tsx';
import Group from '@/elements/layout/Group.tsx';
import Stack from '@/elements/layout/Stack.tsx';
import FormattedTimestamp from '@/elements/time/FormattedTimestamp.tsx';
import Code from '@/elements/typography/Code.tsx';
import Text from '@/elements/typography/Text.tsx';
import { useToast } from '@/providers/ToastProvider.tsx';
import {
  deleteCleanupTask,
  type FixResult,
  fixReconcile,
  getCleanupTasks,
  getReconcile,
  type ReconcileItem,
} from '../../api.ts';
import { useExtTranslations } from '../../translations.ts';

const KIND_COLORS = {
  missing_host: 'orange',
  drift: 'yellow',
  orphan_host: 'grape',
  orphan_certificate: 'grape',
  missing_certificate: 'orange',
} as const;

export default function ReconcileTab() {
  const { t: tExt } = useExtTranslations();
  const { addToast } = useToast();

  const [items, setItems] = useState<ReconcileItem[] | null>(null);
  const [results, setResults] = useState<Map<string, FixResult>>(new Map());
  const [running, setRunning] = useState(false);
  const [fixing, setFixing] = useState<string | null>(null);

  const cleanup = useQuery({
    queryKey: ['dev.caloptreyx.reverseproxy', 'admin', 'cleanup'],
    queryFn: () => getCleanupTasks(),
  });

  const doRun = async () => {
    setRunning(true);
    try {
      setItems(await getReconcile());
      setResults(new Map());
    } catch (msg) {
      addToast(httpErrorToHuman(msg), 'error');
    }
    setRunning(false);
  };

  const doFix = async (target: string[] | 'all', key: string) => {
    setFixing(key);
    try {
      const fixed = await fixReconcile(target);
      const ok = fixed.filter((result) => result.ok).length;
      addToast(
        tExt('pages.admin.reconcile.fixed', { ok, failed: fixed.length - ok }),
        ok === fixed.length ? 'success' : 'error',
      );
      setResults(new Map([...results, ...fixed.map((result) => [result.id, result] as const)]));
      cleanup.refetch();
    } catch (msg) {
      addToast(httpErrorToHuman(msg), 'error');
    }
    setFixing(null);
  };

  return (
    <Stack gap='lg'>
      <Group justify='space-between'>
        <Text size='sm' c='dimmed'>
          {tExt('pages.admin.reconcile.description', {})}
        </Text>
        <Group>
          <Button variant='default' onClick={doRun} loading={running}>
            {tExt('pages.admin.reconcile.run', {})}
          </Button>
          <AdminCan action='proxies.manage'>
            <Button onClick={() => doFix('all', 'all')} loading={fixing === 'all'} disabled={!items?.length}>
              {tExt('pages.admin.reconcile.fixAll', {})}
            </Button>
          </AdminCan>
        </Group>
      </Group>

      {items === null ? (
        <Alert color='blue'>{tExt('pages.admin.reconcile.notRun', {})}</Alert>
      ) : items.length === 0 ? (
        <Alert color='green'>{tExt('pages.admin.reconcile.inSync', {})}</Alert>
      ) : (
        <Table
          columns={[tExt('pages.admin.reconcile.cleanupKind', {}), tExt('pages.server.table.domain', {}), '', '']}
          pagination={{ total: items.length, perPage: items.length, page: 1, data: items }}
        >
          {items.map((item) => {
            const result = results.get(item.id);
            return (
              <TableRow key={item.id}>
                <TableData>
                  <Badge color={KIND_COLORS[item.kind.kind]}>
                    {tExt(`pages.admin.reconcile.kind.${item.kind.kind}`, {})}
                  </Badge>
                </TableData>
                <TableData>{item.domain ? <Code>{item.domain}</Code> : '-'}</TableData>
                <TableData>
                  <Text size='sm'>{item.message}</Text>
                  {result && (
                    <Text size='xs' c={result.ok ? 'green' : 'red'}>
                      {result.ok ? '✓' : `✗ ${result.message ?? ''}`}
                    </Text>
                  )}
                </TableData>
                <TableData>
                  <AdminCan action='proxies.manage'>
                    <Button
                      size='xs'
                      variant='default'
                      onClick={() => doFix([item.id], item.id)}
                      loading={fixing === item.id}
                      disabled={result?.ok}
                    >
                      {tExt('pages.admin.reconcile.fix', {})}
                    </Button>
                  </AdminCan>
                </TableData>
              </TableRow>
            );
          })}
        </Table>
      )}

      <TitleCard title={tExt('pages.admin.reconcile.cleanupTitle', {})}>
        <Stack gap='sm'>
          <Text size='sm' c='dimmed'>
            {tExt('pages.admin.reconcile.cleanupDescription', {})}
          </Text>
          <Table
            columns={[
              tExt('pages.admin.reconcile.cleanupKind', {}),
              tExt('pages.admin.reconcile.cleanupAttempts', {}),
              tExt('pages.admin.reconcile.cleanupError', {}),
              tExt('pages.server.table.created', {}),
              '',
            ]}
            loading={cleanup.isLoading}
            error={cleanup.error ? httpErrorToHuman(cleanup.error) : null}
            pagination={{
              total: cleanup.data?.length ?? 0,
              perPage: Math.max(cleanup.data?.length ?? 0, 1),
              page: 1,
              data: cleanup.data ?? [],
            }}
            empty={
              <Center py='lg'>
                <Text c='dimmed'>{tExt('pages.admin.reconcile.cleanupEmpty', {})}</Text>
              </Center>
            }
          >
            {cleanup.data?.map((task) => (
              <TableRow key={task.uuid}>
                <TableData>
                  <Code>{task.kind}</Code>
                </TableData>
                <TableData>{task.attempts}</TableData>
                <TableData>
                  <Text size='sm'>{task.lastError ?? '-'}</Text>
                </TableData>
                <TableData>
                  <FormattedTimestamp timestamp={task.created} />
                </TableData>
                <TableData>
                  <AdminCan action='proxies.manage'>
                    <Button
                      size='xs'
                      variant='default'
                      color='red'
                      onClick={async () => {
                        try {
                          await deleteCleanupTask(task.uuid);
                          cleanup.refetch();
                        } catch (msg) {
                          addToast(httpErrorToHuman(msg), 'error');
                        }
                      }}
                    >
                      {tExt('pages.admin.reconcile.cleanupDrop', {})}
                    </Button>
                  </AdminCan>
                </TableData>
              </TableRow>
            ))}
          </Table>
        </Stack>
      </TitleCard>
    </Stack>
  );
}
