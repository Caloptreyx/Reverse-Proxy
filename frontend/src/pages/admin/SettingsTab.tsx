import { Center, SimpleGrid } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { type ReactNode, useEffect, useMemo, useState } from 'react';
import { httpErrorToHuman } from '@/api/axios.ts';
import Button from '@/elements/buttons/Button.tsx';
import { AdminCan } from '@/elements/Can.tsx';
import TitleCard from '@/elements/data-display/TitleCard.tsx';
import Alert from '@/elements/feedback/Alert.tsx';
import Spinner from '@/elements/feedback/Spinner.tsx';
import NumberInput from '@/elements/input/NumberInput.tsx';
import PasswordInput from '@/elements/input/PasswordInput.tsx';
import Switch from '@/elements/input/Switch.tsx';
import TagsInput from '@/elements/input/TagsInput.tsx';
import TextInput from '@/elements/input/TextInput.tsx';
import Group from '@/elements/layout/Group.tsx';
import Stack from '@/elements/layout/Stack.tsx';
import Text from '@/elements/typography/Text.tsx';
import { useAdminCan } from '@/plugins/usePermissions.ts';
import { useToast } from '@/providers/ToastProvider.tsx';
import { type ConnectionTest, type ExtensionSettings, getSettings, testConnection, updateSettings } from '../../api.ts';
import { useExtTranslations } from '../../translations.ts';

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <TitleCard title={title}>
      <Stack gap='md'>{children}</Stack>
    </TitleCard>
  );
}

export const adminSettingsQueryKey = ['dev.caloptreyx.reverseproxy', 'admin', 'settings'] as const;

function invalidRegexes(patterns: string[]): string[] {
  return patterns.filter((pattern) => {
    try {
      new RegExp(pattern);
      return false;
    } catch {
      return true;
    }
  });
}

export default function SettingsTab() {
  const { t: tExt } = useExtTranslations();
  const { addToast } = useToast();
  const queryClient = useQueryClient();
  const canManage = useAdminCan('proxies.manage');

  const { data, isLoading, error } = useQuery({
    queryKey: adminSettingsQueryKey,
    queryFn: () => getSettings(),
  });

  const [settings, setSettings] = useState<ExtensionSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<ConnectionTest | null>(null);

  useEffect(() => {
    if (data) {
      setSettings({ ...data.settings, npmSecret: '' });
    }
  }, [data]);

  const invalidPatterns = useMemo(() => invalidRegexes(settings?.blockedPatterns ?? []), [settings?.blockedPatterns]);

  if (isLoading) {
    return (
      <Center py='lg'>
        <Spinner />
      </Center>
    );
  }

  if (error || !settings || !data) {
    return <Alert color='red'>{error ? httpErrorToHuman(error) : null}</Alert>;
  }

  const update = (patch: Partial<ExtensionSettings>) => setSettings({ ...settings, ...patch });

  const doSave = async () => {
    if (invalidPatterns.length > 0) return;
    setSaving(true);
    try {
      await updateSettings({ ...settings, npmSecret: settings.npmSecret || undefined });
      addToast(tExt('pages.admin.settings.saved', {}), 'success');
      queryClient.invalidateQueries({ queryKey: adminSettingsQueryKey });
    } catch (msg) {
      addToast(httpErrorToHuman(msg), 'error');
    }
    setSaving(false);
  };

  const doTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      setTestResult(
        await testConnection({
          npmUrl: settings.npmUrl,
          npmIdentity: settings.npmIdentity,
          npmSecret: settings.npmSecret,
          requestTimeoutSeconds: settings.requestTimeoutSeconds,
        }),
      );
    } catch (msg) {
      addToast(httpErrorToHuman(msg), 'error');
    }
    setTesting(false);
  };

  const defaults = settings.defaults;

  return (
    <Stack gap='lg'>
      <Section title={tExt('pages.admin.connection.title', {})}>
        <TextInput
          withAsterisk
          label={tExt('pages.admin.connection.url', {})}
          description={tExt('pages.admin.connection.urlDescription', {})}
          placeholder='http://npm:81'
          value={settings.npmUrl}
          onChange={(e) => update({ npmUrl: e.target.value })}
          disabled={!canManage}
        />
        <SimpleGrid cols={{ base: 1, md: 2 }}>
          <TextInput
            label={tExt('pages.admin.connection.identity', {})}
            description={tExt('pages.admin.connection.identityDescription', {})}
            value={settings.npmIdentity}
            onChange={(e) => update({ npmIdentity: e.target.value })}
            disabled={!canManage}
          />
          <PasswordInput
            label={tExt('pages.admin.connection.secret', {})}
            description={
              data.hasNpmSecret
                ? tExt('pages.admin.connection.secretStored', {})
                : tExt('pages.admin.connection.secretDescription', {})
            }
            value={settings.npmSecret ?? ''}
            onChange={(e) => update({ npmSecret: e.target.value })}
            disabled={!canManage}
          />
          <TextInput
            label={tExt('pages.admin.settings.dnsTarget', {})}
            description={tExt('pages.admin.settings.dnsTargetDescription', {})}
            placeholder='proxy.example.com'
            value={settings.dnsTarget}
            onChange={(e) => update({ dnsTarget: e.target.value })}
            disabled={!canManage}
          />
          <NumberInput
            withAsterisk
            label={tExt('pages.admin.connection.timeout', {})}
            description={tExt('pages.admin.connection.timeoutDescription', {})}
            value={settings.requestTimeoutSeconds}
            onChange={(value) => update({ requestTimeoutSeconds: Math.min(300, Math.max(5, Number(value) || 30)) })}
            min={5}
            max={300}
            disabled={!canManage}
          />
        </SimpleGrid>

        {testResult && (
          <Alert
            color={testResult.ok ? 'green' : 'red'}
            title={
              testResult.ok
                ? tExt('pages.admin.connection.testOk', {
                    version: testResult.version ?? '?',
                    email: testResult.email ?? '?',
                  })
                : tExt('pages.admin.connection.testFailed', {})
            }
          >
            <Stack gap={4}>
              {testResult.checks.map((check) => (
                <div key={check.name}>
                  {check.ok ? '✓' : '✗'} {check.name}
                  {check.message ? ` - ${check.message}` : ''}
                </div>
              ))}
            </Stack>
          </Alert>
        )}

        <Group justify='flex-end'>
          <AdminCan action='proxies.manage'>
            <Button variant='default' onClick={doTest} loading={testing} disabled={!settings.npmUrl}>
              {tExt('pages.admin.connection.test', {})}
            </Button>
          </AdminCan>
        </Group>
      </Section>

      <Section title={tExt('pages.admin.settings.certificatesTitle', {})}>
        <Text size='xs' c='dimmed'>
          {tExt('pages.admin.settings.certificatesDescription', {})}
        </Text>
        <SimpleGrid cols={{ base: 1, md: 2 }}>
          <NumberInput
            withAsterisk
            label={tExt('pages.admin.settings.dnsPropagationSeconds', {})}
            description={tExt('pages.admin.settings.dnsPropagationSecondsDescription', {})}
            value={settings.dnsPropagationSeconds}
            onChange={(value) => update({ dnsPropagationSeconds: Math.min(600, Math.max(0, Number(value) || 0)) })}
            min={0}
            max={600}
            disabled={!canManage}
          />
          <NumberInput
            withAsterisk
            label={tExt('pages.admin.settings.certificateWarningDays', {})}
            description={tExt('pages.admin.settings.certificateWarningDaysDescription', {})}
            value={settings.certificateWarningDays}
            onChange={(value) => update({ certificateWarningDays: Math.min(60, Math.max(1, Number(value) || 14)) })}
            min={1}
            max={60}
            disabled={!canManage}
          />
        </SimpleGrid>
        <Switch
          label={tExt('pages.admin.settings.reuseCertificates', {})}
          description={tExt('pages.admin.settings.reuseCertificatesDescription', {})}
          checked={settings.reuseCertificates}
          onChange={(e) => update({ reuseCertificates: e.target.checked })}
          disabled={!canManage}
        />
      </Section>

      <Section title={tExt('pages.admin.settings.domainsTitle', {})}>
        <TagsInput
          label={tExt('pages.admin.settings.allowedSuffixes', {})}
          description={tExt('pages.admin.settings.allowedSuffixesDescription', {})}
          placeholder='example.com'
          value={settings.allowedSuffixes}
          onChange={(allowedSuffixes) => update({ allowedSuffixes })}
        />
        <TagsInput
          label={tExt('pages.admin.settings.blockedPatterns', {})}
          description={tExt('pages.admin.settings.blockedPatternsDescription', {})}
          placeholder='^admin\.'
          value={settings.blockedPatterns}
          onChange={(blockedPatterns) => update({ blockedPatterns })}
          invalidTags={invalidPatterns}
          error={
            invalidPatterns.length > 0
              ? tExt('pages.admin.settings.invalidPattern', { pattern: invalidPatterns[0] })
              : undefined
          }
        />
      </Section>

      <Section title={tExt('pages.admin.settings.permissionsTitle', {})}>
        <Switch
          label={tExt('pages.admin.settings.allowLetsencrypt', {})}
          description={tExt('pages.admin.settings.allowLetsencryptDescription', {})}
          checked={settings.allowLetsencrypt}
          onChange={(e) => update({ allowLetsencrypt: e.target.checked })}
          disabled={!canManage}
        />
        <Switch
          label={tExt('pages.admin.settings.allowCustomCertificates', {})}
          description={tExt('pages.admin.settings.allowCustomCertificatesDescription', {})}
          checked={settings.allowCustomCertificates}
          onChange={(e) => update({ allowCustomCertificates: e.target.checked })}
          disabled={!canManage}
        />
        <Switch
          label={tExt('pages.admin.settings.allowCustomNginx', {})}
          description={tExt('pages.admin.settings.allowCustomNginxDescription', {})}
          checked={settings.allowCustomNginx}
          onChange={(e) => update({ allowCustomNginx: e.target.checked })}
          disabled={!canManage}
        />
      </Section>

      <Section title={tExt('pages.admin.settings.defaultsTitle', {})}>
        <NumberInput
          withAsterisk
          label={tExt('pages.admin.settings.defaultLimit', {})}
          description={tExt('pages.admin.settings.defaultLimitDescription', {})}
          value={settings.defaultLimit}
          onChange={(value) => update({ defaultLimit: Number(value) || 0 })}
          min={0}
          disabled={!canManage}
        />
        <Switch
          label={tExt('pages.admin.settings.defaultWebsockets', {})}
          description={tExt('pages.admin.settings.defaultWebsocketsDescription', {})}
          checked={defaults.websockets}
          onChange={(e) => update({ defaults: { ...defaults, websockets: e.target.checked } })}
          disabled={!canManage}
        />
        <Switch
          label={tExt('pages.admin.settings.defaultBlockExploits', {})}
          description={tExt('pages.admin.settings.defaultBlockExploitsDescription', {})}
          checked={defaults.blockExploits}
          onChange={(e) => update({ defaults: { ...defaults, blockExploits: e.target.checked } })}
          disabled={!canManage}
        />
        <Switch
          label={tExt('pages.admin.settings.defaultHttp2', {})}
          description={tExt('pages.admin.settings.defaultHttp2Description', {})}
          checked={defaults.http2}
          onChange={(e) => update({ defaults: { ...defaults, http2: e.target.checked } })}
          disabled={!canManage}
        />
      </Section>

      <Section title={tExt('pages.admin.settings.syncTitle', {})}>
        <Switch
          label={tExt('pages.admin.settings.syncEnabled', {})}
          description={tExt('pages.admin.settings.syncEnabledDescription', {})}
          checked={settings.syncEnabled}
          onChange={(e) => update({ syncEnabled: e.target.checked })}
          disabled={!canManage}
        />
        <NumberInput
          withAsterisk
          label={tExt('pages.admin.settings.syncIntervalSeconds', {})}
          description={tExt('pages.admin.settings.syncIntervalSecondsDescription', {})}
          value={settings.syncIntervalSeconds}
          onChange={(value) => update({ syncIntervalSeconds: Math.min(86400, Math.max(30, Number(value) || 600)) })}
          min={30}
          max={86400}
          disabled={!canManage || !settings.syncEnabled}
        />
      </Section>

      <Group justify='flex-end'>
        <AdminCan action='proxies.manage' cantSave>
          <Button onClick={doSave} loading={saving} disabled={invalidPatterns.length > 0}>
            {tExt('pages.admin.settings.save', {})}
          </Button>
        </AdminCan>
      </Group>
    </Stack>
  );
}
