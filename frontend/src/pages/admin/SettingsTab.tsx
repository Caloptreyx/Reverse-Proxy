import { Center, SimpleGrid } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useMemo, useState } from 'react';
import { httpErrorToHuman } from '@/api/axios.ts';
import Button from '@/elements/buttons/Button.tsx';
import { AdminCan } from '@/elements/Can.tsx';
import TitleCard from '@/elements/data-display/TitleCard.tsx';
import Alert from '@/elements/feedback/Alert.tsx';
import Spinner from '@/elements/feedback/Spinner.tsx';
import NumberInput from '@/elements/input/NumberInput.tsx';
import PasswordInput from '@/elements/input/PasswordInput.tsx';
import Select from '@/elements/input/Select.tsx';
import Switch from '@/elements/input/Switch.tsx';
import TagsInput from '@/elements/input/TagsInput.tsx';
import TextInput from '@/elements/input/TextInput.tsx';
import Group from '@/elements/layout/Group.tsx';
import Stack from '@/elements/layout/Stack.tsx';
import { useAdminCan } from '@/plugins/usePermissions.ts';
import { useToast } from '@/providers/ToastProvider.tsx';
import { type ConnectionTest, type ExtensionSettings, getSettings, testConnection, updateSettings } from '../../api.ts';
import FlagSwitches from '../../components/FlagSwitches.tsx';
import { useExtTranslations } from '../../translations.ts';

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

  return (
    <Stack gap='lg'>
      <TitleCard title={tExt('pages.admin.connection.title', {})}>
        <Stack gap='md'>
          <TextInput
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
              description={data.hasNpmSecret ? tExt('pages.admin.connection.secretStored', {}) : undefined}
              value={settings.npmSecret ?? ''}
              onChange={(e) => update({ npmSecret: e.target.value })}
              disabled={!canManage}
            />
          </SimpleGrid>
          <NumberInput
            label={tExt('pages.admin.connection.timeout', {})}
            description={tExt('pages.admin.connection.timeoutDescription', {})}
            value={settings.requestTimeoutSeconds}
            onChange={(value) => update({ requestTimeoutSeconds: Math.min(300, Math.max(5, Number(value) || 30)) })}
            min={5}
            max={300}
            w={260}
            disabled={!canManage}
          />

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
        </Stack>
      </TitleCard>

      <TitleCard title={tExt('pages.admin.settings.targetsTitle', {})}>
        <Stack gap='md'>
          <TagsInput
            label={tExt('pages.admin.settings.proxyTargets', {})}
            description={tExt('pages.admin.settings.proxyTargetsDescription', {})}
            placeholder='203.0.113.10'
            value={settings.proxyTargets}
            onChange={(proxyTargets) => update({ proxyTargets })}
          />
          <Switch
            label={tExt('pages.admin.settings.dnsPreflight', {})}
            description={tExt('pages.admin.settings.dnsPreflightDescription', {})}
            checked={settings.dnsPreflight}
            onChange={(e) => update({ dnsPreflight: e.target.checked })}
            disabled={!canManage}
          />
        </Stack>
      </TitleCard>

      <TitleCard title={tExt('pages.admin.settings.domainsTitle', {})}>
        <Stack gap='md'>
          <NumberInput
            label={tExt('pages.admin.settings.defaultLimit', {})}
            description={tExt('pages.admin.settings.defaultLimitDescription', {})}
            value={settings.defaultLimit}
            onChange={(value) => update({ defaultLimit: Number(value) || 0 })}
            min={0}
            w={260}
            disabled={!canManage}
          />
          <Switch
            label={tExt('pages.admin.settings.allowCustomDomains', {})}
            description={tExt('pages.admin.settings.allowCustomDomainsDescription', {})}
            checked={settings.allowCustomDomains}
            onChange={(e) => update({ allowCustomDomains: e.target.checked })}
            disabled={!canManage}
          />
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
          {settings.allowCustomNginx && (
            <Alert color='orange'>{tExt('pages.admin.settings.allowCustomNginxWarning', {})}</Alert>
          )}
          <TagsInput
            label={tExt('pages.admin.settings.allowedDomains', {})}
            description={tExt('pages.admin.settings.allowedDomainsDescription', {})}
            placeholder='*.example.com'
            value={settings.allowedDomains}
            onChange={(allowedDomains) => update({ allowedDomains })}
          />
          <TagsInput
            label={tExt('pages.admin.settings.blockedPatterns', {})}
            description={tExt('pages.admin.settings.blockedPatternsDescription', {})}
            value={settings.blockedPatterns}
            onChange={(blockedPatterns) => update({ blockedPatterns })}
            invalidTags={invalidPatterns}
            error={
              invalidPatterns.length > 0
                ? tExt('pages.admin.settings.invalidPattern', { pattern: invalidPatterns[0] })
                : undefined
            }
          />
        </Stack>
      </TitleCard>

      <TitleCard title={tExt('pages.admin.settings.defaultsTitle', {})}>
        <Stack gap='md'>
          <Select
            label={tExt('pages.admin.settings.forwardScheme', {})}
            data={['http', 'https']}
            value={settings.defaults.forwardScheme}
            onChange={(value) =>
              value && update({ defaults: { ...settings.defaults, forwardScheme: value as 'http' | 'https' } })
            }
            allowDeselect={false}
            w={260}
            disabled={!canManage}
          />
          <FlagSwitches
            value={settings.defaults}
            onChange={(flags) => update({ defaults: { ...settings.defaults, ...flags } })}
            disabled={!canManage}
          />
        </Stack>
      </TitleCard>

      <TitleCard title={tExt('pages.admin.settings.certificatesTitle', {})}>
        <Stack gap='md'>
          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <NumberInput
              label={tExt('pages.admin.settings.maxIssuancesPerHour', {})}
              value={settings.maxIssuancesPerHour}
              onChange={(value) => update({ maxIssuancesPerHour: Math.max(1, Number(value) || 1) })}
              min={1}
              disabled={!canManage}
            />
            <NumberInput
              label={tExt('pages.admin.settings.maxIssuancesPerDomainPerWeek', {})}
              value={settings.maxIssuancesPerDomainPerWeek}
              onChange={(value) => update({ maxIssuancesPerDomainPerWeek: Math.max(1, Number(value) || 1) })}
              min={1}
              disabled={!canManage}
            />
          </SimpleGrid>
          <NumberInput
            label={tExt('pages.admin.settings.certificateWarningDays', {})}
            description={tExt('pages.admin.settings.certificateWarningDaysDescription', {})}
            value={settings.certificateWarningDays}
            onChange={(value) => update({ certificateWarningDays: Math.min(60, Math.max(1, Number(value) || 14)) })}
            min={1}
            max={60}
            w={260}
            disabled={!canManage}
          />
          <Switch
            label={tExt('pages.admin.settings.reuseCertificates', {})}
            description={tExt('pages.admin.settings.reuseCertificatesDescription', {})}
            checked={settings.reuseCertificates}
            onChange={(e) => update({ reuseCertificates: e.target.checked })}
            disabled={!canManage}
          />
        </Stack>
      </TitleCard>

      <TitleCard title={tExt('pages.admin.settings.integrationTitle', {})}>
        <Stack gap='md'>
          <Switch
            label={tExt('pages.admin.settings.subdomainManagerIntegration', {})}
            description={tExt('pages.admin.settings.subdomainManagerIntegrationDescription', {})}
            checked={settings.subdomainManagerIntegration}
            onChange={(e) => update({ subdomainManagerIntegration: e.target.checked })}
            disabled={!canManage}
          />
          <Switch
            label={tExt('pages.admin.settings.managedDnsChallenge', {})}
            description={tExt('pages.admin.settings.managedDnsChallengeDescription', {})}
            checked={settings.managedDnsChallenge}
            onChange={(e) => update({ managedDnsChallenge: e.target.checked })}
            disabled={!canManage || !settings.subdomainManagerIntegration}
          />
          <NumberInput
            label={tExt('pages.admin.settings.dnsPropagationSeconds', {})}
            value={settings.dnsPropagationSeconds}
            onChange={(value) => update({ dnsPropagationSeconds: Math.min(600, Math.max(0, Number(value) || 0)) })}
            min={0}
            max={600}
            w={260}
            disabled={!canManage || !settings.subdomainManagerIntegration || !settings.managedDnsChallenge}
          />
        </Stack>
      </TitleCard>

      <TitleCard title={tExt('pages.admin.settings.syncTitle', {})}>
        <Stack gap='md'>
          <Switch
            label={tExt('pages.admin.settings.syncEnabled', {})}
            description={tExt('pages.admin.settings.syncEnabledDescription', {})}
            checked={settings.syncEnabled}
            onChange={(e) => update({ syncEnabled: e.target.checked })}
            disabled={!canManage}
          />
          <Switch
            label={tExt('pages.admin.settings.autoReconcile', {})}
            description={tExt('pages.admin.settings.autoReconcileDescription', {})}
            checked={settings.autoReconcile}
            onChange={(e) => update({ autoReconcile: e.target.checked })}
            disabled={!canManage || !settings.syncEnabled}
          />
          <NumberInput
            label={tExt('pages.admin.settings.syncIntervalSeconds', {})}
            description={tExt('pages.admin.settings.syncIntervalSecondsDescription', {})}
            value={settings.syncIntervalSeconds}
            onChange={(value) => update({ syncIntervalSeconds: Math.min(86400, Math.max(30, Number(value) || 600)) })}
            min={30}
            max={86400}
            w={260}
            disabled={!canManage || !settings.syncEnabled}
          />
        </Stack>
      </TitleCard>

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
