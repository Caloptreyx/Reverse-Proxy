import Tabs from '@/elements/layout/Tabs.tsx';
import { useExtTranslations } from '../../translations.ts';
import NodesTab from './NodesTab.tsx';
import ProxiesTab from './ProxiesTab.tsx';
import ReconcileTab from './ReconcileTab.tsx';
import SettingsTab from './SettingsTab.tsx';

export default function AdminConfigurationPage() {
  const { t: tExt } = useExtTranslations();

  return (
    <Tabs defaultValue='settings' keepMounted={false}>
      <Tabs.List>
        <Tabs.Tab value='settings'>{tExt('pages.admin.tabs.settings', {})}</Tabs.Tab>
        <Tabs.Tab value='nodes'>{tExt('pages.admin.tabs.nodes', {})}</Tabs.Tab>
        <Tabs.Tab value='proxies'>{tExt('pages.admin.tabs.proxies', {})}</Tabs.Tab>
        <Tabs.Tab value='reconcile'>{tExt('pages.admin.tabs.reconcile', {})}</Tabs.Tab>
      </Tabs.List>

      <Tabs.Panel value='settings' pt='md'>
        <SettingsTab />
      </Tabs.Panel>
      <Tabs.Panel value='nodes' pt='md'>
        <NodesTab />
      </Tabs.Panel>
      <Tabs.Panel value='proxies' pt='md'>
        <ProxiesTab />
      </Tabs.Panel>
      <Tabs.Panel value='reconcile' pt='md'>
        <ReconcileTab />
      </Tabs.Panel>
    </Tabs>
  );
}
