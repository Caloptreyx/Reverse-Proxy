import { faShieldHalved } from '@fortawesome/free-solid-svg-icons';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { Extension, ExtensionContext } from 'shared';
import { z } from 'zod';
import { type FieldDef, insertFieldsAfter } from '@/elements/form-engine/index.ts';
import AllocationProxyAction from './components/AllocationProxyAction.tsx';
import AdminConfigurationPage from './pages/admin/AdminConfigurationPage.tsx';
import ServerProxiesPage from './pages/server/ServerProxiesPage.tsx';
import { getExtTranslations } from './translations.ts';

class CaloptreyxReverseProxyExtension extends Extension {
  public cardConfigurationPage: React.FC | null = AdminConfigurationPage;
  public cardIcon: React.ReactNode = <FontAwesomeIcon icon={faShieldHalved} />;

  public initialize(ctx: ExtensionContext): void {
    ctx.extensionRegistry.enterRoutes((routes) =>
      routes.addServerRoute({
        name: () => getExtTranslations().t('pages.server.title', {}),
        icon: faShieldHalved,
        path: '/reverse-proxies',
        element: ServerProxiesPage,
        permission: 'proxies.read',
      }),
    );

    ctx.extensionRegistry.enterPages((pages) =>
      pages.enterServer((server) =>
        server.enterNetwork((network) =>
          network.enterAllocationContextMenu((menu) => menu.addComponentItemInterceptor(AllocationProxyAction)),
        ),
      ),
    );

    ctx.extensionRegistry.enterPermissionIcons((icons) =>
      icons
        .addServerPermissionIcon('proxies', <FontAwesomeIcon icon={faShieldHalved} />)
        .addAdminPermissionIcon('proxies', <FontAwesomeIcon icon={faShieldHalved} />),
    );

    ctx.extensionRegistry.enterForms((forms) => {
      for (const formId of ['admin.servers.create', 'admin.servers.update'] as const) {
        forms.extend(formId, {
          zodShape: {
            featureLimits: z.object({
              proxies: z.number().int().min(0),
            }),
          },
          initialValues: {
            featureLimits: {
              proxies: 0,
            },
          },
          transform: (fields) =>
            insertFieldsAfter(fields, 'featureLimits.schedules', {
              type: 'number',
              name: 'featureLimits.proxies',
              label: () => getExtTranslations().t('serverForm.proxiesLimit', {}),
              description: () => getExtTranslations().t('serverForm.proxiesLimitDescription', {}),
              required: true,
              props: { placeholder: '0', min: 0 },
            } satisfies FieldDef),
        });
      }
    });
  }
}

export default new CaloptreyxReverseProxyExtension();
