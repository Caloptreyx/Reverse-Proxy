import { z } from 'zod';
import { axiosInstance } from '@/api/axios.ts';
import { parseFromApi, parsePaginationFromApi, serializeForApi } from '@/lib/serialization/api-transform.ts';

export const PROXY_ADMIN_BASE = '/api/admin/extensions/dev.caloptreyx.reverseproxy';
export const proxyClientBase = (serverUuid: string) => `/api/client/servers/${serverUuid}/reverse-proxies`;

export const LABEL_REGEX = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
export const DOMAIN_REGEX = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

export const proxyStatusSchema = z.enum(['pending_dns', 'issuing', 'live', 'failed']);
export type ProxyStatus = z.infer<typeof proxyStatusSchema>;

export const proxyFlagsSchema = z.object({
  websockets: z.boolean(),
  caching: z.boolean(),
  http2: z.boolean(),
  hsts: z.boolean(),
  hstsSubdomains: z.boolean(),
  forceHttps: z.boolean(),
  blockExploits: z.boolean(),
});
export type ProxyFlags = z.infer<typeof proxyFlagsSchema>;
export const PROXY_FLAGS = Object.keys(proxyFlagsSchema.shape) as (keyof ProxyFlags)[];

export const proxyDefaultsSchema = proxyFlagsSchema.extend({
  forwardScheme: z.enum(['http', 'https']),
});
export type ProxyDefaults = z.infer<typeof proxyDefaultsSchema>;

export const proxySchema = proxyFlagsSchema.extend({
  uuid: z.string(),
  domain: z.string(),
  managedDomainUuid: z.string().nullable(),
  managedName: z.string().nullable(),
  allocation: z
    .object({
      uuid: z.string(),
      ip: z.string(),
      ipAlias: z.string().nullable(),
      port: z.number().int(),
    })
    .nullable(),
  forwardScheme: z.enum(['http', 'https']),
  advancedConfig: z.string(),
  certificateMode: z.enum(['letsencrypt', 'custom']),
  status: proxyStatusSchema,
  statusMessage: z.string().nullable(),
  certificateExpires: z.coerce.date().nullable(),
  issueAttempts: z.number().int(),
  nextAttempt: z.coerce.date().nullable(),
  created: z.coerce.date(),
});
export type ReverseProxy = z.infer<typeof proxySchema>;

export const adminProxySchema = proxySchema.extend({
  server: z.object({ uuid: z.string(), name: z.string(), owner: z.string() }),
});
export type AdminProxy = z.infer<typeof adminProxySchema>;

export const managedDomainSchema = z.object({
  uuid: z.string(),
  domain: z.string(),
  dnsChallenge: z.boolean(),
});
export type ManagedDomain = z.infer<typeof managedDomainSchema>;

export const serverProxiesSchema = z.object({
  proxies: z.array(proxySchema),
  limit: z.number().int(),
  configured: z.boolean(),
  options: z.object({
    allowCustomDomains: z.boolean(),
    allowLetsencrypt: z.boolean(),
    allowCustomCertificates: z.boolean(),
    allowCustomNginx: z.boolean(),
    proxyTargets: z.array(z.string()),
    defaults: proxyDefaultsSchema,
    managedDomains: z.array(managedDomainSchema),
  }),
});
export type ServerProxies = z.infer<typeof serverProxiesSchema>;

export const certificateInputSchema = z.object({
  certificate: z.string().optional(),
  certificateKey: z.string().optional(),
  intermediateCertificate: z.string().optional(),
  advancedConfig: z.string().optional(),
});

export const createProxySchema = proxyFlagsSchema.extend(certificateInputSchema.shape).extend({
  kind: z.enum(['custom', 'managed']),
  domain: z.string().optional(),
  managedDomainUuid: z.string().optional(),
  name: z.string().optional(),
  allocationUuid: z.string(),
  forwardScheme: z.enum(['http', 'https']),
  certificateMode: z.enum(['letsencrypt', 'custom']),
});
export type CreateProxy = z.infer<typeof createProxySchema>;

export const updateProxySchema = proxyFlagsSchema.extend(certificateInputSchema.shape).extend({
  allocationUuid: z.string().optional(),
  forwardScheme: z.enum(['http', 'https']),
  certificateMode: z.enum(['letsencrypt', 'custom']).optional(),
});
export type UpdateProxy = z.infer<typeof updateProxySchema>;

export const extensionSettingsSchema = z.object({
  npmUrl: z.string(),
  npmIdentity: z.string(),
  npmSecret: z.string().optional(),
  requestTimeoutSeconds: z.number().int().min(5).max(300),
  proxyTargets: z.array(z.string()),
  dnsPreflight: z.boolean(),
  defaultLimit: z.number().int().min(0),
  allowCustomDomains: z.boolean(),
  allowLetsencrypt: z.boolean(),
  allowCustomCertificates: z.boolean(),
  allowCustomNginx: z.boolean(),
  allowedDomains: z.array(z.string()),
  blockedPatterns: z.array(z.string()),
  defaults: proxyDefaultsSchema,
  nodeForwardHosts: z.record(z.string(), z.string()),
  maxIssuancesPerHour: z.number().int().min(1),
  maxIssuancesPerDomainPerWeek: z.number().int().min(1),
  reuseCertificates: z.boolean(),
  certificateWarningDays: z.number().int().min(1).max(60),
  subdomainManagerIntegration: z.boolean(),
  managedDnsChallenge: z.boolean(),
  dnsPropagationSeconds: z.number().int().min(0).max(600),
  syncEnabled: z.boolean(),
  autoReconcile: z.boolean(),
  syncIntervalSeconds: z.number().int().min(30).max(86400),
});
export type ExtensionSettings = z.infer<typeof extensionSettingsSchema>;

export const connectionTestSchema = z.object({
  ok: z.boolean(),
  version: z.string().optional(),
  email: z.string().optional(),
  checks: z.array(z.object({ name: z.string(), ok: z.boolean(), message: z.string().optional() })),
});
export type ConnectionTest = z.infer<typeof connectionTestSchema>;

export const nodeOverrideSchema = z.object({
  uuid: z.string(),
  name: z.string(),
  publicHost: z.string().nullable(),
  forwardHost: z.string().nullable(),
});
export type NodeOverride = z.infer<typeof nodeOverrideSchema>;

export const reconcileItemSchema = z.object({
  id: z.string(),
  kind: z.object({
    kind: z.enum(['missing_host', 'drift', 'orphan_host', 'orphan_certificate', 'missing_certificate']),
    detail: z.array(z.string()).optional(),
  }),
  proxyUuid: z.string().optional(),
  npmProxyHostId: z.number().optional(),
  npmCertificateId: z.number().optional(),
  domain: z.string().optional(),
  message: z.string(),
});
export type ReconcileItem = z.infer<typeof reconcileItemSchema>;

export const fixResultSchema = z.object({ id: z.string(), ok: z.boolean(), message: z.string().optional() });
export type FixResult = z.infer<typeof fixResultSchema>;

export const cleanupTaskSchema = z.object({
  uuid: z.string(),
  kind: z.string(),
  payload: z.json(),
  attempts: z.number().int(),
  lastError: z.string().nullable(),
  created: z.coerce.date(),
});
export type CleanupTask = z.infer<typeof cleanupTaskSchema>;

// server

export const getServerProxies = async (serverUuid: string): Promise<ServerProxies> => {
  const { data } = await axiosInstance.get(proxyClientBase(serverUuid));
  return parseFromApi(serverProxiesSchema, data);
};

export const createProxy = async (serverUuid: string, payload: CreateProxy): Promise<ReverseProxy> => {
  const { data } = await axiosInstance.post(proxyClientBase(serverUuid), serializeForApi(createProxySchema, payload));
  return parseFromApi(proxySchema, data.proxy);
};

export const updateProxy = async (
  serverUuid: string,
  proxyUuid: string,
  payload: UpdateProxy,
): Promise<{ proxy: ReverseProxy; warning: string | null }> => {
  const { data } = await axiosInstance.patch(
    `${proxyClientBase(serverUuid)}/${proxyUuid}`,
    serializeForApi(updateProxySchema, payload),
  );
  return { proxy: parseFromApi(proxySchema, data.proxy), warning: data.warning ?? null };
};

export const deleteProxy = async (serverUuid: string, proxyUuid: string): Promise<void> => {
  await axiosInstance.delete(`${proxyClientBase(serverUuid)}/${proxyUuid}`);
};

export const retryProxy = async (serverUuid: string, proxyUuid: string): Promise<void> => {
  await axiosInstance.post(`${proxyClientBase(serverUuid)}/${proxyUuid}/retry`);
};

// admin

export const getSettings = async (): Promise<{ settings: ExtensionSettings; hasNpmSecret: boolean }> => {
  const { data } = await axiosInstance.get(`${PROXY_ADMIN_BASE}/settings`);
  return { settings: parseFromApi(extensionSettingsSchema, data.settings), hasNpmSecret: data.has_npm_secret };
};

export const updateSettings = async (settings: ExtensionSettings): Promise<void> => {
  await axiosInstance.put(`${PROXY_ADMIN_BASE}/settings`, serializeForApi(extensionSettingsSchema, settings));
};

export const testConnection = async (overrides: {
  npmUrl?: string;
  npmIdentity?: string;
  npmSecret?: string;
  requestTimeoutSeconds?: number;
}): Promise<ConnectionTest> => {
  const { data } = await axiosInstance.post(`${PROXY_ADMIN_BASE}/connection/test`, {
    npm_url: overrides.npmUrl,
    npm_identity: overrides.npmIdentity,
    npm_secret: overrides.npmSecret || undefined,
    request_timeout_seconds: overrides.requestTimeoutSeconds,
  });
  return parseFromApi(connectionTestSchema, data);
};

export const getAdminProxies = async (
  page: number,
  search: string,
  status: ProxyStatus | null,
): Promise<{ proxies: Pagination<AdminProxy>; failing: number }> => {
  const { data } = await axiosInstance.get(`${PROXY_ADMIN_BASE}/proxies`, {
    params: { page, search: search || undefined, status: status ?? undefined },
  });
  return { proxies: parsePaginationFromApi(adminProxySchema, data.proxies), failing: data.failing };
};

export const retryAdminProxy = async (proxyUuid: string): Promise<void> => {
  await axiosInstance.post(`${PROXY_ADMIN_BASE}/proxies/${proxyUuid}/retry`);
};

export const deleteAdminProxy = async (proxyUuid: string): Promise<void> => {
  await axiosInstance.delete(`${PROXY_ADMIN_BASE}/proxies/${proxyUuid}`);
};

export const getNodes = async (): Promise<NodeOverride[]> => {
  const { data } = await axiosInstance.get(`${PROXY_ADMIN_BASE}/nodes`);
  return data.nodes.map((node: unknown) => parseFromApi(nodeOverrideSchema, node));
};

export const updateNode = async (nodeUuid: string, forwardHost: string | null): Promise<void> => {
  await axiosInstance.put(`${PROXY_ADMIN_BASE}/nodes/${nodeUuid}`, { forward_host: forwardHost });
};

export const getReconcile = async (): Promise<ReconcileItem[]> => {
  const { data } = await axiosInstance.get(`${PROXY_ADMIN_BASE}/reconcile`);
  return data.items.map((item: unknown) => parseFromApi(reconcileItemSchema, item));
};

export const fixReconcile = async (items: string[] | 'all'): Promise<FixResult[]> => {
  const { data } = await axiosInstance.post(
    `${PROXY_ADMIN_BASE}/reconcile/fix`,
    items === 'all' ? { all: true } : { items },
  );
  return data.results.map((result: unknown) => parseFromApi(fixResultSchema, result));
};

export const getCleanupTasks = async (): Promise<CleanupTask[]> => {
  const { data } = await axiosInstance.get(`${PROXY_ADMIN_BASE}/cleanup`);
  return data.tasks.map((task: unknown) => parseFromApi(cleanupTaskSchema, task));
};

export const deleteCleanupTask = async (uuid: string): Promise<void> => {
  await axiosInstance.delete(`${PROXY_ADMIN_BASE}/cleanup/${uuid}`);
};
