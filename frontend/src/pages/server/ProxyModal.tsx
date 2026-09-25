import { ModalProps } from '@mantine/core';
import { useEffect, useState } from 'react';
import { httpErrorToHuman } from '@/api/axios.ts';
import Button from '@/elements/buttons/Button.tsx';
import { ServerCan } from '@/elements/Can.tsx';
import Select from '@/elements/input/Select.tsx';
import TextArea from '@/elements/input/TextArea.tsx';
import TextInput from '@/elements/input/TextInput.tsx';
import Divider from '@/elements/layout/Divider.tsx';
import SegmentedControl from '@/elements/layout/SegmentedControl.tsx';
import Stack from '@/elements/layout/Stack.tsx';
import FormModal from '@/elements/modals/FormModal.tsx';
import { ModalFooter } from '@/elements/modals/Modal.tsx';
import Code from '@/elements/typography/Code.tsx';
import Text from '@/elements/typography/Text.tsx';
import { useToast } from '@/providers/ToastProvider.tsx';
import { useTranslations } from '@/providers/TranslationProvider.tsx';
import {
  createProxy,
  DOMAIN_REGEX,
  initialFlags,
  LABEL_REGEX,
  type ProxyFlags,
  type ReverseProxy,
  type ServerProxies,
  updateProxy,
} from '../../api.ts';
import AllocationSelect from '../../components/AllocationSelect.tsx';
import FlagSwitches from '../../components/FlagSwitches.tsx';
import { useExtTranslations } from '../../translations.ts';

type Kind = 'custom' | 'managed';
type Scheme = 'http' | 'https';
type CertificateMode = 'letsencrypt' | 'custom';

const pickFlags = (source: ProxyFlags): ProxyFlags => ({
  websockets: source.websockets,
  caching: source.caching,
  http2: source.http2,
  hsts: source.hsts,
  hstsSubdomains: source.hstsSubdomains,
  forceHttps: source.forceHttps,
  blockExploits: source.blockExploits,
});

export default function ProxyModal({
  serverUuid,
  options,
  proxy,
  allocationUuid: initialAllocationUuid,
  onSaved,
  ...props
}: Omit<ModalProps, 'children'> & {
  serverUuid: string;
  options: ServerProxies['options'];
  proxy?: ReverseProxy;
  allocationUuid?: string;
  onSaved: () => void;
}) {
  const { t: tExt, tReact: tExtReact } = useExtTranslations();
  const { t } = useTranslations();
  const { addToast } = useToast();

  const canManaged = options.managedDomains.length > 0;
  const defaultMode: CertificateMode =
    options.allowLetsencrypt || !options.allowCustomCertificates ? 'letsencrypt' : 'custom';
  const certificateModes = [
    ...(options.allowLetsencrypt || proxy?.certificateMode === 'letsencrypt'
      ? [{ value: 'letsencrypt', label: tExt('pages.server.modal.certificateLetsEncrypt', {}) }]
      : []),
    ...(options.allowCustomCertificates || proxy?.certificateMode === 'custom'
      ? [{ value: 'custom', label: tExt('pages.server.modal.certificateCustom', {}) }]
      : []),
  ];

  const [loading, setLoading] = useState(false);
  const [kind, setKind] = useState<Kind>('custom');
  const [domain, setDomain] = useState('');
  const [managedDomainUuid, setManagedDomainUuid] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [allocationUuid, setAllocationUuid] = useState<string | null>(null);
  const [scheme, setScheme] = useState<Scheme>('http');
  const [flags, setFlags] = useState<ProxyFlags>(initialFlags(options.defaults));
  const [certificateMode, setCertificateMode] = useState<CertificateMode>(defaultMode);
  const [certificate, setCertificate] = useState('');
  const [certificateKey, setCertificateKey] = useState('');
  const [intermediate, setIntermediate] = useState('');
  const [advancedConfig, setAdvancedConfig] = useState('');

  useEffect(() => {
    if (!props.opened) return;
    setKind('custom');
    setDomain('');
    setManagedDomainUuid(options.managedDomains[0]?.uuid ?? null);
    setName('');
    setAllocationUuid(proxy?.allocation?.uuid ?? initialAllocationUuid ?? null);
    setScheme(proxy?.forwardScheme ?? 'http');
    setFlags(proxy ? pickFlags(proxy) : initialFlags(options.defaults));
    setCertificateMode(proxy?.certificateMode ?? defaultMode);
    setCertificate('');
    setCertificateKey('');
    setIntermediate('');
    setAdvancedConfig(proxy?.advancedConfig ?? '');
  }, [props.opened]);

  const normalizedDomain = domain.trim().toLowerCase().replace(/\.$/, '');
  const normalizedName = name.trim().toLowerCase();
  const managedDomain = options.managedDomains.find((entry) => entry.uuid === managedDomainUuid) ?? null;

  // editing an existing custom-cert proxy may keep its certificate
  const keepsCertificate = proxy?.certificateMode === 'custom' && certificateMode === 'custom';
  const certificateValid =
    certificateMode === 'letsencrypt' ||
    (certificate.trim() && certificateKey.trim()) ||
    (keepsCertificate && !certificate.trim() && !certificateKey.trim());

  const domainValid = proxy
    ? true
    : kind === 'custom'
      ? DOMAIN_REGEX.test(normalizedDomain)
      : !!managedDomain && LABEL_REGEX.test(normalizedName);

  const doSubmit = async () => {
    setLoading(true);
    const certificatePayload =
      certificateMode === 'custom' && certificate.trim()
        ? {
            certificate: certificate.trim(),
            certificateKey: certificateKey.trim(),
            intermediateCertificate: intermediate.trim() || undefined,
          }
        : {};

    const advancedPayload = options.allowCustomNginx ? { advancedConfig } : {};

    try {
      if (proxy) {
        const { warning } = await updateProxy(serverUuid, proxy.uuid, {
          ...flags,
          ...certificatePayload,
          ...advancedPayload,
          allocationUuid: allocationUuid ?? undefined,
          forwardScheme: scheme,
          certificateMode:
            certificateMode !== proxy.certificateMode || certificatePayload.certificate ? certificateMode : undefined,
        });
        addToast(warning ?? tExt('pages.server.toast.updated', {}), warning ? 'warning' : 'success');
      } else {
        await createProxy(serverUuid, {
          ...flags,
          ...certificatePayload,
          ...advancedPayload,
          kind,
          domain: kind === 'custom' ? normalizedDomain : undefined,
          managedDomainUuid: kind === 'managed' ? (managedDomainUuid ?? undefined) : undefined,
          name: kind === 'managed' ? normalizedName : undefined,
          allocationUuid: allocationUuid ?? '',
          forwardScheme: scheme,
          certificateMode,
        });
        addToast(tExt('pages.server.toast.created', {}), 'success');
      }
      onSaved();
      props.onClose();
    } catch (msg) {
      addToast(httpErrorToHuman(msg), 'error');
    }
    setLoading(false);
  };

  return (
    <FormModal
      size='lg'
      {...props}
      title={
        proxy
          ? tExt('pages.server.modal.editTitle', { domain: proxy.domain })
          : tExt('pages.server.modal.createTitle', {})
      }
      onSubmit={(e) => {
        e.preventDefault();
        doSubmit();
      }}
    >
      <Stack gap='md'>
        {!proxy && canManaged && (
          <SegmentedControl
            fullWidth
            data={[
              { value: 'custom', label: tExt('pages.server.modal.kindCustom', {}) },
              { value: 'managed', label: tExt('pages.server.modal.kindManaged', {}) },
            ]}
            value={kind}
            onChange={(value) => setKind(value as Kind)}
          />
        )}

        {!proxy && kind === 'custom' && (
          <TextInput
            withAsterisk
            label={tExt('pages.server.modal.domain', {})}
            description={
              options.dnsTarget
                ? tExt('pages.server.modal.domainDescription', { target: options.dnsTarget })
                : tExt('pages.server.modal.domainDescriptionNoTarget', {})
            }
            placeholder='play.example.com'
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            error={domain.length > 0 && !DOMAIN_REGEX.test(normalizedDomain)}
          />
        )}

        {!proxy && kind === 'managed' && (
          <>
            <Select
              withAsterisk
              label={tExt('pages.server.modal.managedDomain', {})}
              data={options.managedDomains.map((entry) => ({ label: entry.domain, value: entry.uuid }))}
              value={managedDomainUuid}
              onChange={setManagedDomainUuid}
              allowDeselect={false}
            />
            <TextInput
              withAsterisk
              label={tExt('pages.server.modal.name', {})}
              description={tExt('pages.server.modal.nameDescription', {})}
              value={name}
              onChange={(e) => setName(e.target.value)}
              error={name.length > 0 && !LABEL_REGEX.test(normalizedName)}
            />
            {managedDomain && LABEL_REGEX.test(normalizedName) && (
              <Text size='sm' c='dimmed'>
                {tExtReact('pages.server.modal.preview', {
                  fqdn: (
                    <Code>
                      {normalizedName}.{managedDomain.domain}
                    </Code>
                  ),
                })}{' '}
                {tExt('pages.server.modal.dnsChallenge', {})}
              </Text>
            )}
          </>
        )}

        <AllocationSelect
          withAsterisk
          label={tExt('pages.server.modal.allocation', {})}
          description={tExt('pages.server.modal.allocationDescription', {})}
          serverUuid={serverUuid}
          value={allocationUuid}
          onChange={setAllocationUuid}
        />

        <Select
          label={tExt('pages.server.modal.scheme', {})}
          description={tExt('pages.server.modal.schemeDescription', {})}
          data={['http', 'https']}
          value={scheme}
          onChange={(value) => value && setScheme(value as Scheme)}
          allowDeselect={false}
        />

        {certificateModes.length > 0 && (
          <>
            <Select
              label={tExt('pages.server.modal.certificateMode', {})}
              data={certificateModes}
              value={certificateMode}
              onChange={(value) => value && setCertificateMode(value as CertificateMode)}
              allowDeselect={false}
            />
            {certificateMode === 'custom' && (
              <>
                {keepsCertificate && (
                  <Text size='sm' c='dimmed'>
                    {tExt('pages.server.modal.replaceCertificate', {})}
                  </Text>
                )}
                <TextArea
                  withAsterisk={!keepsCertificate}
                  label={tExt('pages.server.modal.certificate', {})}
                  placeholder='-----BEGIN CERTIFICATE-----'
                  value={certificate}
                  onChange={(e) => setCertificate(e.target.value)}
                  autosize
                  minRows={3}
                  maxRows={8}
                  ff='monospace'
                />
                <TextArea
                  withAsterisk={!keepsCertificate}
                  label={tExt('pages.server.modal.certificateKey', {})}
                  placeholder='-----BEGIN PRIVATE KEY-----'
                  value={certificateKey}
                  onChange={(e) => setCertificateKey(e.target.value)}
                  autosize
                  minRows={3}
                  maxRows={8}
                  ff='monospace'
                />
                <TextArea
                  label={tExt('pages.server.modal.intermediate', {})}
                  value={intermediate}
                  onChange={(e) => setIntermediate(e.target.value)}
                  autosize
                  minRows={2}
                  maxRows={8}
                  ff='monospace'
                />
              </>
            )}
          </>
        )}

        <Divider label={tExt('pages.server.modal.options', {})} labelPosition='left' />
        <FlagSwitches value={flags} onChange={setFlags} />

        {options.allowCustomNginx && (
          <TextArea
            label={tExt('pages.server.modal.advancedConfig', {})}
            description={tExt('pages.server.modal.advancedConfigDescription', {})}
            placeholder='client_max_body_size 50m;'
            value={advancedConfig}
            onChange={(e) => setAdvancedConfig(e.target.value)}
            autosize
            minRows={2}
            maxRows={10}
            ff='monospace'
          />
        )}

        <ModalFooter>
          <ServerCan action={proxy ? 'proxies.update' : 'proxies.create'}>
            <Button type='submit' loading={loading} disabled={!domainValid || !allocationUuid || !certificateValid}>
              {proxy ? tExt('pages.server.button.edit', {}) : tExt('pages.server.button.create', {})}
            </Button>
          </ServerCan>
          <Button variant='default' onClick={props.onClose}>
            {t('common.button.cancel', {})}
          </Button>
        </ModalFooter>
      </Stack>
    </FormModal>
  );
}
