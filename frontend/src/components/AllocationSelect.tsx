import { SelectProps } from '@mantine/core';
import { z } from 'zod';
import getAllocations from '@/api/server/allocations/getAllocations.ts';
import Select from '@/elements/input/Select.tsx';
import { serverAllocationSchema } from '@/lib/schemas/server/allocations.ts';
import { useSearchableResource } from '@/plugins/resource/useSearchableResource.ts';

type Allocation = z.infer<typeof serverAllocationSchema>;

type Props = Omit<SelectProps, 'data' | 'value' | 'onChange'> & {
  serverUuid: string;
  value: string | null;
  onChange: (uuid: string | null) => void;
};

export default function AllocationSelect({ serverUuid, value, onChange, ...rest }: Props) {
  const allocations = useSearchableResource<Allocation>({
    queryKey: ['dev.caloptreyx.reverseproxy', 'server', serverUuid, 'allocations'],
    fetcher: (search) => getAllocations(serverUuid, 1, search),
  });

  return (
    <Select
      data={allocations.items.map((allocation) => ({
        label: `${allocation.ipAlias ?? allocation.ip}:${allocation.port}${allocation.notes ? ` (${allocation.notes})` : ''}`,
        value: allocation.uuid,
      }))}
      value={value}
      onChange={onChange}
      searchable
      searchValue={allocations.search}
      onSearchChange={allocations.setSearch}
      loading={allocations.loading}
      {...rest}
    />
  );
}
