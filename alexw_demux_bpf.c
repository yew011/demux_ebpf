#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

struct bpf_map_def cpu_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(unsigned int),
	.max_entries = 256,
};

int demux_bpf(void *arg)
{
	unsigned int cpu = bpf_get_smp_processor_id();
	unsigned int value;

	value = bpf_map_lookup_elem(&cpu_map, &cpu);
	value++;
	bpf_map_update_elem(&cpu_map, &cpu, &value, BPF_ANY);

	return (cpu - cpu % 3) + value % 3;
}
