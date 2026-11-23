/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
#ifndef __BPF_ELF__
#define __BPF_ELF__

#include <asm/types.h>

/* Note:
 *
 * The ELF section names below are the ones the tc front-end looks for
 * when picking a program out of an object file. For compatibility, they
 * should stay as-is.
 */

/* ELF section names, etc */
#define ELF_SECTION_LICENSE	"license"
#define ELF_SECTION_PROG	"prog"
#define ELF_SECTION_CLASSIFIER	"classifier"
#define ELF_SECTION_ACTION	"action"

/* Map description used by the pinned map self-check in bpf_graft_map().
 * This is not a kernel ABI and no longer describes any on-disk format;
 * it only holds the values read back from /proc/self/fdinfo.
 */
struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
};

#endif /* __BPF_ELF__ */
