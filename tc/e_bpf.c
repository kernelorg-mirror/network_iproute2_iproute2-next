/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * e_bpf.c	BPF exec proxy
 *
 * Authors:	Daniel Borkmann <daniel@iogearbox.net>
 */

#include <stdio.h>

#include "utils.h"

#include "tc_util.h"

#include "bpf_util.h"

static void explain(void)
{
	fprintf(stderr,
		"Usage: ... bpf [ debug ]\n"
		"       ... bpf [ graft MAP_FILE ] [ key KEY ]\n"
		"          `... [ object-file OBJ_FILE ] [ type TYPE ] [ section NAME ] [ verbose ]\n"
		"          `... [ object-pinned PROG_FILE ]\n"
		"\n"
		"Where MAP_FILE points to a pinned map, OBJ_FILE to an object file\n"
		"and PROG_FILE to a pinned program. TYPE can be {cls, act}, where\n"
		"\'cls\' is default. KEY is optional and can be inferred from the\n"
		"section name, otherwise it needs to be provided.\n");
}

static int parse_bpf(const struct exec_util *eu, int argc, char **argv)
{
	if (argc == 0)
		return 0;

	if (matches(*argv, "debug") == 0 ||
	    matches(*argv, "dbg") == 0) {
		if (bpf_trace_pipe())
			fprintf(stderr,
				"No trace pipe, tracefs not mounted?\n");
		return -1;
	} else if (matches(*argv, "graft") == 0) {
		const char *bpf_map_path;
		bool has_key = false;
		uint32_t key;

		NEXT_ARG();
		bpf_map_path = *argv;
		NEXT_ARG();
		if (matches(*argv, "key") == 0) {
			NEXT_ARG();
			if (get_unsigned(&key, *argv, 0)) {
				fprintf(stderr, "Illegal \"key\"\n");
				return -1;
			}
			has_key = true;
			NEXT_ARG();
		}
		return bpf_graft_map(bpf_map_path, has_key ?
				     &key : NULL, argc, argv);
	}

	explain();
	return -1;
}

struct exec_util bpf_exec_util = {
	.id		= "bpf",
	.parse_eopt	= parse_bpf,
};
