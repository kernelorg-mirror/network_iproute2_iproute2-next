/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bpf_libbpf.c		BPF code relay on libbpf
 * Authors:		Hangbin Liu <haliu@redhat.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bpf_util.h"

static int __attribute__((format(printf, 2, 0)))
verbose_print(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int __attribute__((format(printf, 2, 0)))
silent_print(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level > LIBBPF_WARN)
		return 0;

	return vfprintf(stderr, format, args);
}

static bool bpf_map_is_offload_neutral(const struct bpf_map *map)
{
	return bpf_map__type(map) == BPF_MAP_TYPE_PERF_EVENT_ARRAY;
}

static bool find_prog_to_attach(struct bpf_program *prog,
				struct bpf_program *exist_prog,
				const char *section, const char *prog_name)
{
	if (exist_prog)
		return false;

	/* We have default section name 'prog'. So do not check
	 * section name if there already has program name.
	 */
	if (prog_name)
		return !strcmp(bpf_program__name(prog), prog_name);
	else
		return !strcmp(bpf_program__section_name(prog), section);
}

static int load_bpf_object(struct bpf_cfg_in *cfg)
{
	struct bpf_program *p, *prog = NULL;
	struct bpf_object *obj;
	char root_path[PATH_MAX];
	struct bpf_map *map;
	int prog_fd, ret = 0;

	ret = iproute2_get_root_path(cfg->type, root_path, PATH_MAX);
	if (ret)
		return ret;

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts,
			.pin_root_path = root_path,
	);

	open_opts.kernel_log_level = 1;
	if (cfg->verbose)
		open_opts.kernel_log_level |= 2;

	obj = bpf_object__open_file(cfg->object, &open_opts);
	if (!obj) {
		/* Save errno before any stdio call can clobber it. */
		int err = errno ? -errno : -EINVAL;
		char buf[128];

		libbpf_strerror(err, buf, sizeof(buf));
		fprintf(stderr, "ERROR: opening BPF object file '%s' failed: %s\n",
			cfg->object, buf);
		return err;
	}

	bpf_object__for_each_program(p, obj) {
		bool prog_to_attach = find_prog_to_attach(p, prog,
							  cfg->section,
							  cfg->prog_name);

		/* Only load the program that will be attached */
		if (!prog_to_attach) {
			ret = bpf_program__set_autoload(p, false);
			if (ret)
				return -EINVAL;
			continue;
		}

		bpf_program__set_type(p, cfg->type);
		bpf_program__set_ifindex(p, cfg->ifindex);

		if (prog_to_attach)
			prog = p;
	}

	bpf_object__for_each_map(map, obj) {
		if (!bpf_map_is_offload_neutral(map))
			bpf_map__set_ifindex(map, cfg->ifindex);
	}

	if (!prog) {
		if (cfg->prog_name)
			fprintf(stderr, "object file doesn't contain prog %s\n", cfg->prog_name);
		else
			fprintf(stderr, "object file doesn't contain sec %s\n", cfg->section);
		return -ENOENT;
	}

	ret = bpf_object__load(obj);
	if (ret)
		goto unload_obj;

	prog_fd = fcntl(bpf_program__fd(prog), F_DUPFD_CLOEXEC, 1);
	if (prog_fd < 0)
		ret = -errno;
	else
		cfg->prog_fd = prog_fd;

unload_obj:
	/* Close obj as we don't need it */
	bpf_object__close(obj);
	return ret;
}

/* Load ebpf and return prog fd */
int iproute2_load_libbpf(struct bpf_cfg_in *cfg)
{
	int ret = 0;

	if (cfg->verbose)
		libbpf_set_print(verbose_print);
	else
		libbpf_set_print(silent_print);

	ret = load_bpf_object(cfg);
	if (ret)
		return ret;

	return cfg->prog_fd;
}
