/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * bpf_util.c	BPF common code
 *
 * Authors:	Daniel Borkmann <daniel@iogearbox.net>
 *		Jiri Pirko <jiri@resnulli.us>
 *		Alexei Starovoitov <ast@kernel.org>
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
#include <assert.h>
#include <libgen.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <mntent.h>

#include <arpa/inet.h>

#include "utils.h"
#include "json_print.h"

#include "bpf_util.h"
#include "bpf_elf.h"

struct bpf_prog_meta {
	const char *type;
	const char *subdir;
	const char *section;
};

static const enum bpf_prog_type __bpf_types[] = {
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
};

static const struct bpf_prog_meta __bpf_prog_meta[] = {
	[BPF_PROG_TYPE_SCHED_CLS] = {
		.type		= "cls",
		.subdir		= "tc",
		.section	= ELF_SECTION_CLASSIFIER,
	},
	[BPF_PROG_TYPE_SCHED_ACT] = {
		.type		= "act",
		.subdir		= "tc",
		.section	= ELF_SECTION_ACTION,
	},
	[BPF_PROG_TYPE_XDP] = {
		.type		= "xdp",
		.subdir		= "xdp",
		.section	= ELF_SECTION_PROG,
	},
	[BPF_PROG_TYPE_LWT_IN] = {
		.type		= "lwt_in",
		.subdir		= "ip",
		.section	= ELF_SECTION_PROG,
	},
	[BPF_PROG_TYPE_LWT_OUT] = {
		.type		= "lwt_out",
		.subdir		= "ip",
		.section	= ELF_SECTION_PROG,
	},
	[BPF_PROG_TYPE_LWT_XMIT] = {
		.type		= "lwt_xmit",
		.subdir		= "ip",
		.section	= ELF_SECTION_PROG,
	},
	[BPF_PROG_TYPE_LWT_SEG6LOCAL] = {
		.type		= "lwt_seg6local",
		.subdir		= "ip",
		.section	= ELF_SECTION_PROG,
	},
};

static const char *bpf_prog_to_subdir(enum bpf_prog_type type)
{
	assert(type < ARRAY_SIZE(__bpf_prog_meta) &&
	       __bpf_prog_meta[type].subdir);
	return __bpf_prog_meta[type].subdir;
}

const char *bpf_prog_to_default_section(enum bpf_prog_type type)
{
	assert(type < ARRAY_SIZE(__bpf_prog_meta) &&
	       __bpf_prog_meta[type].section);
	return __bpf_prog_meta[type].section;
}

static inline __u64 bpf_ptr_to_u64(const void *ptr)
{
	return (__u64)(unsigned long)ptr;
}

static int bpf_map_update(int fd, const void *key, const void *value,
			  uint64_t flags)
{
	union bpf_attr attr = {};

	attr.map_fd = fd;
	attr.key = bpf_ptr_to_u64(key);
	attr.value = bpf_ptr_to_u64(value);
	attr.flags = flags;

	return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_prog_fd_by_id(uint32_t id)
{
	union bpf_attr attr = {};

	attr.prog_id = id;

	return bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
}

static int bpf_prog_info_by_fd(int fd, struct bpf_prog_info *info,
			       uint32_t *info_len)
{
	union bpf_attr attr = {};
	int ret;

	attr.info.bpf_fd = fd;
	attr.info.info = bpf_ptr_to_u64(info);
	attr.info.info_len = *info_len;

	*info_len = 0;
	ret = bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
	if (!ret)
		*info_len = attr.info.info_len;

	return ret;
}

int bpf_dump_prog_info(FILE *f, uint32_t id)
{
	struct bpf_prog_info info = {};
	uint32_t len = sizeof(info);
	int fd, ret, dump_ok = 0;

	open_json_object("prog");
	print_uint(PRINT_ANY, "id", "id %u ", id);

	fd = bpf_prog_fd_by_id(id);
	if (fd < 0)
		goto out;

	ret = bpf_prog_info_by_fd(fd, &info, &len);
	if (!ret && len) {
		int jited = !!info.jited_prog_len;

		print_string(PRINT_ANY, "name", "name %s ", info.name);
		print_hexstring("tag", "tag %s ",
				info.tag, sizeof(info.tag));
		print_uint(PRINT_JSON, "jited", NULL, jited);
		if (jited && !is_json_context())
			fprintf(f, "jited ");

		if (show_details) {
			if (info.load_time) {
				/* ns since boottime */
				print_lluint(PRINT_ANY, "load_time",
					     "load_time %llu ", info.load_time);

				print_luint(PRINT_ANY, "created_by_uid",
					    "created_by_uid %lu ",
					    info.created_by_uid);
			}

			if (info.btf_id)
				print_luint(PRINT_ANY, "btf_id", "btf_id %lu ",
					    info.btf_id);
		}

		dump_ok = 1;
	}

	close(fd);
out:
	close_json_object();
	return dump_ok;
}

static int bpf_parse_string(char *arg, bool from_file, __u16 *bpf_len,
			    char **bpf_string, bool *need_release,
			    const char separator)
{
	char sp;

	if (from_file) {
		size_t tmp_len, op_len = sizeof("65535 255 255 4294967295,");
		char *tmp_string, *pos, c_prev = ' ';
		FILE *fp;
		int c;

		tmp_len = sizeof("4096,") + BPF_MAXINSNS * op_len;
		tmp_string = pos = calloc(1, tmp_len);
		if (tmp_string == NULL)
			return -ENOMEM;

		fp = fopen(arg, "r");
		if (fp == NULL) {
			perror("Cannot fopen");
			free(tmp_string);
			return -ENOENT;
		}

		while ((c = fgetc(fp)) != EOF) {
			switch (c) {
			case '\n':
				if (c_prev != ',')
					*(pos++) = ',';
				c_prev = ',';
				break;
			case ' ':
			case '\t':
				if (c_prev != ' ')
					*(pos++) = c;
				c_prev = ' ';
				break;
			default:
				*(pos++) = c;
				c_prev = c;
			}
			if (pos - tmp_string == tmp_len)
				break;
		}

		if (!feof(fp)) {
			free(tmp_string);
			fclose(fp);
			return -E2BIG;
		}

		fclose(fp);
		*pos = 0;

		*need_release = true;
		*bpf_string = tmp_string;
	} else {
		*need_release = false;
		*bpf_string = arg;
	}

	if (sscanf(*bpf_string, "%hu%c", bpf_len, &sp) != 2 ||
	    sp != separator) {
		if (*need_release)
			free(*bpf_string);
		return -EINVAL;
	}

	return 0;
}

static int bpf_ops_parse(int argc, char **argv, struct sock_filter *bpf_ops,
			 bool from_file)
{
	char *bpf_string, *token, separator = ',';
	int ret = 0, i = 0;
	bool need_release;
	__u16 bpf_len = 0;

	if (argc < 1)
		return -EINVAL;
	if (bpf_parse_string(argv[0], from_file, &bpf_len, &bpf_string,
			     &need_release, separator))
		return -EINVAL;
	if (bpf_len == 0 || bpf_len > BPF_MAXINSNS) {
		ret = -EINVAL;
		goto out;
	}

	token = bpf_string;
	while ((token = strchr(token, separator)) && (++token)[0]) {
		if (i >= bpf_len) {
			fprintf(stderr, "Real program length exceeds encoded length parameter!\n");
			ret = -EINVAL;
			goto out;
		}

		if (sscanf(token, "%hu %hhu %hhu %u,",
			   &bpf_ops[i].code, &bpf_ops[i].jt,
			   &bpf_ops[i].jf, &bpf_ops[i].k) != 4) {
			fprintf(stderr, "Error at instruction %d!\n", i);
			ret = -EINVAL;
			goto out;
		}

		i++;
	}

	if (i != bpf_len) {
		fprintf(stderr, "Parsed program length is less than encoded length parameter!\n");
		ret = -EINVAL;
		goto out;
	}
	ret = bpf_len;
out:
	if (need_release)
		free(bpf_string);

	return ret;
}

void bpf_print_ops(struct rtattr *bpf_ops, __u16 len)
{
	struct sock_filter *ops = RTA_DATA(bpf_ops);
	int i;

	if (len == 0)
		return;

	open_json_object("bytecode");
	print_uint(PRINT_ANY, "length", "bytecode \'%u,", len);
	open_json_array(PRINT_JSON, "insns");

	for (i = 0; i < len; i++) {
		open_json_object(NULL);
		print_hu(PRINT_ANY, "code", "%hu ", ops[i].code);
		print_hhu(PRINT_ANY, "jt", "%hhu ", ops[i].jt);
		print_hhu(PRINT_ANY, "jf", "%hhu ", ops[i].jf);
		if (i == len - 1)
			print_uint(PRINT_ANY, "k", "%u\'", ops[i].k);
		else
			print_uint(PRINT_ANY, "k", "%u,", ops[i].k);
		close_json_object();
	}

	close_json_array(PRINT_JSON, NULL);
	close_json_object();
}

static void bpf_map_pin_report(const struct bpf_elf_map *pin,
			       const struct bpf_elf_map *obj)
{
	fprintf(stderr, "Map specification differs from pinned file!\n");

	if (obj->type != pin->type)
		fprintf(stderr, " - Type:         %u (obj) != %u (pin)\n",
			obj->type, pin->type);
	if (obj->size_key != pin->size_key)
		fprintf(stderr, " - Size key:     %u (obj) != %u (pin)\n",
			obj->size_key, pin->size_key);
	if (obj->size_value != pin->size_value)
		fprintf(stderr, " - Size value:   %u (obj) != %u (pin)\n",
			obj->size_value, pin->size_value);
	if (obj->max_elem != pin->max_elem)
		fprintf(stderr, " - Max elems:    %u (obj) != %u (pin)\n",
			obj->max_elem, pin->max_elem);
	if (obj->flags != pin->flags)
		fprintf(stderr, " - Flags:        %#x (obj) != %#x (pin)\n",
			obj->flags, pin->flags);

	fprintf(stderr, "\n");
}

struct bpf_prog_data {
	unsigned int type;
	unsigned int jited;
};

struct bpf_map_ext {
	struct bpf_prog_data owner;
};

static int bpf_derive_elf_map_from_fdinfo(int fd, struct bpf_elf_map *map,
					  struct bpf_map_ext *ext)
{
	unsigned int val, owner_type = 0, owner_jited = 0;
	char file[PATH_MAX], buff[4096];
	FILE *fp;

	snprintf(file, sizeof(file), "/proc/%d/fdinfo/%d", getpid(), fd);
	memset(map, 0, sizeof(*map));

	fp = fopen(file, "r");
	if (!fp) {
		fprintf(stderr, "No procfs support?!\n");
		return -EIO;
	}

	while (fgets(buff, sizeof(buff), fp)) {
		if (sscanf(buff, "map_type:\t%u", &val) == 1)
			map->type = val;
		else if (sscanf(buff, "key_size:\t%u", &val) == 1)
			map->size_key = val;
		else if (sscanf(buff, "value_size:\t%u", &val) == 1)
			map->size_value = val;
		else if (sscanf(buff, "max_entries:\t%u", &val) == 1)
			map->max_elem = val;
		else if (sscanf(buff, "map_flags:\t%i", &val) == 1)
			map->flags = val;
		else if (sscanf(buff, "owner_prog_type:\t%i", &val) == 1)
			owner_type = val;
		else if (sscanf(buff, "owner_jited:\t%i", &val) == 1)
			owner_jited = val;
	}

	fclose(fp);
	if (ext) {
		memset(ext, 0, sizeof(*ext));
		ext->owner.type  = owner_type;
		ext->owner.jited = owner_jited;
	}

	return 0;
}

static int bpf_map_selfcheck_pinned(int fd, const struct bpf_elf_map *map,
				    struct bpf_map_ext *ext, int length,
				    enum bpf_prog_type type)
{
	struct bpf_elf_map tmp, zero = {};
	int ret;

	ret = bpf_derive_elf_map_from_fdinfo(fd, &tmp, ext);
	if (ret < 0)
		return ret;

	/* The decision to reject this is on kernel side eventually, but
	 * at least give the user a chance to know what's wrong.
	 */
	if (ext->owner.type && ext->owner.type != type)
		fprintf(stderr, "Program array map owner types differ: %u (obj) != %u (pin)\n",
			type, ext->owner.type);

	if (!memcmp(&tmp, map, length)) {
		return 0;
	} else {
		/* If kernel doesn't have eBPF-related fdinfo, we cannot do much,
		 * so just accept it. We know we do have an eBPF fd and in this
		 * case, everything is 0. It is guaranteed that no such map exists
		 * since map type of 0 is unloadable BPF_MAP_TYPE_UNSPEC.
		 */
		if (!memcmp(&tmp, &zero, length))
			return 0;

		bpf_map_pin_report(&tmp, map);
		return -EINVAL;
	}
}

static int bpf_mnt_fs(const char *target)
{
	bool bind_done = false;

	while (mount("", target, "none", MS_PRIVATE | MS_REC, NULL)) {
		if (errno != EINVAL || bind_done) {
			fprintf(stderr, "mount --make-private %s failed: %s\n",
				target,	strerror(errno));
			return -1;
		}

		if (mount(target, target, "none", MS_BIND, NULL)) {
			fprintf(stderr, "mount --bind %s %s failed: %s\n",
				target,	target, strerror(errno));
			return -1;
		}

		bind_done = true;
	}

	if (mount("bpf", target, "bpf", 0, "mode=0700")) {
		fprintf(stderr, "mount -t bpf bpf %s failed: %s\n",
			target,	strerror(errno));
		return -1;
	}

	return 0;
}

static int bpf_mnt_check_target(const char *target)
{
	int ret;

	ret = mkdir(target, S_IRWXU);
	if (ret) {
		if (errno == EEXIST)
			return 0;
		fprintf(stderr, "mkdir %s failed: %s\n", target,
			strerror(errno));
	}

	return ret;
}

static int bpf_valid_mntpt(const char *mnt, unsigned long magic)
{
	struct statfs st_fs;

	if (statfs(mnt, &st_fs) < 0)
		return -ENOENT;
	if ((unsigned long)st_fs.f_type != magic)
		return -ENOENT;

	return 0;
}

static const char *bpf_find_mntpt_single(unsigned long magic, char *mnt,
					 int len, const char *mntpt)
{
	int ret;

	ret = bpf_valid_mntpt(mntpt, magic);
	if (ret)
		return NULL;

	if (strlcpy(mnt, mntpt, len) >= (size_t)len)
		return NULL;

	return mnt;
}

static const char *bpf_find_mntpt(const char *fstype, unsigned long magic,
				  char *mnt, int len,
				  const char * const *known_mnts)
{
	const char * const *ptr;
	const char *found = NULL;
	struct mntent *ent;
	FILE *fp;

	if (known_mnts) {
		ptr = known_mnts;
		while (*ptr) {
			if (bpf_find_mntpt_single(magic, mnt, len, *ptr))
				return mnt;
			ptr++;
		}
	}

	fp = setmntent("/proc/mounts", "r");
	if (fp == NULL)
		return NULL;

	while ((ent = getmntent(fp)) != NULL) {
		if (strcmp(ent->mnt_type, fstype) != 0)
			continue;

		found = bpf_find_mntpt_single(magic, mnt, len, ent->mnt_dir);
		if (found)
			break;
	}

	endmntent(fp);
	return found;
}

int bpf_trace_pipe(void)
{
	char tracefs_mnt[PATH_MAX] = TRACE_DIR_MNT;
	static const char * const tracefs_known_mnts[] = {
		TRACE_DIR_MNT,
		"/sys/kernel/debug/tracing",
		"/tracing",
		"/trace",
		0,
	};
	int fd_in, fd_out = STDERR_FILENO;
	char tpipe[PATH_MAX];
	const char *mnt;

	mnt = bpf_find_mntpt("tracefs", TRACEFS_MAGIC, tracefs_mnt,
			     sizeof(tracefs_mnt), tracefs_known_mnts);
	if (!mnt) {
		fprintf(stderr, "tracefs not mounted?\n");
		return -1;
	}

	snprintf(tpipe, sizeof(tpipe), "%s/trace_pipe", mnt);

	fd_in = open(tpipe, O_RDONLY);
	if (fd_in < 0)
		return -1;

	fprintf(stderr, "Running! Hang up with ^C!\n\n");
	while (1) {
		static char buff[4096];
		ssize_t ret;

		ret = read(fd_in, buff, sizeof(buff));
		if (ret > 0 && write(fd_out, buff, ret) == ret)
			continue;
		break;
	}

	close(fd_in);
	return -1;
}

static int bpf_gen_global(const char *bpf_sub_dir)
{
	char bpf_glo_dir[PATH_MAX];
	int ret;

	snprintf(bpf_glo_dir, sizeof(bpf_glo_dir), "%s/%s/",
		 bpf_sub_dir, BPF_DIR_GLOBALS);

	ret = mkdir(bpf_glo_dir, S_IRWXU);
	if (ret && errno != EEXIST) {
		fprintf(stderr, "mkdir %s failed: %s\n", bpf_glo_dir,
			strerror(errno));
		return ret;
	}

	return 0;
}

static int bpf_gen_master(const char *base, const char *name)
{
	char bpf_sub_dir[PATH_MAX + NAME_MAX + 1];
	int ret;

	snprintf(bpf_sub_dir, sizeof(bpf_sub_dir), "%s%s/", base, name);

	ret = mkdir(bpf_sub_dir, S_IRWXU);
	if (ret && errno != EEXIST) {
		fprintf(stderr, "mkdir %s failed: %s\n", bpf_sub_dir,
			strerror(errno));
		return ret;
	}

	return bpf_gen_global(bpf_sub_dir);
}

static int bpf_slave_via_bind_mnt(const char *full_name,
				  const char *full_link)
{
	int ret;

	ret = mkdir(full_name, S_IRWXU);
	if (ret) {
		assert(errno != EEXIST);
		fprintf(stderr, "mkdir %s failed: %s\n", full_name,
			strerror(errno));
		return ret;
	}

	ret = mount(full_link, full_name, "none", MS_BIND, NULL);
	if (ret) {
		rmdir(full_name);
		fprintf(stderr, "mount --bind %s %s failed: %s\n",
			full_link, full_name, strerror(errno));
	}

	return ret;
}

static int bpf_gen_slave(const char *base, const char *name,
			 const char *link)
{
	char bpf_lnk_dir[PATH_MAX + NAME_MAX + 1];
	char bpf_sub_dir[PATH_MAX + NAME_MAX];
	struct stat sb = {};
	int ret;

	snprintf(bpf_lnk_dir, sizeof(bpf_lnk_dir), "%s%s/", base, link);
	snprintf(bpf_sub_dir, sizeof(bpf_sub_dir), "%s%s",  base, name);

	ret = symlink(bpf_lnk_dir, bpf_sub_dir);
	if (ret) {
		if (errno != EEXIST) {
			if (errno != EPERM) {
				fprintf(stderr, "symlink %s failed: %s\n",
					bpf_sub_dir, strerror(errno));
				return ret;
			}

			return bpf_slave_via_bind_mnt(bpf_sub_dir,
						      bpf_lnk_dir);
		}

		ret = lstat(bpf_sub_dir, &sb);
		if (ret) {
			fprintf(stderr, "lstat %s failed: %s\n",
				bpf_sub_dir, strerror(errno));
			return ret;
		}

		if ((sb.st_mode & S_IFMT) != S_IFLNK)
			return bpf_gen_global(bpf_sub_dir);
	}

	return 0;
}

static int bpf_gen_hierarchy(const char *base)
{
	int ret, i;

	ret = bpf_gen_master(base, bpf_prog_to_subdir(__bpf_types[0]));
	for (i = 1; i < ARRAY_SIZE(__bpf_types) && !ret; i++)
		ret = bpf_gen_slave(base,
				    bpf_prog_to_subdir(__bpf_types[i]),
				    bpf_prog_to_subdir(__bpf_types[0]));
	return ret;
}

static const char *bpf_get_work_dir(enum bpf_prog_type type)
{
	static char bpf_tmp[PATH_MAX+1] = BPF_DIR_MNT;
	static char bpf_wrk_dir[PATH_MAX];
	static const char *mnt;
	static bool bpf_mnt_cached;
	const char *mnt_env = getenv(BPF_ENV_MNT);
	static const char * const bpf_known_mnts[] = {
		BPF_DIR_MNT,
		"/bpf",
		0,
	};
	int ret;

	if (bpf_mnt_cached) {
		const char *out = mnt;

		if (out && type) {
			snprintf(bpf_tmp, sizeof(bpf_tmp), "%s%s/",
				 out, bpf_prog_to_subdir(type));
			out = bpf_tmp;
		}
		return out;
	}

	if (mnt_env)
		mnt = bpf_find_mntpt_single(BPF_FS_MAGIC, bpf_tmp,
					    sizeof(bpf_tmp), mnt_env);
	else
		mnt = bpf_find_mntpt("bpf", BPF_FS_MAGIC, bpf_tmp,
				     sizeof(bpf_tmp), bpf_known_mnts);
	if (!mnt) {
		mnt = mnt_env ? : BPF_DIR_MNT;
		ret = bpf_mnt_check_target(mnt);
		if (!ret)
			ret = bpf_mnt_fs(mnt);
		if (ret) {
			mnt = NULL;
			goto out;
		}
	}

	ret = snprintf(bpf_wrk_dir, sizeof(bpf_wrk_dir), "%s/", mnt);
	if (ret < 0 || ret >= sizeof(bpf_wrk_dir)) {
		mnt = NULL;
		goto out;
	}

	ret = bpf_gen_hierarchy(bpf_wrk_dir);
	if (ret) {
		mnt = NULL;
		goto out;
	}

	mnt = bpf_wrk_dir;
out:
	bpf_mnt_cached = true;
	if (mnt && type) {
		snprintf(bpf_tmp, sizeof(bpf_tmp), "%s%s/",
			 mnt, bpf_prog_to_subdir(type));
		return bpf_tmp;
	}
	return mnt;
}

static int bpf_obj_get(const char *pathname, enum bpf_prog_type type)
{
	union bpf_attr attr = {};
	char tmp[PATH_MAX];

	if (strlen(pathname) > 2 && pathname[0] == 'm' &&
	    pathname[1] == ':' && bpf_get_work_dir(type)) {
		snprintf(tmp, sizeof(tmp), "%s/%s",
			 bpf_get_work_dir(type), pathname + 2);
		pathname = tmp;
	}

	attr.pathname = bpf_ptr_to_u64(pathname);

	return bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

static int bpf_obj_pinned(const char *pathname, enum bpf_prog_type type)
{
	int prog_fd = bpf_obj_get(pathname, type);

	if (prog_fd < 0)
		fprintf(stderr, "Couldn\'t retrieve pinned program \'%s\': %s\n",
			pathname, strerror(errno));
	return prog_fd;
}

static int bpf_do_parse(struct bpf_cfg_in *cfg, const bool *opt_tbl)
{
	const char *file, *section, *prog_name;
	bool verbose = false;
	int i, ret, argc;
	char **argv;

	argv = cfg->argv;
	argc = cfg->argc;

	if (opt_tbl[CBPF_BYTECODE] &&
	    (matches(*argv, "bytecode") == 0 ||
	     strcmp(*argv, "bc") == 0)) {
		cfg->mode = CBPF_BYTECODE;
	} else if (opt_tbl[CBPF_FILE] &&
		   (matches(*argv, "bytecode-file") == 0 ||
		    strcmp(*argv, "bcf") == 0)) {
		cfg->mode = CBPF_FILE;
	} else if (opt_tbl[EBPF_OBJECT] &&
		   (matches(*argv, "object-file") == 0 ||
		    strcmp(*argv, "obj") == 0)) {
		cfg->mode = EBPF_OBJECT;
	} else if (opt_tbl[EBPF_PINNED] &&
		   (matches(*argv, "object-pinned") == 0 ||
		    matches(*argv, "pinned") == 0 ||
		    matches(*argv, "fd") == 0)) {
		cfg->mode = EBPF_PINNED;
	} else {
		fprintf(stderr, "What mode is \"%s\"?\n", *argv);
		return -1;
	}

	NEXT_ARG();
	file = section = prog_name = NULL;
	if (cfg->mode == EBPF_OBJECT || cfg->mode == EBPF_PINNED) {
		file = *argv;
		NEXT_ARG_FWD();

		if (cfg->type == BPF_PROG_TYPE_UNSPEC) {
			if (argc > 0 && matches(*argv, "type") == 0) {
				NEXT_ARG();
				for (i = 0; i < ARRAY_SIZE(__bpf_prog_meta);
				     i++) {
					if (!__bpf_prog_meta[i].type)
						continue;
					if (!matches(*argv,
						     __bpf_prog_meta[i].type)) {
						cfg->type = i;
						break;
					}
				}

				if (cfg->type == BPF_PROG_TYPE_UNSPEC) {
					fprintf(stderr, "What type is \"%s\"?\n",
						*argv);
					return -1;
				}
				NEXT_ARG_FWD();
			} else {
				cfg->type = BPF_PROG_TYPE_SCHED_CLS;
			}
		}

		section = bpf_prog_to_default_section(cfg->type);
		if (argc > 0 && matches(*argv, "section") == 0) {
			NEXT_ARG();
			section = *argv;
			NEXT_ARG_FWD();
		}

		if (argc > 0 && strcmp(*argv, "program") == 0) {
			NEXT_ARG();
			prog_name = *argv;
			NEXT_ARG_FWD();
		}

		if (argc > 0 && matches(*argv, "verbose") == 0) {
			verbose = true;
			NEXT_ARG_FWD();
		}

		PREV_ARG();
	}

	if (cfg->mode == CBPF_BYTECODE || cfg->mode == CBPF_FILE) {
		ret = bpf_ops_parse(argc, argv, cfg->opcodes,
				    cfg->mode == CBPF_FILE);
		cfg->n_opcodes = ret;
	} else if (cfg->mode == EBPF_OBJECT) {
		ret = 0; /* program will be loaded by load stage */
	} else if (cfg->mode == EBPF_PINNED) {
		ret = bpf_obj_pinned(file, cfg->type);
		cfg->prog_fd = ret;
	} else {
		return -1;
	}

	cfg->object  = file;
	cfg->section = section;
	cfg->argc    = argc;
	cfg->argv    = argv;
	cfg->verbose = verbose;
	cfg->prog_name = prog_name;

	return ret;
}

static int bpf_do_load(struct bpf_cfg_in *cfg)
{
	if (cfg->mode == EBPF_OBJECT)
		return iproute2_load_libbpf(cfg);
	return 0;
}

int bpf_load_common(struct bpf_cfg_in *cfg, const struct bpf_cfg_ops *ops,
		    void *nl)
{
	char annotation[256];
	int ret;

	ret = bpf_do_load(cfg);
	if (ret < 0)
		return ret;

	if (cfg->mode == CBPF_BYTECODE || cfg->mode == CBPF_FILE)
		ops->cbpf_cb(nl, cfg->opcodes, cfg->n_opcodes);
	if (cfg->mode == EBPF_OBJECT || cfg->mode == EBPF_PINNED) {
		snprintf(annotation, sizeof(annotation), "%s:[%s]",
			 basename(strdupa(cfg->object)),
			 cfg->mode == EBPF_PINNED ? "*fsobj" : cfg->section);
		ops->ebpf_cb(nl, cfg->prog_fd, annotation);
	}

	return 0;
}

int bpf_parse_common(struct bpf_cfg_in *cfg, const struct bpf_cfg_ops *ops)
{
	bool opt_tbl[BPF_MODE_MAX] = {};

	if (ops->cbpf_cb) {
		opt_tbl[CBPF_BYTECODE] = true;
		opt_tbl[CBPF_FILE]     = true;
	}

	if (ops->ebpf_cb) {
		opt_tbl[EBPF_OBJECT]   = true;
		opt_tbl[EBPF_PINNED]   = true;
	}

	return bpf_do_parse(cfg, opt_tbl);
}

int bpf_parse_and_load_common(struct bpf_cfg_in *cfg,
			      const struct bpf_cfg_ops *ops, void *nl)
{
	int ret;

	ret = bpf_parse_common(cfg, ops);
	if (ret < 0)
		return ret;

	return bpf_load_common(cfg, ops, nl);
}

int bpf_graft_map(const char *map_path, uint32_t *key, int argc, char **argv)
{
	const bool opt_tbl[BPF_MODE_MAX] = {
		[EBPF_OBJECT]	= true,
		[EBPF_PINNED]	= true,
	};
	const struct bpf_elf_map test = {
		.type		= BPF_MAP_TYPE_PROG_ARRAY,
		.size_key	= sizeof(int),
		.size_value	= sizeof(int),
	};
	struct bpf_cfg_in cfg = {
		.type		= BPF_PROG_TYPE_UNSPEC,
		.argc		= argc,
		.argv		= argv,
	};
	struct bpf_map_ext ext = {};
	int ret, prog_fd, map_fd;
	uint32_t map_key;

	ret = bpf_do_parse(&cfg, opt_tbl);
	if (ret < 0)
		return ret;

	ret = bpf_do_load(&cfg);
	if (ret < 0)
		return ret;

	prog_fd = cfg.prog_fd;

	if (key) {
		map_key = *key;
	} else {
		ret = sscanf(cfg.section, "%*i/%i", &map_key);
		if (ret != 1) {
			fprintf(stderr, "Couldn\'t infer map key from section name! Please provide \'key\' argument!\n");
			ret = -EINVAL;
			goto out_prog;
		}
	}

	map_fd = bpf_obj_get(map_path, cfg.type);
	if (map_fd < 0) {
		fprintf(stderr, "Couldn\'t retrieve pinned map \'%s\': %s\n",
			map_path, strerror(errno));
		ret = map_fd;
		goto out_prog;
	}

	ret = bpf_map_selfcheck_pinned(map_fd, &test, &ext,
				       offsetof(struct bpf_elf_map, max_elem),
				       cfg.type);
	if (ret < 0) {
		fprintf(stderr, "Map \'%s\' self-check failed!\n", map_path);
		goto out_map;
	}

	ret = bpf_map_update(map_fd, &map_key, &prog_fd, BPF_ANY);
	if (ret < 0)
		fprintf(stderr, "Map update failed: %s\n", strerror(errno));
out_map:
	close(map_fd);
out_prog:
	close(prog_fd);
	return ret;
}

int bpf_prog_load_dev(enum bpf_prog_type type, const struct bpf_insn *insns,
		      size_t size_insns, const char *license, __u32 ifindex,
		      char *log, size_t size_log, bool verbose)
{
	union bpf_attr attr = {};

	attr.prog_type = type;
	attr.insns = bpf_ptr_to_u64(insns);
	attr.insn_cnt = size_insns / sizeof(struct bpf_insn);
	attr.license = bpf_ptr_to_u64(license);
	attr.prog_ifindex = ifindex;

	if (size_log > 0) {
		attr.log_buf = bpf_ptr_to_u64(log);
		attr.log_size = size_log;
		attr.log_level = 1;
		if (verbose)
			attr.log_level |= 2;
	}

	return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

int bpf_program_load(enum bpf_prog_type type, const struct bpf_insn *insns,
		     size_t size_insns, const char *license, char *log,
		     size_t size_log, bool verbose)
{
	return bpf_prog_load_dev(type, insns, size_insns, license, 0, log, size_log, verbose);
}

static void bpf_init_env(void)
{
	struct rlimit limit = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	/* Don't bother in case we fail! */
	setrlimit(RLIMIT_MEMLOCK, &limit);
}

int iproute2_get_root_path(enum bpf_prog_type type, char *root_path,
			   size_t len)
{
	const char *wrk_dir;
	int ret;

	bpf_init_env();

	wrk_dir = bpf_get_work_dir(type);
	if (!wrk_dir) {
		fprintf(stderr, "No mounted eBPF fs to pin maps under\n");
		return -1;
	}

	if ((size_t)snprintf(root_path, len, "%s/%s",
			     wrk_dir, BPF_DIR_GLOBALS) >= len) {
		fprintf(stderr, "Pin root path for %s too long\n", wrk_dir);
		return -1;
	}

	ret = mkdir(root_path, S_IRWXU);
	if (ret && errno != EEXIST) {
		fprintf(stderr, "mkdir %s failed: %s\n", root_path, strerror(errno));
		return ret;
	}

	return 0;
}
