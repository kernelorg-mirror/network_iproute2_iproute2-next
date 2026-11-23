#!/bin/sh
# BPF classifier: object loading, map pinning and graft.
#
# Needs clang with a bpf target to build the test objects, and a
# mountable bpffs for anything that pins. Skips if either is missing.

. lib/generic.sh

CLANG="${CLANG:-clang}"

command -v "$CLANG" >/dev/null 2>&1 || ts_skip
echo 'int f(void) { return 0; }' > "$STD_OUT.c"
$CLANG -target bpf -c "$STD_OUT.c" -o "$STD_OUT.o" 2>/dev/null || ts_skip
rm -f "$STD_OUT.c" "$STD_OUT.o"

WORK=$(mktemp -d)
BPFFS="$WORK/bpffs"
mkdir -p "$BPFFS"
mount -t bpf bpf "$BPFFS" 2>/dev/null || ts_skip
trap 'umount "$BPFFS" 2>/dev/null; rm -rf "$WORK"' EXIT

export TC_BPF_MNT="$BPFFS"

# Headers live next to the test tree, reached via the iproute2 build dir.
SRCDIR=$(cd "$SNAME" && pwd)

# linux/types.h pulls in asm/types.h, which lives in the multiarch
# directory that a bpf target does not search by default.
MULTIARCH=$(${CC:-cc} -print-multiarch 2>/dev/null)
[ -n "$MULTIARCH" ] && ARCHINC="-I/usr/include/$MULTIARCH"

build_obj()
{
	$CLANG -target bpf -O2 -g -I"$SRCDIR/include" $ARCHINC \
		-c "$1" -o "$2" 2>/dev/null
}

cat > "$WORK/cls.c" <<'EOF'
#include "bpf_api.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(uint32_t));
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} test_map __section(".maps");

__section("classifier")
int cls(struct __sk_buff *skb)
{
	return 0;
}

BPF_LICENSE("GPL");
EOF

build_obj "$WORK/cls.c" "$WORK/cls.o" || ts_skip

DEV="$(rand_dev)"
ts_ip "$0" "Add $DEV dummy interface" link add dev $DEV up type dummy
ts_tc "$0" "Add clsact qdisc" qdisc add dev $DEV clsact

ts_tc "$0" "Add BPF filter from object file" \
	filter add dev $DEV ingress bpf da obj $WORK/cls.o sec classifier
ts_tc "$0" "Show ingress filters" filter show dev $DEV ingress
test_on "cls.o:\[classifier\]"
test_on "direct-action"

ts_tc "$0" "Show ingress filters as JSON" -json filter show dev $DEV ingress
test_on "\"bpf_name\":\"cls.o:\[classifier\]\""

# A cls program pins below the tc/ subdirectory, not at the mount root.
echo -n "test on: \"map pinned under tc/globals\""
if [ -e "$BPFFS/tc/globals/test_map" ]; then
	pr_success
else
	pr_failed
fi

# libbpf 1.0 and later refuse an object with a legacy "maps" section.
cat > "$WORK/legacy.c" <<'EOF'
#include <linux/bpf.h>

struct bpf_elf_map {
	__u32 type, size_key, size_value, max_elem, flags, id, pinning;
};

struct bpf_elf_map __attribute__((section("maps"), used)) old_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.max_elem	= 1,
};

__attribute__((section("classifier"), used))
int cls(struct __sk_buff *skb)
{
	return 0;
}

char __attribute__((section("license"), used)) _license[] = "GPL";
EOF

if build_obj "$WORK/legacy.c" "$WORK/legacy.o"; then
	echo -n "test on: \"legacy maps section rejected\""
	if $TC filter add dev $DEV ingress bpf da obj $WORK/legacy.o \
		sec classifier 2>&1 | grep -q .; then
		pr_success
	else
		pr_failed
	fi
fi

# Graft: load an entry program that tail calls through a pinned prog
# array, then replace the entry in that map from a second object.
cat > "$WORK/graft.c" <<'EOF'
#include "bpf_api.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(uint32_t));
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} jmp_tc __section(".maps");

__section("aaa")
int cls_aaa(struct __sk_buff *skb)
{
	return 0;
}

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	tail_call(skb, &jmp_tc, 0);
	return BPF_H_DEFAULT;
}

BPF_LICENSE("GPL");
EOF

if build_obj "$WORK/graft.c" "$WORK/graft.o"; then
	ts_tc "$0" "Remove clsact qdisc" qdisc del dev $DEV clsact
	ts_tc "$0" "Add clsact qdisc" qdisc add dev $DEV clsact
	ts_tc "$0" "Add tail call entry program" \
		filter add dev $DEV ingress bpf da obj $WORK/graft.o \
		sec classifier
	ts_tc "$0" "Graft section aaa into pinned prog array" \
		exec bpf graft m:globals/jmp_tc key 0 \
		obj $WORK/graft.o sec aaa
fi
