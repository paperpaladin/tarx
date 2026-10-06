#!/bin/bash
# tarx test harness.  GNU tar is the oracle: every interop claim below is
# checked against the real thing, in both directions.  Set TARX_SKIP_BIG=1 to
# skip the 9 GiB base-256 tests (the asan build does, they are I/O bound).
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
TARX=$ROOT/tarx
TMP=$HERE/tmp
GNUTAR=${GNUTAR:-tar}

rm -rf "$TMP"
mkdir -p "$TMP"

pass=0
fail=0
ok()   { pass=$((pass+1)); printf 'ok   %s\n' "$1"; }
no()   { fail=$((fail+1)); printf 'FAIL %s\n' "$1"; }
# assert <name> <cmd...>  -- passes if the command succeeds
assert() { local n=$1; shift; if "$@" >/dev/null 2>&1; then ok "$n"; else no "$n"; fi; }
# refute <name> <cmd...>  -- passes if the command FAILS
refute() { local n=$1; shift; if "$@" >/dev/null 2>&1; then no "$n"; else ok "$n"; fi; }
eq()   { if [ "$2" = "$3" ]; then ok "$1"; else no "$1 (got '$2' want '$3')"; fi; }

[ -x "$TARX" ] || { echo "no $TARX -- run make first"; exit 1; }

# ===================================================================== #
# the tree under test                                                   #
# ===================================================================== #
# Every awkward case the format has: nesting, a symlink, a hard link, a
# >100-byte path that CAN be ustar-split, a >100-byte path that CANNOT (forcing
# pax), an empty file, mode 0700, and binary data with NUL bytes.
# shortcut: diff -r follows symlinks, so the symlink comparisons below are
# weaker than they look and a dangling link would abort diff outright.  Ceiling:
# an extractor that got every target wrong would still pass.  Upgrade path:
# diff --no-dereference plus a readlink per link.
build_tree() {
	local d=$1
	rm -rf "$d"
	mkdir -p "$d/a/b/c"
	echo hello >"$d/a/f1"
	echo nested >"$d/a/b/c/deep.txt"
	printf 'bin\000\001\002\377data\000' >"$d/a/b/binary.dat"
	: >"$d/empty"
	echo secret >"$d/mode700"; chmod 700 "$d/mode700"
	echo world >"$d/mode400"; chmod 400 "$d/mode400"
	printf 'a' >"$d/sp ace.txt"
	printf 'b' >"$d/üñí©ode.txt"
	ln -s a/f1 "$d/sym"
	ln -s ../f1 "$d/a/b/relsym"
	ln "$d/a/f1" "$d/hard"
	# 150-byte member path, splittable on a '/': exercises prefix[155]+name[100].
	local p
	p=$(python3 -c 'print("split/"*20 + "s"*25)')
	mkdir -p "$d/$(dirname "$p")"
	echo splitme >"$d/$p"
	# 150-byte single component: no legal '/' to split on, so pax is forced.
	python3 -c "
import sys
open(sys.argv[1] + '/' + 'P'*150, 'w').write('paxlong\n')" "$d"
}

build_tree "$TMP/tree"

MEMBER_COUNT=$(cd "$TMP" && find tree | wc -l)

# ===================================================================== #
# 1. tarx creates -> GNU tar reads                                      #
# ===================================================================== #
(cd "$TMP" && "$TARX" -cf x.tar tree) 2>"$TMP/create.err"
eq "tarx -c exits 0" "$?" 0
assert "tarx -c is silent on stderr" test ! -s "$TMP/create.err"
assert "GNU tar -tvf accepts a tarx archive" "$GNUTAR" -tvf "$TMP/x.tar"

# GNU tar's member list must match the tree exactly (modulo dir trailing '/').
"$GNUTAR" -tf "$TMP/x.tar" | sed 's|/$||' | sort >"$TMP/gnu.list"
(cd "$TMP" && find tree | sort) >"$TMP/find.list"
assert "GNU tar sees every member tarx wrote" diff -q "$TMP/gnu.list" "$TMP/find.list"

mkdir -p "$TMP/gx"
assert "GNU tar -xf extracts a tarx archive" "$GNUTAR" -xf "$TMP/x.tar" -C "$TMP/gx"
assert "tarx->GNU: diff -r byte-identical" diff -r "$TMP/tree" "$TMP/gx/tree"
eq "tarx->GNU: mode 0700 preserved" "$(stat -c %a "$TMP/gx/tree/mode700")" 700
eq "tarx->GNU: mode 0400 preserved" "$(stat -c %a "$TMP/gx/tree/mode400")" 400
eq "tarx->GNU: symlink target preserved" "$(readlink "$TMP/gx/tree/sym")" a/f1
eq "tarx->GNU: relative symlink preserved" "$(readlink "$TMP/gx/tree/a/b/relsym")" ../f1
eq "tarx->GNU: hard link shares an inode" \
	"$(stat -c %i "$TMP/gx/tree/hard")" "$(stat -c %i "$TMP/gx/tree/a/f1")"
eq "tarx->GNU: empty file is empty" "$(stat -c %s "$TMP/gx/tree/empty")" 0
assert "tarx->GNU: NUL-containing binary identical" \
	cmp "$TMP/tree/a/b/binary.dat" "$TMP/gx/tree/a/b/binary.dat"
eq "tarx->GNU: mtime preserved" \
	"$(stat -c %Y "$TMP/gx/tree/a/f1")" "$(stat -c %Y "$TMP/tree/a/f1")"

# ===================================================================== #
# 2. GNU tar creates -> tarx reads                                      #
# ===================================================================== #
for fmt in gnu oldgnu posix; do
	arc=$TMP/g_$fmt.tar
	dst=$TMP/tx_$fmt
	mkdir -p "$dst"
	if ! "$GNUTAR" --format=$fmt -cf "$arc" -C "$TMP" tree 2>/dev/null; then
		no "GNU tar could not write --format=$fmt (unexpected)"
		continue
	fi
	assert "GNU($fmt)->tarx: list succeeds" "$TARX" -tf "$arc"
	eq "GNU($fmt)->tarx: list has $MEMBER_COUNT members" \
		"$("$TARX" -tf "$arc" | wc -l)" "$MEMBER_COUNT"
	assert "GNU($fmt)->tarx: extract succeeds" "$TARX" -xf "$arc" -C "$dst"
	assert "GNU($fmt)->tarx: diff -r byte-identical" diff -r "$TMP/tree" "$dst/tree"
	eq "GNU($fmt)->tarx: mode 0700 preserved" "$(stat -c %a "$dst/tree/mode700")" 700
	eq "GNU($fmt)->tarx: symlink target preserved" "$(readlink "$dst/tree/sym")" a/f1
	eq "GNU($fmt)->tarx: hard link shares an inode" \
		"$(stat -c %i "$dst/tree/hard")" "$(stat -c %i "$dst/tree/a/f1")"
	eq "GNU($fmt)->tarx: mtime preserved" \
		"$(stat -c %Y "$dst/tree/a/f1")" "$(stat -c %Y "$TMP/tree/a/f1")"
done

# Strict ustar cannot represent the unsplittable >100-byte name at all -- GNU
# tar refuses to dump it ("file name is too long (cannot be split)"), which is
# the oracle confirming pax is not optional.  Test the pure-ustar path on a tree
# without it.
cp -a "$TMP/tree" "$TMP/ustree"
rm -f "$TMP/ustree/"$(printf 'P%.0s' $(seq 150))
assert "GNU tar writes --format=ustar for the splittable tree" \
	"$GNUTAR" --format=ustar -cf "$TMP/g_ustar.tar" -C "$TMP" ustree
mkdir -p "$TMP/tx_ustar"
assert "GNU(ustar)->tarx: extract succeeds" "$TARX" -xf "$TMP/g_ustar.tar" -C "$TMP/tx_ustar"
assert "GNU(ustar)->tarx: diff -r byte-identical" \
	diff -r "$TMP/ustree" "$TMP/tx_ustar/ustree"

# ===================================================================== #
# 3. tarx -> tarx round trip                                            #
# ===================================================================== #
mkdir -p "$TMP/rt"
assert "tarx->tarx round trip extracts" \
	sh -c "'$TARX' -cf - -C '$TMP' tree | '$TARX' -xf - -C '$TMP/rt'"
assert "tarx->tarx: diff -r byte-identical" diff -r "$TMP/tree" "$TMP/rt/tree"
eq "tarx->tarx: mode 0700 preserved" "$(stat -c %a "$TMP/rt/tree/mode700")" 700
eq "tarx->tarx: symlink target preserved" "$(readlink "$TMP/rt/tree/sym")" a/f1
eq "tarx->tarx: hard link shares an inode" \
	"$(stat -c %i "$TMP/rt/tree/hard")" "$(stat -c %i "$TMP/rt/tree/a/f1")"

# Double round trip through GNU in the middle: tarx -> GNU -> tarx.
mkdir -p "$TMP/mid" "$TMP/rt2"
"$GNUTAR" -xf "$TMP/x.tar" -C "$TMP/mid"
"$GNUTAR" -cf "$TMP/mid.tar" -C "$TMP/mid" tree
assert "tarx->GNU->tarx triple hop extracts" "$TARX" -xf "$TMP/mid.tar" -C "$TMP/rt2"
assert "tarx->GNU->tarx: diff -r byte-identical" diff -r "$TMP/tree" "$TMP/rt2/tree"

# ===================================================================== #
# 4. long-path encodings: prefix split vs pax                           #
# ===================================================================== #
# The splittable 150-byte path must go in prefix+name with NO pax header; the
# unsplittable one must produce one.  Checked by reading the raw header bytes,
# because "it extracted fine" would pass either way.
python3 - "$TMP/x.tar" <<'PY' && ok "long paths use the right encodings" || no "long paths use the right encodings"
import sys
data = open(sys.argv[1], 'rb').read()
split_seen = pax_seen = False
off = 0
while off + 512 <= len(data):
    h = data[off:off+512]
    if h == b'\0'*512:
        break
    name = h[0:100].split(b'\0')[0].decode()
    prefix = h[345:500].split(b'\0')[0].decode()
    typ = chr(h[156])
    size = int(h[124:136].split(b'\0')[0].strip() or b'0', 8)
    if typ == 'x':
        body = data[off+512:off+512+size].decode()
        if ' path=' in body:
            pax_seen = True
    if prefix and 's'*25 in name:
        split_seen = True
        assert len(prefix) <= 155 and len(name) <= 100
        assert len(prefix + '/' + name) == len('tree/' + 'split/'*20 + 's'*25)
    off += 512 + (size + 511) // 512 * 512
assert split_seen, "no ustar prefix/name split emitted"
assert pax_seen, "no pax extended header path= emitted"
PY

# ===================================================================== #
# 5. end-of-archive: exactly two zero blocks                            #
# ===================================================================== #
python3 - "$TMP/x.tar" <<'PY' && ok "archive ends with two 512-byte zero blocks" || no "archive ends with two 512-byte zero blocks"
import sys
d = open(sys.argv[1], 'rb').read()
assert len(d) % 512 == 0, len(d)
assert d[-1024:] == b'\0' * 1024
assert d[-1536:-1024] != b'\0' * 512, "more than two trailing zero blocks"
PY

# ===================================================================== #
# 6. base-256 size encoding: a 9 GiB member                             #
# ===================================================================== #
BIGSZ=9663676416
if [ "${TARX_SKIP_BIG:-0}" = 1 ]; then
	echo "skip big-file (base-256) tests: TARX_SKIP_BIG=1"
elif ! (mkdir -p "$TMP/big" && truncate -s 9G "$TMP/big/big.bin") 2>/dev/null; then
	echo "skip big-file (base-256) tests: filesystem will not make a 9G file"
else
	# Piped so neither side needs 9 GiB of archive on disk.
	got=$("$TARX" -cf - -C "$TMP" big | "$GNUTAR" -tvf - | awk '/big.bin/{print $3}')
	eq "tarx->GNU: GNU tar reads our base-256 9G size" "$got" "$BIGSZ"
	got=$("$GNUTAR" -cf - -C "$TMP" big | "$TARX" -tvf - | awk '/big.bin/{print $3}')
	eq "GNU->tarx: tarx reads GNU's base-256 9G size" "$got" "$BIGSZ"
	mkdir -p "$TMP/bigx"
	assert "tarx round-trips a 9G member" \
		sh -c "'$TARX' -cf - -C '$TMP' big | '$TARX' -xf - -C '$TMP/bigx'"
	eq "9G member extracts at full size" "$(stat -c %s "$TMP/bigx/big/big.bin")" "$BIGSZ"
	assert "9G member is byte-identical" cmp "$TMP/big/big.bin" "$TMP/bigx/big/big.bin"
	rm -f "$TMP/bigx/big/big.bin" "$TMP/big/big.bin"
fi

# ===================================================================== #
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
