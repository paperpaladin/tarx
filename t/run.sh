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
	# link target over 100 bytes: forces pax linkpath=
	ln -s "$(python3 -c 'print("t/"*60 + "z")')" "$d/longsym"
	ln -s ../f1 "$d/a/b/relsym"
	ln -s nowhere/at/all "$d/dangling"
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
assert "tarx->GNU: diff -r byte-identical" diff -r --no-dereference "$TMP/tree" "$TMP/gx/tree"
eq "tarx->GNU: mode 0700 preserved" "$(stat -c %a "$TMP/gx/tree/mode700")" 700
eq "tarx->GNU: mode 0400 preserved" "$(stat -c %a "$TMP/gx/tree/mode400")" 400
eq "tarx->GNU: symlink target preserved" "$(readlink "$TMP/gx/tree/sym")" a/f1
eq "tarx->GNU: relative symlink preserved" "$(readlink "$TMP/gx/tree/a/b/relsym")" ../f1
eq "tarx->GNU: dangling symlink preserved" "$(readlink "$TMP/gx/tree/dangling")" nowhere/at/all
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
	assert "GNU($fmt)->tarx: diff -r byte-identical" diff -r --no-dereference "$TMP/tree" "$dst/tree"
	eq "GNU($fmt)->tarx: mode 0700 preserved" "$(stat -c %a "$dst/tree/mode700")" 700
	eq "GNU($fmt)->tarx: symlink target preserved" "$(readlink "$dst/tree/sym")" a/f1
	eq "GNU($fmt)->tarx: hard link shares an inode" \
		"$(stat -c %i "$dst/tree/hard")" "$(stat -c %i "$dst/tree/a/f1")"
	eq "GNU($fmt)->tarx: mtime preserved" \
		"$(stat -c %Y "$dst/tree/a/f1")" "$(stat -c %Y "$TMP/tree/a/f1")"
done

# Strict ustar cannot represent an unsplittable >100-byte name or a >100-byte
# link target at all -- GNU tar refuses to dump both ("file name is too long
# (cannot be split)", "link name is too long"), which is the oracle confirming
# pax is not optional.  Test the pure-ustar path on a tree without them.
cp -a "$TMP/tree" "$TMP/ustree"
rm -f "$TMP/ustree/"$(printf 'P%.0s' $(seq 150)) "$TMP/ustree/longsym"
assert "GNU tar writes --format=ustar for the splittable tree" \
	"$GNUTAR" --format=ustar -cf "$TMP/g_ustar.tar" -C "$TMP" ustree
mkdir -p "$TMP/tx_ustar"
assert "GNU(ustar)->tarx: extract succeeds" "$TARX" -xf "$TMP/g_ustar.tar" -C "$TMP/tx_ustar"
assert "GNU(ustar)->tarx: diff -r byte-identical" \
	diff -r --no-dereference "$TMP/ustree" "$TMP/tx_ustar/ustree"

# ===================================================================== #
# 3. tarx -> tarx round trip                                            #
# ===================================================================== #
mkdir -p "$TMP/rt"
assert "tarx->tarx round trip extracts" \
	sh -c "'$TARX' -cf - -C '$TMP' tree | '$TARX' -xf - -C '$TMP/rt'"
assert "tarx->tarx: diff -r byte-identical" diff -r --no-dereference "$TMP/tree" "$TMP/rt/tree"
eq "tarx->tarx: mode 0700 preserved" "$(stat -c %a "$TMP/rt/tree/mode700")" 700
eq "tarx->tarx: symlink target preserved" "$(readlink "$TMP/rt/tree/sym")" a/f1
eq "tarx->tarx: hard link shares an inode" \
	"$(stat -c %i "$TMP/rt/tree/hard")" "$(stat -c %i "$TMP/rt/tree/a/f1")"

# Double round trip through GNU in the middle: tarx -> GNU -> tarx.
mkdir -p "$TMP/mid" "$TMP/rt2"
"$GNUTAR" -xf "$TMP/x.tar" -C "$TMP/mid"
"$GNUTAR" -cf "$TMP/mid.tar" -C "$TMP/mid" tree
assert "tarx->GNU->tarx triple hop extracts" "$TARX" -xf "$TMP/mid.tar" -C "$TMP/rt2"
assert "tarx->GNU->tarx: diff -r byte-identical" diff -r --no-dereference "$TMP/tree" "$TMP/rt2/tree"

eq "tarx->GNU: >100 byte symlink target preserved (pax linkpath)" \
	"$(readlink "$TMP/gx/tree/longsym")" "$(readlink "$TMP/tree/longsym")"
eq "tarx->tarx: >100 byte symlink target preserved" \
	"$(readlink "$TMP/rt/tree/longsym")" "$(readlink "$TMP/tree/longsym")"

# ===================================================================== #
# 4. long-path encodings: prefix split vs pax                           #
# ===================================================================== #
# The splittable 150-byte path must go in prefix+name with NO pax header; the
# unsplittable one must produce one.  Checked by reading the raw header bytes,
# because "it extracted fine" would pass either way.
python3 - "$TMP/x.tar" <<'PY' && ok "long paths use the right encodings" || no "long paths use the right encodings"
import sys
data = open(sys.argv[1], 'rb').read()
split_seen = pax_seen = paxlink_seen = False
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
        if 'linkpath=' in body:
            paxlink_seen = True
        elif ' path=' in body:
            pax_seen = True
    if prefix and 's'*25 in name:
        split_seen = True
        assert len(prefix) <= 155 and len(name) <= 100
        assert len(prefix + '/' + name) == len('tree/' + 'split/'*20 + 's'*25)
    off += 512 + (size + 511) // 512 * 512
assert split_seen, "no ustar prefix/name split emitted"
assert pax_seen, "no pax extended header path= emitted"
assert paxlink_seen, "no pax extended header linkpath= emitted"
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
# 7. SECURITY: path traversal must be REFUSED, not sanitised            #
# ===================================================================== #
# Each case extracts into $TMP/jail/dest and then proves (a) tarx exited
# nonzero, (b) the payload is not inside dest, and (c) nothing at all appeared
# beside dest -- i.e. nothing escaped.

# Hand-written headers, because GNU tar will not emit several of these.
cat >"$TMP/mkevil.py" <<'PY'
import sys, os

def hdr(name, typ='0', size=0, link='', mode=0o644, prefix=''):
    h = bytearray(512)
    def put(off, s, n):
        b = s.encode() if isinstance(s, str) else s
        assert len(b) <= n, (off, len(b), n)
        h[off:off+len(b)] = b
    put(0, name, 100)
    put(100, '%07o\0' % mode, 8)
    put(108, '%07o\0' % 0, 8)
    put(116, '%07o\0' % 0, 8)
    put(124, '%011o\0' % size, 12)
    put(136, '%011o\0' % 0, 12)
    h[148:156] = b' ' * 8           # checksum computed over spaces, see tarx.c
    h[156] = ord(typ)
    put(157, link, 100)
    put(257, 'ustar\0', 6)
    put(263, '00', 2)
    put(345, prefix, 155)
    put(148, '%06o\0 ' % sum(h), 8)
    return bytes(h)

def body(b):
    return b + b'\0' * (-len(b) % 512)

def member(name, typ='0', content=b'', link='', mode=0o644, prefix=''):
    return hdr(name, typ, len(content), link, mode, prefix) + body(content)

def pax(records, then):
    recs = b''
    for k, v in records:
        base = len(k) + len(v) + 3
        n = base
        while True:
            m = base + len(str(n))
            if m == n:
                break
            n = m
        recs += b'%d %s=%s\n' % (n, k.encode(), v.encode())
    return hdr('PaxHeaders/x', 'x', len(recs)) + body(recs) + then

PAYLOAD = b'PWNED\n'
cases = {
  # name                     archive bytes
  'dotdot':      member('../escape', content=PAYLOAD),
  'dotdot_deep': member('dest/../../escape', content=PAYLOAD),
  'absolute':    member('/tmp/tarx-should-never-write-this', content=PAYLOAD),
  'abs_prefix':  member('escape', content=PAYLOAD, prefix='/tmp'),
  'symabs':      member('link', '2', link='/tmp/tarx-should-never-write-this'),
  'symesc':      member('link', '2', link='../../escape'),
  'symdeep':     member('d/link', '2', link='../../escape'),
  'hardesc':     member('h', '1', link='../escape'),
  # the member name is clean; the malicious path arrives via pax
  'pax_dotdot':  pax([('path', '../escape')], member('placeholder', content=PAYLOAD)),
  'pax_abs':     pax([('path', '/tmp/tarx-should-never-write-this')],
                     member('placeholder', content=PAYLOAD)),
  # GNU 'L' long-name delivery of the same thing
  'gnu_dotdot':  (hdr('././@LongLink', 'L', len('../escape') + 1) +
                  body(b'../escape\0') + member('placeholder', content=PAYLOAD)),
  # two members: a legal symlink, then a file "through" it.  Purely lexical
  # checks pass this; only an lstat on each parent component catches it.
  'via_symlink': (member('sub/', '5', mode=0o755) +
                  member('sub/up', '2', link='..') +
                  member('sub/up/escape', content=PAYLOAD)),
  # a bad member sandwiched between good ones: refusal is per-member, the
  # good members must still land
  'mixed':       (member('good.txt', content=b'fine\n') +
                  member('../escape', content=PAYLOAD) +
                  member('also-good.txt', content=b'fine\n')),
}
# Not a refusal case on its own -- "link/escape" is perfectly legal into an
# empty destination.  It only turns hostile when "link" already exists as a
# symlink, which the harness sets up separately.
extras = {
  'through_existing': member('link/escape', content=PAYLOAD),
}
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
for k, v in list(cases.items()) + list(extras.items()):
    open(os.path.join(out, k + '.tar'), 'wb').write(v + b'\0' * 1024)
print('\n'.join(sorted(cases)))
PY
EVILS=$(python3 "$TMP/mkevil.py" "$TMP/evil")

# GNU tar, with -P, happily writes the two classic cases -- so we also test
# archives produced by the oracle itself, not only our hand-rolled bytes.
mkdir -p "$TMP/src" && echo PWNED >"$TMP/src/escape"
"$GNUTAR" -P -cf "$TMP/evil/gnu_dotdot_real.tar" --transform='s|.*|../escape|' \
	-C "$TMP/src" escape 2>/dev/null
"$GNUTAR" -P -cf "$TMP/evil/gnu_absolute_real.tar" \
	--transform='s|.*|/tmp/tarx-should-never-write-this|' \
	-C "$TMP/src" escape 2>/dev/null
assert "GNU tar -P really stored '../escape' (oracle sanity)" \
	sh -c "'$GNUTAR' -tf '$TMP/evil/gnu_dotdot_real.tar' | grep -q '\\.\\./escape'"
assert "GNU tar -P really stored an absolute path (oracle sanity)" \
	sh -c "'$GNUTAR' -tf '$TMP/evil/gnu_absolute_real.tar' | grep -qx '/tmp/tarx-should-never-write-this'"
EVILS="$EVILS gnu_dotdot_real gnu_absolute_real"

CANARY=/tmp/tarx-should-never-write-this
rm -f "$CANARY"
for ev in $EVILS; do
	jail=$TMP/jail/$ev
	rm -rf "$jail"
	mkdir -p "$jail/dest"
	out=$("$TARX" -xvf "$TMP/evil/$ev.tar" -C "$jail/dest" 2>&1)
	rc=$?

	# (a) refusal is loud and the exit status is nonzero
	if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q REFUSING; then
		ok "refuse[$ev]: nonzero exit and a REFUSING message"
	else
		no "refuse[$ev]: rc=$rc out=$(printf '%s' "$out" | tr '\n' ';')"
	fi

	# (b) nothing appeared next to dest, i.e. nothing escaped the destination
	stray=$(cd "$jail" && find . -mindepth 1 -maxdepth 1 ! -name dest)
	eq "refuse[$ev]: nothing written beside the destination" "$stray" ""

	# (c) and nothing with the payload landed anywhere under the jail
	hits=$(grep -rl PWNED "$jail" 2>/dev/null | tr '\n' ' ')
	eq "refuse[$ev]: payload never written" "$hits" ""
done
refute "the absolute-path canary $CANARY was never created" test -e "$CANARY"

# The refusal must be per-member, not fatal: in the mixed archive extracted by
# the loop above, the good members must have landed anyway.
assert "mixed archive: safe member before the bad one extracted" \
	test -f "$TMP/jail/mixed/dest/good.txt"
assert "mixed archive: safe member after the bad one extracted" \
	test -f "$TMP/jail/mixed/dest/also-good.txt"

# Refusal must not depend on the destination being empty: an existing symlink
# inside the destination must not be written through, even though the member
# name "link/escape" contains nothing suspicious at all.
rm -rf "$TMP/jail/pre"; mkdir -p "$TMP/jail/pre/dest" "$TMP/jail/pre/outside"
ln -s ../outside "$TMP/jail/pre/dest/link"
"$TARX" -xf "$TMP/evil/through_existing.tar" -C "$TMP/jail/pre/dest" >/dev/null 2>&1
refute "pre-existing symlink in dest is not written through" \
	test -e "$TMP/jail/pre/outside/escape"
assert "pre-existing symlink case still refuses loudly" \
	sh -c "'$TARX' -xf '$TMP/evil/through_existing.tar' -C '$TMP/jail/pre/dest' 2>&1 | grep -q REFUSING"

# ===================================================================== #
# 8. hostile / malformed input must not crash                           #
# ===================================================================== #
head -c 300 "$TMP/x.tar" >"$TMP/trunc_hdr.tar"
head -c 2000 "$TMP/x.tar" >"$TMP/trunc_mid.tar"
head -c 4096 /dev/urandom >"$TMP/random.tar"
: >"$TMP/zero.tar"
for bad in trunc_hdr trunc_mid random zero; do
	"$TARX" -tf "$TMP/$bad.tar" >/dev/null 2>&1
	rc=$?
	if [ "$rc" -lt 128 ]; then
		ok "malformed[$bad]: exits cleanly (rc=$rc), no signal"
	else
		no "malformed[$bad]: died with signal (rc=$rc)"
	fi
done

# A thousand single-byte mutations of a real archive: the header parser must
# never fault.  Cheap stand-in for the real fuzzer in PLAN.md.
python3 - "$TMP" "$TARX" <<'PY' && ok "1000 mutated archives: no crashes" || no "1000 mutated archives: crashed"
import random, subprocess, sys
tmp, tarx = sys.argv[1], sys.argv[2]
base = bytearray(open(tmp + '/x.tar', 'rb').read()[:60 * 512])
random.seed(1)
bad = []
for i in range(1000):
    m = bytearray(base)
    for _ in range(random.randint(1, 4)):
        m[random.randrange(len(m))] = random.randrange(256)
    p = subprocess.run([tarx, '-tvf', '-'], input=bytes(m),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if p.returncode < 0 or p.returncode >= 128:
        bad.append((i, p.returncode))
assert not bad, bad[:5]
PY

# ===================================================================== #
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
