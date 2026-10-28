#!/bin/bash
# tarx test harness.  GNU tar is the oracle: every interop claim below is
# checked against the real thing, in both directions.  Set TARX_SKIP_BIG=1 to
# skip the 9 GiB base-256 tests (the asan build does, they are I/O bound).
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
TARX=$ROOT/tarx
GNUTAR=${GNUTAR:-tar}

# Scratch carries the pid, and is removed on the way out. It was $HERE/tmp,
# wiped at the start of every run, so two runs of this suite at once deleted
# each other's fixtures mid-test. Hit for real: two instances of
# .portfolio/extract.py overlapped and the repos with fixed scratch names
# reported failures they do not have.
#
# Nothing used to remove it afterwards either, which left this repo's symlink
# zoo -- a dangling link, an over-long one, and a loop 42 levels deep, all
# built on purpose because refusing to follow a hostile symlink is what tarx
# is for -- sitting in the tree permanently. unrepro could not check this repo
# at all because of it: shutil.copytree follows symlinks by default, so it
# raised on the dangling one and ELOOP on the loop, and reported a traceback
# instead of a verdict. unrepro now copies links as links; this stops leaving
# them behind in the first place.
#
# chmod before rm because the suite restores modes out of archives, and a
# directory extracted without write permission cannot be deleted until it has
# some.
TMP=$HERE/tmp.$$
trap 'chmod -R u+rwX "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT INT TERM

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
	echo suid >"$d/suid"; chmod 4755 "$d/suid"
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

# A tar archive is untrusted input, so setuid/setgid bits from one must not be
# honoured by an unprivileged extractor.  GNU tar drops them without -p; so do
# we, and the oracle is what says what "right" means here.
eq "setuid bit dropped on tarx extract (matches GNU default)" \
	"$(stat -c %a "$TMP/rt/tree/suid")" "$(stat -c %a "$TMP/gx/tree/suid")"
refute "setuid bit is not restored from an archive" \
	sh -c "[ \"$(stat -c %a "$TMP/rt/tree/suid")\" = 4755 ]"
# ...but the bit IS in the archive, so `tar -xp` can get it back.
mkdir -p "$TMP/gp"
"$GNUTAR" -xpf "$TMP/x.tar" -C "$TMP/gp" 2>/dev/null
eq "tarx stored the setuid bit verbatim (GNU -xp restores 4755)" \
	"$(stat -c %a "$TMP/gp/tree/suid")" 4755

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
# 6b. GNU sparse members, all four encodings GNU tar can still write    #
# ===================================================================== #
# The whole point of a sparse file is where the holes are, so the fixture has
# a hole at offset 0, six more at different offsets, and ends in a hole -- the
# last is the classic off-by-one, because only the final ftruncate puts it
# back.  `holes` has eight data extents, more than the four an old-GNU 'S'
# header can hold, so it also forces the continuation-block chain.
#
# Three things are asserted per format and they catch different failures.
# `cmp` against the original catches a hole in the wrong PLACE, because the
# bytes move.  The apparent size catches a lost trailing hole.  And
# `stat -c %b` against what GNU TAR'S OWN EXTRACTION allocated catches writing
# the holes out as real zero blocks -- compared to the oracle rather than to a
# number of our own, because whether a gap becomes a hole is the filesystem's
# decision and not ours.
mkdir -p "$TMP/sparse"
python3 - "$TMP/sparse" <<'PY'
import sys, os
d = sys.argv[1]
f = open(os.path.join(d, 'holes'), 'wb')
f.seek(1 << 20)                     # hole at the very start
for i in range(8):
    f.seek((2 * i + 2) << 19)       # 512 KiB of data every 1 MiB
    f.write(bytes([65 + i]) * (1 << 19))
f.truncate(10 << 20)                # ... and a 1 MiB hole at the very end
f.close()
open(os.path.join(d, 'allhole'), 'wb').truncate(1 << 20)   # nothing but hole
open(os.path.join(d, 'dense'), 'wb').write(b'not sparse at all\n')
PY

# A fixture with no holes tests nothing, so prove this one has them before
# believing anything below.
sp_apparent=$(stat -c %s "$TMP/sparse/holes")
sp_alloc=$(stat -c %b "$TMP/sparse/holes")
if [ "$((sp_alloc * 512))" -lt "$((sp_apparent / 2))" ]; then
	ok "sparse fixture really is sparse ($sp_alloc blocks for $sp_apparent bytes)"
else
	no "sparse fixture is not sparse: $sp_alloc blocks for $sp_apparent bytes"
fi

# Which encoding is actually in the archive.  --sparse-version is only honoured
# by --format=posix; gnu and oldgnu write the old 'S' header whatever is asked
# for, so without this the five legs below could all be testing one format.
cat >"$TMP/sparsefmt.py" <<'PY'
import sys
d = open(sys.argv[1], 'rb').read()
off, seen = 0, set()
while off + 512 <= len(d) and d[off:off+512] != b'\0' * 512:
    h = d[off:off+512]
    tf = chr(h[156])
    size = int(h[124:136].rstrip(b'\0 ').decode() or '0', 8)
    off += 512
    if tf == 'S':
        seen.add('oldgnu-S')
        # The continuation blocks of an 'S' map sit between the header and
        # the data and are NOT counted in the size field.  Walking over them
        # as though they were headers is how the first version of this
        # checker crashed on exactly the archives it was written for.
        ext = h[482]
        while ext:
            ext = d[off + 504]
            off += 512
    elif tf == 'x':
        body = d[off:off+size]
        if b'GNU.sparse.major=1' in body:
            seen.add('1.0')
        elif b'GNU.sparse.map=' in body:
            seen.add('0.1')
        elif b'GNU.sparse.numbytes=' in body:
            seen.add('0.0')
    off += ((size + 511) // 512) * 512
print(','.join(sorted(seen)) or 'none')
PY

sparse_leg() {
	local tag=$1 want=$2; shift 2
	local ar=$TMP/sp-$tag.tar
	rm -rf "$TMP/sp-x-$tag" "$TMP/sp-g-$tag"
	mkdir -p "$TMP/sp-x-$tag" "$TMP/sp-g-$tag"
	if ! "$GNUTAR" --sparse "$@" -cf "$ar" -C "$TMP/sparse" \
	     holes allhole dense 2>/dev/null; then
		no "GNU tar writes $tag sparse members"
		return
	fi
	eq "GNU tar really wrote $tag (oracle sanity)" \
		"$(python3 "$TMP/sparsefmt.py" "$ar")" "$want"
	assert "sparse[$tag]: tarx -x succeeds" \
		"$TARX" -xf "$ar" -C "$TMP/sp-x-$tag"
	"$GNUTAR" -xf "$ar" -C "$TMP/sp-g-$tag" 2>/dev/null
	local f
	for f in holes allhole dense; do
		# apparent size AND allocated blocks, both against GNU's own
		# extraction of the same archive.
		eq "sparse[$tag]: $f size and allocation match GNU's extract" \
			"$(stat -c '%s %b' "$TMP/sp-x-$tag/$f" 2>/dev/null)" \
			"$(stat -c '%s %b' "$TMP/sp-g-$tag/$f" 2>/dev/null)"
		assert "sparse[$tag]: $f is byte-identical to the original" \
			cmp "$TMP/sparse/$f" "$TMP/sp-x-$tag/$f"
	done
	# -t must report the apparent size, not the stored one.
	eq "sparse[$tag]: tarx -tv reports the apparent sizes" \
		"$("$TARX" -tvf "$ar" | awk '{print $3}' | tr '\n' ' ')" \
		"$("$GNUTAR" -tvf "$ar" | awk '{print $3}' | tr '\n' ' ')"
	rm -rf "$TMP/sp-x-$tag" "$TMP/sp-g-$tag" "$ar"
}

sparse_leg oldgnu  oldgnu-S --format=oldgnu
sparse_leg gnu     oldgnu-S --format=gnu
sparse_leg pax0.0  0.0      --format=posix --sparse-version=0.0
sparse_leg pax0.1  0.1      --format=posix --sparse-version=0.1
sparse_leg pax1.0  1.0      --format=posix --sparse-version=1.0

# Three hops with GNU in the middle: tarx has to read a sparse member and
# write it back as an ordinary dense one that GNU still accepts.  tarx cannot
# write sparse members yet, so this is the whole of the write half.
mkdir -p "$TMP/sp-hop" "$TMP/sp-hop-out"
"$GNUTAR" --sparse --format=gnu -cf "$TMP/sp-hop.tar" -C "$TMP/sparse" holes
"$TARX" -xf "$TMP/sp-hop.tar" -C "$TMP/sp-hop" 2>/dev/null
assert "sparse: tarx -> GNU reads back the de-sparsed member" \
	sh -c "'$TARX' -cf - -C '$TMP/sp-hop' holes | '$GNUTAR' -xf - -C '$TMP/sp-hop-out'"
assert "sparse: GNU -> tarx -> GNU is byte-identical" \
	cmp "$TMP/sparse/holes" "$TMP/sp-hop-out/holes"
rm -rf "$TMP/sp-hop" "$TMP/sp-hop-out" "$TMP/sp-hop.tar" "$TMP/sparse" \
	"$TMP/sparsefmt.py"

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

# One canary per absolute path the evil archives aim at. There used to be
# only /tmp/tarx-should-never-write-this, and the `abs_prefix` member aims at
# /tmp/escape -- prefix "/tmp" plus name "escape" -- which is neither inside
# the jail nor that canary. So for that case checks (b) and (c) below could
# not observe the escape at all (both look only under $jail) and the whole
# assertion rested on (a), the REFUSING message. A stub that printed REFUSING
# and wrote the payload outside the jail passed all three.
CANARIES="/tmp/tarx-should-never-write-this /tmp/escape"
CANARY=/tmp/tarx-should-never-write-this
for c in $CANARIES; do rm -f "$c"; done
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

	# (c) and nothing with the payload landed anywhere under the jail, or
	# at any of the absolute paths these archives aim at. The second half
	# is what makes this meaningful for abs_prefix and absolute, whose
	# targets are outside $jail by construction.
	hits=$(grep -rl PWNED "$jail" $CANARIES 2>/dev/null | tr '\n' ' ')
	eq "refuse[$ev]: payload never written" "$hits" ""
done
for c in $CANARIES; do
	refute "the absolute-path canary $c was never created" test -e "$c"
done

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

# A sparse map is as attacker-controlled as a path is, and the byte-flip
# fuzzer below will essentially never produce an 'S' typeflag by chance, so
# the two ways a map can lie get their own hand-written archives.
python3 - "$TMP" <<'PY'
import sys
tmp = sys.argv[1]

def shdr(name, stored, realsize, pairs, isext=0):
    h = bytearray(512)
    h[0:len(name)] = name.encode()
    h[100:108] = b'%07o\0' % 0o644
    h[108:116] = b'%07o\0' % 0
    h[116:124] = b'%07o\0' % 0
    h[124:136] = b'%011o\0' % stored
    h[136:148] = b'%011o\0' % 0
    h[148:156] = b' ' * 8
    h[156] = ord('S')
    h[257:263] = b'ustar '
    h[263:265] = b' \0'
    for i, (o, n) in enumerate(pairs):
        h[386+i*24:386+i*24+12] = b'%011o\0' % o
        h[386+i*24+12:386+i*24+24] = b'%011o\0' % n
    h[482] = isext
    h[483:495] = b'%011o\0' % realsize
    h[148:156] = b'%06o\0 ' % sum(h)
    return bytes(h)

# isextended says another map block follows, and the archive stops instead.
open(tmp + '/sp_trunc.tar', 'wb').write(shdr('t', 0, 1 << 20, [], isext=1))
# The map claims 64 KiB of data where the member stores 512 bytes, and the
# archive is long enough that reading the difference would SUCCEED, swallowing
# the blocks that follow.  Without the used+want>stored guard this extracts a
# 1 MiB file full of the rest of the archive instead of failing.
open(tmp + '/sp_overclaim.tar', 'wb').write(
    shdr('t', 512, 1 << 20, [(0, 1 << 16)]) + b'Z' * 512 + b'\0' * (200 * 512))
# An extent that ends past the apparent size.  GNU tar calls this an invalid
# sparse archive member and exits 2; the assertion below makes it say so.
open(tmp + '/sp_short.tar', 'wb').write(
    shdr('t', 512, 0, [(0, 512)]) + b'Z' * 512 + b'\0' * 1024)
PY
for bad in sp_trunc sp_overclaim sp_short; do
	rm -rf "$TMP/spjail-$bad"; mkdir -p "$TMP/spjail-$bad"
	"$TARX" -xf "$TMP/$bad.tar" -C "$TMP/spjail-$bad" >/dev/null 2>&1
	rc=$?
	if [ "$rc" -ge 1 ] && [ "$rc" -lt 128 ]; then
		ok "malformed[$bad]: refused cleanly (rc=$rc), no signal"
	else
		no "malformed[$bad]: rc=$rc (want nonzero and under 128)"
	fi
done
# The refusal has to be a refusal, not a partial extraction: nothing may be
# written past the bytes the member actually stores.
eq "malformed[sp_overclaim]: no data written past the stored size" \
	"$(stat -c %s "$TMP/spjail-sp_overclaim/t" 2>/dev/null || echo missing)" "0"
# ... and GNU tar must agree that sp_short is invalid, or we are refusing a
# member the format allows.
refute "GNU tar also rejects sp_short (oracle sanity)" \
	"$GNUTAR" -xf "$TMP/sp_short.tar" -C "$TMP/spjail-sp_short"

# A thousand mutations of a real archive, 1 to 4 bytes each: the header parser must
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
