# tarx

A tar archive reader and writer in one file of C11 -- ustar plus the pax and
base-256 extensions needed for long paths and huge files -- checked against GNU
tar in both directions, and hardened to refuse any member that would be written
outside the destination.

```
tarx -c|-t|-x [-v] [-f ARCHIVE] [-C DIR] [PATH...]
```

```sh
make
./tarx -cvf src.tar src          # create
./tarx -tvf src.tar              # list, long form
./tarx -xf src.tar -C /tmp/out   # extract
./tarx -cf - src | gzip > src.tgz   # pipes: -f - is stdin/stdout
```

## Why this exists

tar is the only archive format you cannot avoid, and it is far simpler than its
reputation: a 512-byte header of ASCII octal fields, the file's bytes padded to
512, repeat, two zero blocks at the end. The complexity is entirely in three
places that are easy to get *almost* right:

* **the checksum**, which is the unsigned sum of all 512 header bytes *with the
  checksum field itself counted as eight ASCII spaces* -- it has to be, since you
  cannot include a value in the sum you are computing to produce it;
* **the `prefix`/`name` split**, which lets a 255-byte path into a format whose
  name field is 100 bytes, but only if there is a `/` in exactly the right
  window -- and pax extended headers, which exist because often there is not;
* **base-256 numeric fields**, which are how a size above 8 GiB fits in twelve
  bytes that were specified as octal ASCII.

The second reason is the extractor. `tar -x` is the textbook path-traversal
sink, and "it extracted my files" is not evidence that it is safe. Writing one
from scratch forces you to confront every way a member can aim outside the
destination -- including the ones that have no `..` in them anywhere.

## The oracle

GNU tar 1.35 is the authority: if tarx and tar disagree, tarx is wrong, because
tar *is* the format. The harness drives both directions.

**tarx writes, GNU tar reads.** `tarx -c` on a tree containing nested
directories, a symlink, a relative symlink, a dangling symlink, a symlink whose
*target* is 121 bytes (so it needs pax `linkpath=`), a hard link, an empty file,
a mode-0700 file, a mode-0400 file, a setuid file, filenames containing a space
and non-ASCII UTF-8, a binary file full of NUL and 0xFF bytes, a 150-byte path
that *can* be ustar-split and a 150-byte path that cannot. Then `tar -tvf` must list every member, `tar -xf` must extract it, and
`diff -r --no-dereference` must report nothing -- with `stat` and `readlink`
checked explicitly on top, because `diff` does not compare modes and, without
`--no-dereference`, does not compare symlinks either.

**GNU tar writes, tarx reads.** The same tree through `--format=gnu`,
`--format=oldgnu`, `--format=posix` and `--format=ustar`, each extracted by
`tarx -x` and compared the same way. This is what proves tarx reads *both*
long-name conventions: `posix` delivers the 150-byte path in a pax `path=`
record, `gnu` and `oldgnu` deliver it in an `L` member.

**Round trips.** `tarx -> tarx`, and the three-hop `tarx -> GNU tar -> tarx`.

**Byte-level assertions.** `diff -r` passing proves the two agree; it does not
prove the encoding is *right*. Emitting a pax header for every long path would
pass every test above. So a reader walks the raw 512-byte blocks of the archive
tarx produced and asserts that the splittable path went into `prefix`+`name`
with no pax header, that the unsplittable one produced a `path=` record, that
the long symlink produced a `linkpath=` record, and that the file ends in
exactly two zero blocks and no more.

**8 GiB.** A 9 GiB (`truncate -s 9G`) member, piped so neither side needs 9 GiB
of archive on disk: `tarx -cf - | tar -tvf -` must report 9663676416, and
`tar -cf - | tarx -tvf -` must too, and `tarx -cf - | tarx -xf -` must produce a
file `cmp` calls identical. If the filesystem refuses the 9 GiB file the harness
says so and skips, rather than passing quietly.

**What the interop test caught.** Three real things, all of them invisible to
a tarx-only round trip:

1. **tarx was honouring setuid/setgid/sticky bits from an untrusted archive.**
   `tarx -c` and GNU tar wrote byte-identical mode fields (`0004755`), but GNU
   tar extracted the file as `0755` and tarx extracted it as `04755`. GNU is
   right: plain `tar -x` deliberately drops those bits unless you are root or
   pass `-p`, because an archive should not be able to hand an unprivileged user
   a setuid file they did not ask for. tarx now drops them the same way, and the
   harness asserts both halves -- that the extracted bit is gone, *and* that
   `tar -xpf` on our archive still recovers `4755`, proving we stored it rather
   than dropped it on the way in.
2. **The harness itself was lying about symlinks.** `diff -r` follows symbolic
   links, so the original `diff -r tree out` compared what each link *pointed
   at* rather than the link -- it would have passed an extractor that got every
   target wrong, and it aborted outright on a dangling link. `diff -r
   --no-dereference` plus an explicit `readlink` per link turned three vacuous
   passes into real ones.
3. **Strict ustar genuinely cannot hold the test tree.** `tar --format=ustar`
   refuses to dump both the unsplittable 150-byte name (`file name is too long
   (cannot be split); not dumped`) and the 121-byte symlink target (`link name
   is too long`). That is the oracle stating, in its own words, that the
   `prefix`/`name` split is not a general solution and pax is not optional -- so
   the ustar leg of the suite runs against a fixture with those two members
   removed, and says why.

## Security

**An extractor must never write outside its destination, and `tarx` refuses
rather than sanitises.** Silently rewriting `../../etc/passwd` into
`etc/passwd` means the file you were warned about lands somewhere you did not
expect, so every unsafe member gets a loud `REFUSING` line on stderr, is
skipped, and makes the process exit nonzero. Safe members in the same archive
still extract.

Five distinct checks, because there are five distinct attacks:

| attack | check |
| --- | --- |
| `/etc/cron.d/x` -- absolute member path | reject any name starting with `/` |
| `../../escape` -- `..` component | reject any path component equal to `..` |
| symlink `link` -> `/etc`, then a member under `link/` | reject absolute symlink targets |
| symlink `d/link` -> `../../escape` | walk the target from the link's own directory; reject if the depth ever goes below the extraction root |
| member `sub/up` is a legal symlink to `..`, then member `sub/up/escape` -- **nothing suspicious in either name** | `lstat` every parent component before creating it and refuse if any is a symlink; write files with `unlink` then `O_CREAT\|O_EXCL\|O_NOFOLLOW` so no open can ever resolve through a link |

The checks run on the *final* name, after pax and GNU overrides are applied --
the easiest way to get this wrong is to validate `header.name` and then let a
pax `path=../escape` record replace it.

### The test that proves it

`t/run.sh` builds fifteen hostile archives and extracts each into a fresh
`jail/<case>/dest`. Headers are hand-written in Python (the checksum computed
over spaces, exactly as the format requires) because GNU tar will not emit most
of these -- but two cases *are* built by GNU `tar -P`, and the harness first
asserts via `tar -tf` that the nasty path really is in there, so the oracle
vouches that the attack is genuine before we claim to have stopped it.

For every case three things are asserted: tarx exited nonzero with a `REFUSING`
message; `find jail/<case> -maxdepth 1 ! -name dest` is **empty**, i.e. nothing
appeared beside the destination; and `grep -rl PWNED jail/<case>` finds
**nothing**, i.e. the payload was never written anywhere. A `/tmp` canary path
covers the absolute case from the far side. The cases are:

```
dotdot  dotdot_deep  absolute  abs_prefix   (prefix field holding "/tmp")
symabs  symesc  symdeep  hardesc
pax_dotdot  pax_abs      (malicious path smuggled in via a pax record)
gnu_dotdot                (...via a GNU 'L' long-name member)
via_symlink               (the two-member symlink-parent attack)
mixed                     (good, bad, good -- the good two must still land)
```

Plus: a destination that *already* contains `link -> ../outside` must not be
written through; malformed input (truncated header, truncated mid-member,
4 KiB of `/dev/urandom`, empty file) must exit cleanly and never on a signal;
and 1000 mutations of a real archive -- 1 to 4 bytes each, not one -- are fed
to the header parser asserting no crash. `make test-asan` sets
`TARX_SKIP_BIG=1`, so it runs 113 of the 118 under
`-fsanitize=address,undefined`; the five it drops are the 9 GiB sparse cases.
That is still the build that matters most, since every byte the parser
touches is attacker-controlled. (This said "the whole suite", contradicted
ninety lines below by the same README's "runs those 113".) Valgrind is clean on
create, list and extract too.

## make test

```
$ make test
cc -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter -D_FILE_OFFSET_BITS=64 -o tarx tarx.c
ok   tarx -c exits 0
ok   tarx -c is silent on stderr
ok   GNU tar -tvf accepts a tarx archive
ok   GNU tar sees every member tarx wrote
ok   GNU tar -xf extracts a tarx archive
ok   tarx->GNU: diff -r byte-identical
ok   tarx->GNU: mode 0700 preserved
ok   tarx->GNU: mode 0400 preserved
ok   tarx->GNU: symlink target preserved
ok   tarx->GNU: relative symlink preserved
ok   tarx->GNU: dangling symlink preserved
ok   tarx->GNU: hard link shares an inode
ok   tarx->GNU: empty file is empty
ok   tarx->GNU: NUL-containing binary identical
ok   tarx->GNU: mtime preserved
ok   GNU(gnu)->tarx: list succeeds
ok   GNU(gnu)->tarx: list has 40 members
ok   GNU(gnu)->tarx: extract succeeds
ok   GNU(gnu)->tarx: diff -r byte-identical
ok   GNU(gnu)->tarx: mode 0700 preserved
ok   GNU(gnu)->tarx: symlink target preserved
ok   GNU(gnu)->tarx: hard link shares an inode
ok   GNU(gnu)->tarx: mtime preserved
ok   GNU(oldgnu)->tarx: list succeeds
...
ok   GNU tar writes --format=ustar for the splittable tree
ok   GNU(ustar)->tarx: extract succeeds
ok   GNU(ustar)->tarx: diff -r byte-identical
ok   tarx->tarx round trip extracts
ok   tarx->tarx: diff -r byte-identical
ok   tarx->tarx: mode 0700 preserved
ok   tarx->tarx: symlink target preserved
ok   tarx->tarx: hard link shares an inode
ok   tarx->GNU->tarx triple hop extracts
ok   tarx->GNU->tarx: diff -r byte-identical
ok   setuid bit dropped on tarx extract (matches GNU default)
ok   setuid bit is not restored from an archive
ok   tarx stored the setuid bit verbatim (GNU -xp restores 4755)
ok   tarx->GNU: >100 byte symlink target preserved (pax linkpath)
ok   tarx->tarx: >100 byte symlink target preserved
ok   long paths use the right encodings
ok   archive ends with two 512-byte zero blocks
ok   tarx->GNU: GNU tar reads our base-256 9G size
ok   GNU->tarx: tarx reads GNU's base-256 9G size
ok   tarx round-trips a 9G member
ok   9G member extracts at full size
ok   9G member is byte-identical
ok   GNU tar -P really stored '../escape' (oracle sanity)
ok   GNU tar -P really stored an absolute path (oracle sanity)
ok   refuse[abs_prefix]: nonzero exit and a REFUSING message
ok   refuse[abs_prefix]: nothing written beside the destination
ok   refuse[abs_prefix]: payload never written
ok   refuse[absolute]: nonzero exit and a REFUSING message
ok   refuse[absolute]: nothing written beside the destination
ok   refuse[absolute]: payload never written
ok   refuse[dotdot]: nonzero exit and a REFUSING message
ok   refuse[dotdot]: nothing written beside the destination
ok   refuse[dotdot]: payload never written
...
ok   refuse[via_symlink]: nonzero exit and a REFUSING message
ok   refuse[via_symlink]: nothing written beside the destination
ok   refuse[via_symlink]: payload never written
ok   refuse[gnu_dotdot_real]: nonzero exit and a REFUSING message
ok   refuse[gnu_dotdot_real]: nothing written beside the destination
ok   refuse[gnu_dotdot_real]: payload never written
ok   refuse[gnu_absolute_real]: nonzero exit and a REFUSING message
ok   refuse[gnu_absolute_real]: nothing written beside the destination
ok   refuse[gnu_absolute_real]: payload never written
ok   the absolute-path canary /tmp/tarx-should-never-write-this was never created
ok   mixed archive: safe member before the bad one extracted
ok   mixed archive: safe member after the bad one extracted
ok   pre-existing symlink in dest is not written through
ok   pre-existing symlink case still refuses loudly
ok   malformed[trunc_hdr]: exits cleanly (rc=2), no signal
ok   malformed[trunc_mid]: exits cleanly (rc=2), no signal
ok   malformed[random]: exits cleanly (rc=2), no signal
ok   malformed[zero]: exits cleanly (rc=0), no signal
ok   1000 mutated archives: no crashes

118 passed, 0 failed
```

(Elided with `...` for length; the full run prints 118 `ok` lines and takes
about 35 seconds, nearly all of it the 9 GiB member. `TARX_SKIP_BIG=1 t/run.sh`
drops to 113 tests in under a second, and `make test-asan` runs those 113 under
`-fsanitize=address,undefined`.)

## Status

**What works**: ustar read and write; directories, regular files, symlinks
(including relative and dangling ones), hard links, FIFOs; mode bits and mtime;
paths over 100 bytes via both the `prefix`/`name` split and pax `path=`; link
targets over 100 bytes via pax `linkpath=`; sizes over 8 GiB via base-256;
reading pax `x`/`g` headers and GNU `L`/`K` members; the two-zero-block
terminator; `-f -` for pipes; the full traversal-refusal set above. Clean under
`-Wall -Wextra`, ASan, UBSan and Valgrind.

**What does not work** -- honestly:

* **No compression.** No `-z`/`-j`/`-J`. Pipe through `gzip`.
* **No sparse-file support, in either direction.** A 9 GiB hole is archived as
  9 GiB of literal zeros and extracted as 9 GiB of real blocks. GNU `--sparse`
  members (`typeflag` `S`, `GNU.sparse.*` pax records) are not understood and
  will extract wrongly rather than being rejected -- this is the worst remaining
  gap and the first item in PLAN.md.
* **No xattrs, ACLs, SELinux labels or capabilities.** Silently dropped.
* **No ownership restore.** We never `chown`, so everything lands owned by the
  extracting user. uid/gid/uname/gname *are* stored and shown by `-tv`.
* **No device nodes created** on extract (listed, then skipped -- `mknod` needs
  root).
* **Pax keywords other than `path` and `linkpath` are ignored**, including
  `size`, `mtime`, `uid` and `gname`. For `--format=posix` archives whose values
  do fit the fixed fields this is harmless; for the rare ones where they do not,
  tarx uses the fallback field and gets it wrong.
* **Permission-bit policy diverges from GNU tar in one direction.** Like plain
  `tar -x`, tarx drops setuid/setgid/sticky bits unless it is running as root
  (the archive still *stores* them, so `tar -xp` recovers them). Unlike plain
  `tar -x`, tarx does **not** apply the umask to the remaining 0777 bits, so a
  mode-0666 member extracts as 0666 where GNU tar would give 0644 -- tarx behaves
  like `tar -xp` there. There is no `-p` flag to choose.
* **No sub-second mtime**; pre-epoch mtimes are clamped to 0 rather than
  encoded in negative base-256.
* **No `-r`/`-u`/`--delete`/`--diff`**, no member selection, no wildcards, no
  `--exclude`, no `--strip-components`, no incremental or multi-volume
  archives, no `--blocking-factor` (output is never padded past the two zero
  blocks, which is legal but unlike GNU's default 20-block padding).
* **The symlink-escape analysis is lexical**, backed by a per-component
  `lstat` and `O_NOFOLLOW` opens. That is correct against a hostile *archive*,
  which is the threat model, but it is TOCTOU-racy against a hostile *process*
  writing into the destination concurrently. An `openat`-rooted rewrite is in
  PLAN.md.
* **Not fast.** 64 KiB `read`/`write` loops, no `copy_file_range`, no
  `sendfile`, no hole detection. `qsort` is an insertion sort.

## Design

One file, 1181 lines, three parts.

*Header codec.* A `struct tarhdr` of nothing but `char` arrays, so it has no
padding and a `_Static_assert` pins `sizeof` at 512. `put_num`/`get_num` handle
the octal form and the base-256 form; `chksums` computes the unsigned and
signed sums at once, so verification can accept the historic signed variant
while we only ever write the unsigned one.

*Create.* A recursive walk that sorts each directory so archives are
reproducible, a small `(dev, ino) -> first name` table that turns the second and
later names for an inode into `typeflag '1'` members, and `split_name`, which
decides between the `prefix` split and a pax header. The pax record length field
counts itself, so computing it is a two-iteration fixed point.

*Read.* One loop over 512-byte blocks. Pax `x` and GNU `L`/`K` members set
`ov_path`/`ov_link` overrides consumed by the *next* real member -- which is also
why the security checks live after the name is assembled rather than where the
header is parsed. Directory modes and mtimes are deferred to a list and applied
in reverse at the end, because a mode-0500 directory has to be writable while
its children are being created. Extraction never seeks, so stdin works.

Deliberate shortcuts are marked with `shortcut:` comments naming the ceiling
and the upgrade path; `PLAN.md` tracks them as forward work.

## License

GPL-3.0-or-later. See `LICENSE`.
