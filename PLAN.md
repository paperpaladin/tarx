# tarx

## Contract

`tarx` is a tar archive reader and writer: one C11 file, no libraries, no
shelling out.

```
tarx -c|-t|-x [-v] [-f ARCHIVE] [-C DIR] [PATH...]
```

* `-c` writes an archive of `PATH...` (directories recursed, sorted).
* `-t` lists it; `-tv` lists it long-form.
* `-x` extracts it.
* `-f FILE` names the archive; `-` or omitted means stdin/stdout, so `tarx`
  works in a pipe and never needs to seek.
* `-C DIR` chdirs first. `-f` is resolved before the chdir, as GNU tar does.

In scope, on both the write and the read side:

* regular files, directories, symlinks, hard links, FIFOs
* permission bits and mtime.  setuid/setgid/sticky are always *stored*; they
  are only *restored* when extracting as root, matching plain `tar -x`.
* paths longer than 100 bytes, by **ustar `prefix`/`name` split** when the path
  has a `/` in the legal window, and by **pax extended header** (`path=`) when
  it does not
* link targets longer than 100 bytes, by pax `linkpath=`
* files larger than 8 GiB, by **base-256 numeric fields**
* GNU `L`/`K` long-name members and pax headers on read (we never write `L`/`K`)
* the terminating pair of 512-byte zero blocks

Exit status: 0 success, 1 something was skipped or refused, 2 the archive is
not parseable.

## Hard invariant

**1. GNU tar and tarx agree in both directions.** Anything `tarx -c` writes,
GNU `tar -tvf` lists correctly and `tar -xf` extracts to byte-identical files
with the same modes, symlink targets and hard-link identity. Anything GNU tar
writes in `v7`-through-`pax` format, `tarx -t` lists and `tarx -x` extracts to
byte-identical files. This is not a design goal, it is the acceptance test: if
the two disagree, tarx is wrong, because tar is the format.

**2. No member can ever be written outside the destination.** Not by an
absolute path, not by `..`, not by a symlink whose target climbs out, not by a
file written *through* a symlink that an earlier member of the same archive
created, not by a malicious path smuggled in via a pax `path=` record or a GNU
`L` header. The response is refusal with a nonzero exit, never silent
sanitisation -- an extractor that quietly rewrites the paths you asked about is
worse than one that stops.

## Oracle

Ranked, strongest first.

1. **GNU tar 1.35, bidirectionally.** `tarx -c` -> `tar -xf` -> `diff -r
   --no-dereference` plus explicit `stat`/`readlink`/inode comparisons, and the
   reverse for `--format=` each of `gnu`, `oldgnu`, `posix`, `ustar`. Also the
   three-hop `tarx -> GNU -> tarx`. Non-negotiable: tar defines the format.
2. **Byte-level assertions on the archive tarx produced.** `diff -r` passing
   proves the pair agree, not that the encoding is right -- a pax header for
   *every* long path would also pass. A Python reader walks the raw 512-byte
   blocks and asserts the splittable 150-byte path used `prefix`+`name` with no
   pax header, the unsplittable one produced a `path=` record, the 122-byte
   symlink target produced a `linkpath=` record, and the file ends in exactly
   two zero blocks and no more.
3. **Traversal refusal, with the escape proven absent.** Fifteen hostile
   archives (hand-written headers, plus two built by GNU `tar -P` so the oracle
   itself vouches that the nasty path really is in there). Each asserts a
   nonzero exit, a `REFUSING` message, that nothing appeared beside the
   destination directory, and that the payload string exists nowhere under the
   jail. A `/tmp` canary path checks the absolute case from the other side.
4. **`diff -r --no-dereference`, not `diff -r`.** Plain `diff -r` follows
   symlinks, so it compares what a link points at and not the link -- it would
   pass an extractor that got every target wrong, and it fails outright on a
   dangling one.
5. **ASan + UBSan over the whole harness** (`make test-asan`), plus 1000
   single-byte mutations of a real archive fed to the header parser, asserting
   no process ever dies on a signal. Valgrind is clean on create, list and
   extract but is not wired into `make test`.
6. **`cmp` on a 9 GiB member**, and the size field read back through GNU tar
   and through tarx, piped so neither side needs 9 GiB of archive on disk.

## Non-goals

* Compression. No gzip, bzip2, xz, zstd. Pipe it: `tarx -cf - d | gzip >d.tgz`.
* Sparse-file encoding. A 9 GiB hole is archived as 9 GiB of zeros and
  extracted as 9 GiB of real blocks; GNU `--sparse` members are not read.
* xattrs, ACLs, SELinux labels, capabilities.
* Restoring ownership. We never `chown`, so an unprivileged extract gives you
  your own uid rather than failing. uid/gid/uname/gname are stored and listed.
* Creating device nodes (`mknod` needs root).
* Appending, updating, deleting, `--diff`, member selection, wildcards,
  `--exclude`, `--strip-components`, incremental archives, volume labels,
  multi-volume archives, `--blocking-factor`.
* Sub-second mtime precision (no pax `mtime=` with a fraction).
* A `-p`/`--preserve-permissions` flag. tarx always restores the 0777 bits
  exactly (ignoring umask, like `tar -xp`) and always drops setuid/setgid/sticky
  unless root (like plain `tar -x`). One fixed policy, no flag to pick.
* Being fast. The data path is a 64 KiB `read`/`write` loop with no `sendfile`,
  no `copy_file_range`, no hole detection.

## Commit sequence

- [x] ustar header: the 512-byte struct, octal and base-256 numeric fields,
      the checksum-over-spaces rule
      why: every other decision depends on these three being exactly right,
      and all three are the parts people get subtly wrong.
- [x] `-c` for regular files, dirs, symlinks, hard links, FIFOs; sorted
      traversal; two trailing zero blocks
      why: produce something GNU tar can read before trying to read anything,
      so the oracle can be pointed at us from day one.
- [x] long paths: `prefix`/`name` split, pax `path=`/`linkpath=` fallback
      why: the 100-byte limit is the first wall every real tree hits, and the
      split rules are fiddly enough to deserve their own step.
- [x] `-t`/`-x`: pax and GNU `L`/`K` on read, deferred directory
      modes/mtimes, `-C`, stdin/stdout archives
      why: deferring dir metadata is the only way a mode-0500 directory
      extracts with its children intact.
- [x] security: absolute/`..` refusal, symlink-target escape analysis,
      `lstat` on every parent component, `unlink`+`O_EXCL|O_NOFOLLOW` writes
      why: this is the whole reason the project is interesting; it goes in
      before any convenience feature, not after.
- [x] the harness: bidirectional GNU interop, byte-level encoding assertions,
      fifteen hostile archives, malformed input, 1000 mutations, 9 GiB
      why: a claim about tar interop that is not checked against tar is a
      guess.
- [x] drop setuid/setgid/sticky bits on extract unless root
      why: the oracle caught us restoring 04755 where GNU tar restored 0755.
      GNU is right -- an untrusted archive must not be able to hand an
      unprivileged user a setuid file -- and it is a one-line policy, so it
      belongs in the first release rather than a TODO.

### Milestone 1 -- the gaps that bite real users

- [ ] read GNU sparse members (`typeflag` `S`, and pax
      `GNU.sparse.*` / sparse 1.0 map members)
      why: `tar --sparse` is common on VM images and database files, and we
      currently fail them with a confusing size mismatch rather than a clear
      "unsupported".
- [ ] write sparse members by probing holes with `SEEK_HOLE`/`SEEK_DATA`
      why: archiving a 9 GiB hole as 9 GiB of literal zeros is the single
      worst behaviour in the tool today.
- [ ] `-z` via a `../inflate` sibling (raw DEFLATE, no zlib): decompress on
      read first, then fixed-Huffman compression on create
      why: ~every tarball in the wild is `.tar.gz`, piping through `gzip` is
      only a workaround when `gzip` is installed, and shipping only the read
      half would be a half-feature.
- [ ] a real fuzzing harness over the header parser: a
      `tarx_parse_one(buf, len)` entry point plus an `-fsanitize=fuzzer`
      target, with a seed corpus of the archives the test suite already builds
      why: 1000 scripted byte flips is a smoke test; coverage-guided fuzzing
      is what actually finds the parser bug we have not thought of.
- [ ] pax `size=`, `mtime=` (with fraction), `uid=`, `gid=`, `uname=`,
      `gname=` keywords on read, via a keyword table
      why: GNU `--format=posix` emits these for values the fixed fields cannot
      hold, and we currently ignore them and use the (wrong) fallback field.
- [ ] xattrs and ACLs: `SCHILY.xattr.*` records on read and write
      why: restoring a tree with capabilities or SELinux labels silently
      loses them today, which is the dangerous kind of data loss.
- [ ] `--numeric-owner` and a root-mode `chown`/`mknod` path
      why: tarx cannot currently be used to restore a system image.
- [ ] `--strip-components=N` and member-name selection on extract
      why: the two options everybody reaches for within ten minutes of using
      a tar clone.
- [ ] replace the lexical symlink-escape analysis with `openat`-relative
      extraction rooted at a destination fd
      why: lexical analysis plus per-component `lstat` is correct but
      TOCTOU-racy against a concurrent writer in the destination; an
      `O_PATH` root fd and `openat` everywhere makes escape structurally
      impossible rather than checked.
- [ ] `--list-verbose` time zone and locale handling to match GNU byte for
      byte, then diff the two listings in the harness
      why: right now the harness compares member *sets*, not the full `-tv`
      output, so a formatting divergence would go unnoticed.
- [ ] `-p`/`--preserve-permissions` and umask-aware extraction, so the two
      permission policies are selectable and both match GNU exactly
      why: tarx currently sits between GNU's two modes (no umask like `-xp`,
      no setuid like plain `-x`), which is defensible but is a divergence the
      harness documents rather than tests away.
- [ ] `-r`/`-u` (append and update) by seeking back over the zero blocks
      why: requires the archive fd to be seekable, which is the first place
      the pipe-friendly design has to grow a special case.
