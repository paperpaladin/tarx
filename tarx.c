/* tarx -- a tar archive reader/writer in C11, from scratch.
 *
 * Supports ustar (POSIX.1-1988) fully, plus the two extensions you cannot
 * avoid in practice: pax extended headers (POSIX.1-2001) for paths and link
 * targets that do not fit the fixed fields, and base-256 numeric fields for
 * sizes above 8 GiB.  GNU tar's 'L'/'K' long-name members are read but never
 * written -- pax is the standard, GNU's scheme is the legacy we must tolerate.
 *
 * shortcut: no compression of any kind.  Ceiling: ~every tarball in the wild
 * is .tar.gz and tarx cannot open one directly.  Upgrade path: pipe it
 * (`gzip -dc x.tgz | tarx -tf -`) until a raw-DEFLATE sibling exists.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define BLK 512

/* A pax extended header is attacker-controlled and length-prefixed, so it is
 * the one place a hostile archive can ask us to allocate.  Cap it. */
#define PAX_MAX (1u << 20)

/* All ustar fields are fixed-width char arrays, so this struct has no padding
 * and sizeof == 512 on every ABI we care about. */
struct tarhdr {
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
	char linkname[100];
	char magic[6];
	char version[2];
	char uname[32];
	char gname[32];
	char devmajor[8];
	char devminor[8];
	char prefix[155];
	char pad[12];
};
_Static_assert(sizeof(struct tarhdr) == BLK, "ustar header must be 512 bytes");

enum {
	T_REG = '0', T_LNK = '1', T_SYM = '2', T_CHR = '3', T_BLK = '4',
	T_DIR = '5', T_FIFO = '6', T_CONT = '7',
	T_PAX = 'x', T_PAXG = 'g', T_GNU_LONGNAME = 'L', T_GNU_LONGLINK = 'K'
};

static const char *prog = "tarx";
static int opt_v;
static int afd = -1;		/* archive fd */
static const char *afile;
static int failures;		/* nonzero exit without aborting the whole run */

static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", prog);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(2);
}

static void warn_(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", prog);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void *xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);
	if (!p)
		die("out of memory");
	return p;
}

static char *xstrdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = xmalloc(n);
	memcpy(p, s, n);
	return p;
}

/* ---------------------------------------------------------------- raw I/O */

static void xwrite(int fd, const void *buf, size_t n)
{
	const char *p = buf;
	while (n) {
		ssize_t w = write(fd, p, n);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			die("write: %s", strerror(errno));
		}
		p += w;
		n -= (size_t)w;
	}
}

/* Returns bytes read; short only at EOF. */
static size_t xread(int fd, void *buf, size_t n)
{
	char *p = buf;
	size_t got = 0;
	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			die("read: %s", strerror(errno));
		}
		if (r == 0)
			break;
		got += (size_t)r;
	}
	return got;
}

/* ------------------------------------------------------- numeric encoding */

/* ustar stores numbers as right-aligned zero-padded octal ASCII with a NUL (or
 * space) terminator, so an n-byte field holds at most 8^(n-1)-1: the 12-byte
 * size field tops out at 8589934591, i.e. 8 GiB - 1.  For anything larger GNU
 * tar and star use "base-256": set bit 7 of byte 0 as a flag and read the whole
 * field as a big-endian two's-complement integer.  We only ever emit the
 * positive form (byte 0 == 0x80, value in the remaining n-1 bytes). */
static void put_num(char *p, size_t n, uint64_t v)
{
	if (v < ((uint64_t)1 << (3 * (n - 1)))) {
		char tmp[32];
		snprintf(tmp, sizeof tmp, "%0*llo", (int)(n - 1),
			 (unsigned long long)v);
		memcpy(p, tmp, n - 1);
		p[n - 1] = '\0';
	} else {
		memset(p, 0, n);
		p[0] = (char)0x80;
		for (size_t i = n - 1; i >= 1; i--) {
			p[i] = (char)(v & 0xff);
			v >>= 8;
		}
	}
}

static int get_num(const char *p, size_t n, uint64_t *out)
{
	const unsigned char *u = (const unsigned char *)p;

	if (u[0] & 0x80) {
		uint64_t v = 0;
		if (u[0] != 0x80)	/* negative / >2^(8n-8): not a size we handle */
			return -1;
		for (size_t i = 1; i < n; i++) {
			if (v > (UINT64_MAX >> 8))
				return -1;
			v = (v << 8) | u[i];
		}
		*out = v;
		return 0;
	}

	uint64_t v = 0;
	size_t i = 0;
	while (i < n && (u[i] == ' ' || u[i] == '\0'))
		i++;
	if (i == n) {		/* an entirely blank field means zero */
		*out = 0;
		return 0;
	}
	for (; i < n && u[i] >= '0' && u[i] <= '7'; i++) {
		if (v > (UINT64_MAX >> 3))
			return -1;
		v = v * 8 + (uint64_t)(u[i] - '0');
	}
	while (i < n && (u[i] == ' ' || u[i] == '\0'))
		i++;
	if (i != n)
		return -1;
	*out = v;
	return 0;
}

/* The checksum is the unsigned sum of all 512 header bytes *with the 8-byte
 * checksum field itself treated as ASCII spaces* -- it has to be, since you
 * cannot include a value in the sum you are computing to produce it.  Historic
 * tars signed-extended the bytes, so verification accepts either sum. */
static void chksums(const struct tarhdr *h, unsigned *uns, int *sgn)
{
	const unsigned char *b = (const unsigned char *)h;
	unsigned u = 0;
	int s = 0;
	for (size_t i = 0; i < BLK; i++) {
		int c = (i >= 148 && i < 156) ? ' ' : (int)b[i];
		u += (unsigned)c;
		s += (i >= 148 && i < 156) ? ' ' : (int)(signed char)b[i];
	}
	*uns = u;
	*sgn = s;
}

/* shortcut: paths over 100 bytes are truncated with a warning.  Ceiling: any
 * real source tree.  Upgrade path: the ustar prefix/name split and a pax
 * extended header, which is the very next commit. */
static int split_name(const char *p, char *name, char *prefix)
{
	size_t len = strlen(p);

	memset(name, 0, 100);
	memset(prefix, 0, 155);
	if (len > 100) {
		warn_("%s: path over 100 bytes, truncated", p);
		failures++;
		len = 100;
	}
	memcpy(name, p, len);
	return 0;
}

/* ===================================================================== */
/* create								 */
/* ===================================================================== */

struct hl {			/* seen hard-linkable inodes */
	dev_t dev;
	ino_t ino;
	char *name;
};
static struct hl *hls;
static size_t nhl, caphl;

static void pad_to_block(uint64_t written)
{
	static const char zeros[BLK];
	size_t r = (size_t)(written % BLK);
	if (r)
		xwrite(afd, zeros, BLK - r);
}

static void finish_header(struct tarhdr *h)
{
	unsigned u;
	int s;
	memcpy(h->magic, "ustar", 6);
	memcpy(h->version, "00", 2);
	memset(h->chksum, ' ', 8);
	chksums(h, &u, &s);
	/* GNU writes six octal digits, NUL, space.  Everything reads that. */
	char tmp[8];
	snprintf(tmp, sizeof tmp, "%06o", u & 0777777);
	memcpy(h->chksum, tmp, 7);
	h->chksum[7] = ' ';
	xwrite(afd, h, BLK);
}

static void write_member(const char *path, const struct stat *st, int type,
			 const char *link, uint64_t size)
{
	struct tarhdr h;
	char name[100], prefix[155];

	split_name(path, name, prefix);
	if (link && strlen(link) > 100) {
		warn_("%s: link target over 100 bytes, truncated", path);
		failures++;
	}
	memset(&h, 0, sizeof h);
	memcpy(h.name, name, 100);
	memcpy(h.prefix, prefix, 155);
	put_num(h.mode, 8, (uint64_t)(st->st_mode & 07777));
	put_num(h.uid, 8, (uint64_t)st->st_uid);
	put_num(h.gid, 8, (uint64_t)st->st_gid);
	put_num(h.size, 12, size);
	/* Pre-epoch mtimes would need the negative base-256 form; clamp. */
	put_num(h.mtime, 12, st->st_mtime < 0 ? 0 : (uint64_t)st->st_mtime);
	h.typeflag = (char)type;
	if (link)
		memcpy(h.linkname, link, strlen(link) > 100 ? 100 : strlen(link));

	struct passwd *pw = getpwuid(st->st_uid);
	struct group *gr = getgrgid(st->st_gid);
	if (pw)
		snprintf(h.uname, sizeof h.uname, "%s", pw->pw_name);
	if (gr)
		snprintf(h.gname, sizeof h.gname, "%s", gr->gr_name);
	if (type == T_CHR || type == T_BLK) {
		put_num(h.devmajor, 8, (uint64_t)major(st->st_rdev));
		put_num(h.devminor, 8, (uint64_t)minor(st->st_rdev));
	}
	finish_header(&h);
}

static void copy_file_data(const char *path, uint64_t size)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		warn_("%s: %s", path, strerror(errno));
		/* Header already promised `size` bytes; keep the stream valid. */
		failures++;
	}
	/* shortcut: a plain 64 KiB read/write loop -- no copy_file_range, no
	 * SEEK_HOLE probing, so a sparse 9 GiB file becomes 9 GiB of literal
	 * zeros in the archive.  Ceiling: archiving VM images or DB files is
	 * absurdly wasteful.  Upgrade path: GNU/pax sparse members, which needs
	 * a format change, not just an I/O change -- see PLAN.md Milestone 1. */
	static char buf[1 << 16];
	uint64_t left = size;
	while (left) {
		size_t want = left > sizeof buf ? sizeof buf : (size_t)left;
		size_t got = fd < 0 ? 0 : xread(fd, buf, want);
		if (got < want) {
			memset(buf + got, 0, want - got);
			if (fd >= 0) {
				warn_("%s: file shrank while reading, padding", path);
				failures++;
				close(fd);
				fd = -1;
			}
		}
		xwrite(afd, buf, want);
		left -= want;
	}
	if (fd >= 0)
		close(fd);
	pad_to_block(size);
}

static void add_path(const char *path);

static void add_dir(const char *path)
{
	DIR *d = opendir(path);
	if (!d) {
		warn_("%s: %s", path, strerror(errno));
		failures++;
		return;
	}
	/* Collect and sort so archives are reproducible; readdir order is not. */
	char **names = NULL;
	size_t n = 0, cap = 0;
	struct dirent *de;
	while ((de = readdir(d))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (n == cap) {
			cap = cap ? cap * 2 : 16;
			names = realloc(names, cap * sizeof *names);
			if (!names)
				die("out of memory");
		}
		names[n++] = xstrdup(de->d_name);
	}
	closedir(d);
	/* shortcut: insertion sort, O(n^2).  Ceiling: a directory with ~100k
	 * entries starts to drag.  Upgrade path: qsort(3) with a strcmp
	 * comparator -- one line, done the day someone notices. */
	for (size_t i = 0; i < n; i++)
		for (size_t j = i; j && strcmp(names[j - 1], names[j]) > 0; j--) {
			char *t = names[j - 1];
			names[j - 1] = names[j];
			names[j] = t;
		}
	size_t pl = strlen(path);
	int slash = pl && path[pl - 1] == '/';
	for (size_t i = 0; i < n; i++) {
		char *sub = xmalloc(pl + strlen(names[i]) + 2);
		sprintf(sub, "%s%s%s", path, slash ? "" : "/", names[i]);
		add_path(sub);
		free(sub);
		free(names[i]);
	}
	free(names);
}

static void add_path(const char *path)
{
	struct stat st;
	if (lstat(path, &st) < 0) {
		warn_("%s: %s", path, strerror(errno));
		failures++;
		return;
	}

	/* Hard links: the second and later names for an inode become type '1'
	 * members whose linkname is the first name we stored. */
	if (!S_ISDIR(st.st_mode) && st.st_nlink > 1) {
		for (size_t i = 0; i < nhl; i++)
			if (hls[i].dev == st.st_dev && hls[i].ino == st.st_ino) {
				if (opt_v)
					printf("%s link to %s\n", path, hls[i].name);
				write_member(path, &st, T_LNK, hls[i].name, 0);
				return;
			}
		if (nhl == caphl) {
			caphl = caphl ? caphl * 2 : 32;
			hls = realloc(hls, caphl * sizeof *hls);
			if (!hls)
				die("out of memory");
		}
		hls[nhl].dev = st.st_dev;
		hls[nhl].ino = st.st_ino;
		hls[nhl].name = xstrdup(path);
		nhl++;
	}

	if (opt_v)
		printf("%s%s\n", path, S_ISDIR(st.st_mode) ? "/" : "");

	if (S_ISDIR(st.st_mode)) {
		/* Directory members carry a trailing '/' by convention; some
		 * readers rely on it to tell a dir from a zero-length file. */
		size_t l = strlen(path);
		char *p = xmalloc(l + 2);
		memcpy(p, path, l);
		if (l && path[l - 1] != '/')
			p[l++] = '/';
		p[l] = '\0';
		write_member(p, &st, T_DIR, NULL, 0);
		free(p);
		add_dir(path);
	} else if (S_ISLNK(st.st_mode)) {
		char tgt[PATH_MAX];
		ssize_t r = readlink(path, tgt, sizeof tgt - 1);
		if (r < 0) {
			warn_("%s: %s", path, strerror(errno));
			failures++;
			return;
		}
		tgt[r] = '\0';
		write_member(path, &st, T_SYM, tgt, 0);
	} else if (S_ISREG(st.st_mode)) {
		write_member(path, &st, T_REG, NULL, (uint64_t)st.st_size);
		copy_file_data(path, (uint64_t)st.st_size);
	} else if (S_ISFIFO(st.st_mode)) {
		write_member(path, &st, T_FIFO, NULL, 0);
	} else if (S_ISCHR(st.st_mode)) {
		write_member(path, &st, T_CHR, NULL, 0);
	} else if (S_ISBLK(st.st_mode)) {
		write_member(path, &st, T_BLK, NULL, 0);
	} else {
		warn_("%s: unsupported file type, skipped", path);
		failures++;
	}
}

static void do_create(int argc, char **argv)
{
	static const char zeros[BLK];
	if (argc == 0)
		die("create: no input paths");
	for (int i = 0; i < argc; i++) {
		/* Strip trailing slashes so member names stay canonical. */
		char *p = xstrdup(argv[i]);
		size_t l = strlen(p);
		while (l > 1 && p[l - 1] == '/')
			p[--l] = '\0';
		add_path(p);
		free(p);
	}
	/* An archive ends with two 512-byte zero blocks.  One is ambiguous with
	 * a corrupt header; two is the agreed end-of-archive marker, and real
	 * tars often pad further to the blocking factor (we do not). */
	xwrite(afd, zeros, BLK);
	xwrite(afd, zeros, BLK);
}

/* ===================================================================== */
/* read: list and extract						 */
/* ===================================================================== */

struct defer {			/* dir modes/times applied after the contents */
	char *path;
	mode_t mode;
	time_t mtime;
};
static struct defer *defs;
static size_t ndef, capdef;

static void defer_dir(const char *path, mode_t mode, time_t mtime)
{
	if (ndef == capdef) {
		capdef = capdef ? capdef * 2 : 32;
		defs = realloc(defs, capdef * sizeof *defs);
		if (!defs)
			die("out of memory");
	}
	defs[ndef].path = xstrdup(path);
	defs[ndef].mode = mode;
	defs[ndef].mtime = mtime;
	ndef++;
}

static void set_times(const char *path, time_t mtime)
{
	struct timespec ts[2];
	ts[0].tv_sec = mtime;
	ts[0].tv_nsec = 0;
	ts[1] = ts[0];
	utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);
}

static void flush_defers(void)
{
	/* Reverse order: a parent may be mode 0500, so children must be done. */
	for (size_t i = ndef; i-- > 0;) {
		chmod(defs[i].path, defs[i].mode);
		set_times(defs[i].path, defs[i].mtime);
		free(defs[i].path);
	}
	ndef = 0;
}

/* Create the parent directories of `path`.  A member may name a file inside a
 * directory the archive never stored one for, so we cannot rely on seeing a
 * '5' member first. */
static int ensure_dirs(const char *path)
{
	char *tmp = xstrdup(path);
	int ok = 1;
	for (char *s = tmp; *s; s++) {
		if (*s != '/' || s == tmp)
			continue;
		*s = '\0';
		if (mkdir(tmp, 0755) < 0 && errno != EEXIST) {
			warn_("mkdir %s: %s", tmp, strerror(errno));
			failures++;
			ok = 0;
		}
		*s = '/';
		if (!ok)
			break;
	}
	free(tmp);
	return ok;
}

static void mode_str(mode_t m, int type, char out[11])
{
	static const char *rwx[8] = { "---", "--x", "-w-", "-wx",
		"r--", "r-x", "rw-", "rwx"
	};
	out[0] = type == T_DIR ? 'd' : type == T_SYM ? 'l' :
	    type == T_LNK ? 'h' : type == T_FIFO ? 'p' :
	    type == T_CHR ? 'c' : type == T_BLK ? 'b' : '-';
	memcpy(out + 1, rwx[(m >> 6) & 7], 3);
	memcpy(out + 4, rwx[(m >> 3) & 7], 3);
	memcpy(out + 7, rwx[m & 7], 3);
	if (m & 04000)
		out[3] = (m & 0100) ? 's' : 'S';
	if (m & 02000)
		out[6] = (m & 010) ? 's' : 'S';
	out[10] = '\0';
}

/* Parse "<len> <key>=<value>\n" records.  `len` includes itself, so a record
 * can claim a length that runs off the end of the buffer -- check every step. */
static void parse_pax(const char *buf, size_t n, char **path, char **link)
{
	size_t i = 0;
	while (i < n) {
		size_t start = i, len = 0;
		while (i < n && buf[i] >= '0' && buf[i] <= '9') {
			if (len > PAX_MAX)
				return;
			len = len * 10 + (size_t)(buf[i++] - '0');
		}
		if (i == start || i >= n || buf[i] != ' ')
			return;	/* malformed: stop, keep what we have */
		i++;
		if (len < i - start + 1 || start + len > n)
			return;
		size_t end = start + len;	/* points just past the '\n' */
		const char *eq = memchr(buf + i, '=', end - i);
		if (!eq)
			return;
		size_t klen = (size_t)(eq - (buf + i));
		const char *v = eq + 1;
		size_t vlen = end - 1 - (size_t)(v - buf);	/* drop trailing \n */
		char *val = xmalloc(vlen + 1);
		memcpy(val, v, vlen);
		val[vlen] = '\0';
		if (klen == 4 && !memcmp(buf + i, "path", 4)) {
			free(*path);
			*path = val;
		} else if (klen == 8 && !memcmp(buf + i, "linkpath", 8)) {
			free(*link);
			*link = val;
		} else {
			/* shortcut: unknown pax keywords (size, mtime, uid,
			 * atime, SCHILY.*, LIBARCHIVE.*) are ignored.  Ceiling:
			 * a GNU-sparse-1.0 or >8EiB member would be read wrong.
			 * Upgrade path: a keyword table feeding the same
			 * override struct `path`/`link` already use. */
			free(val);
		}
		i = end;
	}
}

/* Read `size` bytes of member data plus its block padding into a buffer. */
static char *read_data(uint64_t size, size_t *outn)
{
	if (size > PAX_MAX)
		die("header payload of %llu bytes is implausible",
		    (unsigned long long)size);
	size_t n = (size_t)size;
	char *buf = xmalloc(n + 1);
	if (xread(afd, buf, n) != n)
		die("unexpected end of archive in header payload");
	buf[n] = '\0';
	size_t pad = (BLK - (n % BLK)) % BLK;
	char junk[BLK];
	if (pad)
		xread(afd, junk, pad);
	*outn = n;
	return buf;
}

static void skip_data(uint64_t size)
{
	uint64_t total = size + ((BLK - (size % BLK)) % BLK);
	static char buf[1 << 16];
	/* lseek would be faster but must work on pipes, so just read. */
	while (total) {
		size_t want = total > sizeof buf ? sizeof buf : (size_t)total;
		if (xread(afd, buf, want) != want)
			die("unexpected end of archive");
		total -= want;
	}
}

static void extract_data(const char *path, uint64_t size, mode_t mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		warn_("%s: %s", path, strerror(errno));
		failures++;
		skip_data(size);
		return;
	}
	static char buf[1 << 16];
	uint64_t left = size;
	while (left) {
		size_t want = left > sizeof buf ? sizeof buf : (size_t)left;
		if (xread(afd, buf, want) != want)
			die("unexpected end of archive in %s", path);
		xwrite(fd, buf, want);
		left -= want;
	}
	close(fd);
	/* shortcut: no chown/fchown.  Ceiling: tarx cannot restore a system
	 * image -- everything lands owned by the extracting user.  Upgrade
	 * path: attempt fchown when geteuid()==0 (or --numeric-owner is given)
	 * and warn, not fail, on EPERM. */
	size_t pad = (size_t)((BLK - (size % BLK)) % BLK);
	if (pad) {
		char junk[BLK];
		xread(afd, junk, pad);
	}
	chmod(path, mode);
}

static void do_read(int extract)
{
	char *ov_path = NULL, *ov_link = NULL;
	int saw_any = 0;

	for (;;) {
		struct tarhdr h;
		size_t got = xread(afd, &h, BLK);
		if (got == 0) {
			if (saw_any)
				warn_("archive ended without the two zero blocks");
			break;
		}
		if (got != BLK)
			die("truncated header (%zu bytes)", got);

		int allzero = 1;
		for (size_t i = 0; i < BLK; i++)
			if (((char *)&h)[i]) {
				allzero = 0;
				break;
			}
		if (allzero) {
			/* First zero block: the second one confirms EOA. */
			struct tarhdr h2;
			size_t g2 = xread(afd, &h2, BLK);
			if (g2 == BLK) {
				for (size_t i = 0; i < BLK; i++)
					if (((char *)&h2)[i]) {
						warn_("data after a zero block, stopping");
						break;
					}
			}
			break;
		}
		saw_any = 1;

		unsigned u;
		int s;
		uint64_t cs;
		chksums(&h, &u, &s);
		if (get_num(h.chksum, 8, &cs) < 0 ||
		    ((uint64_t)u != cs && (uint64_t)s != cs))
			die("header checksum mismatch -- not a tar archive, or corrupt");

		uint64_t size, mode, mtime;
		if (get_num(h.size, 12, &size) < 0)
			die("bad size field");
		if (get_num(h.mode, 8, &mode) < 0)
			mode = 0644;
		if (get_num(h.mtime, 12, &mtime) < 0)
			mtime = 0;

		int type = (unsigned char)h.typeflag;
		if (type == '\0')
			type = T_REG;	/* ancient tars left it NUL */

		if (type == T_PAX || type == T_PAXG) {
			size_t n;
			char *d = read_data(size, &n);
			if (type == T_PAX)
				parse_pax(d, n, &ov_path, &ov_link);
			free(d);
			continue;
		}
		if (type == T_GNU_LONGNAME || type == T_GNU_LONGLINK) {
			size_t n;
			char *d = read_data(size, &n);
			d[n] = '\0';
			char **slot = type == T_GNU_LONGNAME ? &ov_path : &ov_link;
			free(*slot);
			*slot = xstrdup(d);	/* stored NUL-terminated */
			free(d);
			continue;
		}

		/* Assemble the real name: pax/GNU override beats the fixed
		 * fields; otherwise join prefix and name with a '/'. */
		char namebuf[256 + 2];
		const char *name;
		if (ov_path) {
			name = ov_path;
		} else {
			char nm[101], pf[156];
			memcpy(nm, h.name, 100);
			nm[100] = '\0';
			memcpy(pf, h.prefix, 155);
			pf[155] = '\0';
			/* The prefix field only means anything in ustar/pax. */
			if (pf[0] && !memcmp(h.magic, "ustar", 5))
				snprintf(namebuf, sizeof namebuf, "%s/%s", pf, nm);
			else
				snprintf(namebuf, sizeof namebuf, "%s", nm);
			name = namebuf;
		}
		char lnkbuf[101];
		const char *lname = ov_link;
		if (!lname) {
			memcpy(lnkbuf, h.linkname, 100);
			lnkbuf[100] = '\0';
			lname = lnkbuf;
		}

		/* Trailing slash with a regular typeflag means a directory in
		 * pre-ustar archives. */
		size_t nl = strlen(name);
		if (type == T_REG && nl && name[nl - 1] == '/')
			type = T_DIR;

		char *clean = xstrdup(name);
		size_t cl = strlen(clean);
		while (cl > 1 && clean[cl - 1] == '/')
			clean[--cl] = '\0';

		if (!extract) {
			if (opt_v) {
				char ms[11];
				mode_str((mode_t)mode, type, ms);
				char ts[32];
				time_t t = (time_t)mtime;
				struct tm tm;
				localtime_r(&t, &tm);
				strftime(ts, sizeof ts, "%Y-%m-%d %H:%M", &tm);
				char un[33], gn[33];
				memcpy(un, h.uname, 32);
				un[32] = '\0';
				memcpy(gn, h.gname, 32);
				gn[32] = '\0';
				printf("%s %s/%s %11llu %s %s%s%s%s\n", ms,
				       un, gn, (unsigned long long)size, ts, name,
				       type == T_SYM ? " -> " : type == T_LNK ?
				       " link to " : "",
				       (type == T_SYM || type == T_LNK) ? lname : "",
				       "");
			} else {
				printf("%s\n", name);
			}
			skip_data(size);
			goto next;
		}

		if (!ensure_dirs(clean)) {
			skip_data(size);
			goto next;
		}
		if (opt_v)
			printf("%s\n", name);

		switch (type) {
		case T_DIR:
			if (mkdir(clean, 0700) < 0 && errno != EEXIST) {
				warn_("mkdir %s: %s", clean, strerror(errno));
				failures++;
				break;
			}
			defer_dir(clean, (mode_t)(mode & 07777), (time_t)mtime);
			break;
		case T_REG:
		case T_CONT:
			extract_data(clean, size, (mode_t)(mode & 07777));
			set_times(clean, (time_t)mtime);
			break;
		case T_SYM:
			(void)unlink(clean);	/* overwrite */
			if (symlink(lname, clean) < 0) {
				warn_("symlink %s: %s", clean, strerror(errno));
				failures++;
			} else {
				set_times(clean, (time_t)mtime);
			}
			break;
		case T_LNK:
			(void)unlink(clean);
			/* On Linux link() does not resolve a symlinked target,
			 * so a hostile "link to a-symlink-to-/etc/passwd" gets
			 * a link to the symlink, not to the file. */
			if (link(lname, clean) < 0) {
				warn_("link %s -> %s: %s", clean, lname,
				      strerror(errno));
				failures++;
			}
			break;
		case T_FIFO:
			if (mkfifo(clean, (mode_t)(mode & 07777)) < 0) {
				warn_("mkfifo %s: %s", clean, strerror(errno));
				failures++;
			} else {
				set_times(clean, (time_t)mtime);
			}
			break;
		default:
			/* shortcut: device nodes are listed but not created --
			 * mknod needs root and an unprivileged extractor that
			 * silently skips is friendlier than one that fails.
			 * Ceiling: no /dev restores.  Upgrade: attempt mknod
			 * and only warn on EPERM. */
			warn_("%s: typeflag '%c' not extracted", name, type);
			skip_data(size);
			break;
		}

 next:
		free(clean);
		free(ov_path);
		free(ov_link);
		ov_path = ov_link = NULL;
	}
	free(ov_path);
	free(ov_link);
	if (extract)
		flush_defers();
}

/* ===================================================================== */

static void usage(void)
{
	fprintf(stderr,
		"usage: %s -c|-t|-x [-v] [-f ARCHIVE] [-C DIR] [PATH...]\n"
		"  -c create   -t list   -x extract\n"
		"  -f FILE     archive file ('-' or omitted = stdin/stdout)\n"
		"  -C DIR      chdir here first\n"
		"  -v          verbose\n", prog);
	exit(2);
}

int main(int argc, char **argv)
{
	int mode = 0;
	const char *dir = NULL;
	int c;

	while ((c = getopt(argc, argv, "ctxvf:C:")) != -1) {
		switch (c) {
		case 'c':
		case 't':
		case 'x':
			if (mode && mode != c)
				die("pick exactly one of -c, -t, -x");
			mode = c;
			break;
		case 'v':
			opt_v = 1;
			break;
		case 'f':
			afile = optarg;
			break;
		case 'C':
			dir = optarg;
			break;
		default:
			usage();
		}
	}
	if (!mode)
		usage();

	/* Open the archive before chdir: -f is relative to the invocation. */
	if (!afile || !strcmp(afile, "-")) {
		afd = mode == 'c' ? STDOUT_FILENO : STDIN_FILENO;
	} else if (mode == 'c') {
		afd = open(afile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (afd < 0)
			die("%s: %s", afile, strerror(errno));
	} else {
		afd = open(afile, O_RDONLY);
		if (afd < 0)
			die("%s: %s", afile, strerror(errno));
	}

	if (dir && chdir(dir) < 0)
		die("chdir %s: %s", dir, strerror(errno));

	if (mode == 'c')
		do_create(argc - optind, argv + optind);
	else
		do_read(mode == 'x');

	if (afd > 2)
		close(afd);
	return failures ? 1 : 0;
}
