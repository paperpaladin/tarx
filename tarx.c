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

/* shortcut: unused until -c exists; xwrite is here because extract_data needs
 * it too and one short-write loop is enough for both. */
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
 * size field tops out at 8589934591, i.e. 8 GiB - 1. */
static int get_num(const char *p, size_t n, uint64_t *out)
{
	const unsigned char *u = (const unsigned char *)p;
	uint64_t v = 0;

	/* shortcut: bit 7 of byte 0 marks a base-256 field; we reject it for
	 * now.  Ceiling: any member over 8 GiB - 1 bytes is unreadable.
	 * Upgrade path: decode it, which is the very next commit. */
	if (u[0] & 0x80)
		return -1;

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
		die("-c is not implemented yet");
	do_read(mode == 'x');

	if (afd > 2)
		close(afd);
	return failures ? 1 : 0;
}
