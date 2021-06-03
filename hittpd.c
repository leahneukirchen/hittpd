/* hittpd - efficient, no-frills HTTP 1.1 server */

/* Copyright 2020, 2021 Leah Neukirchen <leah@vuxu.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#define TIMEOUT 60
#define MAX_CLIENTS 1024

#ifdef __linux__
#include <sys/sendfile.h>
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "http_parser.h"

#ifdef __GLIBC__
// POSIX 2008 is hard, let's go shopping.
char *strptime(const char *restrict, const char *restrict, struct tm *restrict);
#endif

struct conn_data {
	enum { NONE, HOST, IMS, RANGE, OTHER, SENDING } state;
	char *host;
	char *ims;
	char *path;
	int fd;

	/* state needed:
	   - if serving file: fd, range and offset
	   - if serving string: string, range and offset
	 */

	off_t off, first, last;
	int stream_fd;
	char *buf;

	time_t deadline;
};

char mimetypes[] =
    ":.html=text/html"
    ":.htm=text/html"
    ":.gif=image/gif"
    ":.jpeg=image/jpeg"
    ":.jpg=image/jpeg"
    ":.png=image/png"
    ":.css=text/css"
    ":.js=application/javascript"
    ":.txt=text/plain"
    ":.xml=text/xml"
    ":.xsl=text/xml"
    ":.pdf=application/pdf"
    ":.svg=image/svg+xml"
    ":.ico=image/x-icon";

const char *default_mimetype = "application/octet-stream";
char default_vhost[] = "_default";
char default_port[] = "80";

const char *wwwroot = "/var/www";
int tilde = 0;
int vhost = 0;
int quiet = 0;
int show_index = 1;
int only_public = 0;
int reuse_port = 0;
const char *custom_mimetypes = "";

static int
on_url(http_parser *p, const char *s, size_t l)
{
	struct conn_data *data = p->data;

	size_t len = data->path ? strlen(data->path) : 0;
	char *new = realloc(data->path, len + l + 1);
	if (!new)
		return 1;
	data->path = new;
	memcpy(data->path + len, s, l);
	data->path[len + l] = 0;

	return 0;
}

static int
on_header_field(http_parser *p, const char *s, size_t l)
{
	struct conn_data *data = p->data;

	if (l == 4 && strncasecmp(s, "host", l) == 0)
		data->state = HOST;
	else if (l == 17 && strncasecmp(s, "if-modified-since", l) == 0)
		data->state = IMS;
	else if (l == 5 && strncasecmp(s, "range", l) == 0)
		data->state = RANGE;
	else
		data->state = OTHER;    // ignore others

	return 0;
}

int scan_int64(const char **s, int64_t *u) {
	const char *t = *s;
	long x;
	for (x = 0; *t && (unsigned)(*t)-'0' < 10 && x <= LLONG_MAX/10 - 1; t++)
		x = x * 10 + ((*t)-'0');
	if (t != *s) {
		*s = t;
		*u = x;
		return 1;
	}
	return 0;
}

void
parse_range(struct conn_data *data, const char *s, size_t l)
{
	if (strncmp("bytes=", s, 6) != 0)
		goto invalid;

	const char *e = s + l;
	s += 6;

	if (*s == '-') {
		s++;
		if (!(scan_int64(&s, &(data->first)) && s == e))
			goto invalid;
		data->first = -data->first;
		data->last = -1;
	} else {
		if (!(scan_int64(&s, &(data->first)) && *s == '-'))
			goto invalid;
		s++;
		if (s == e)
			data->last = -1;
		else if (!(scan_int64(&s, &(data->last)) && s == e))
			goto invalid;
	}

	return;

invalid:
	data->first = data->last = -666;
}

static int
on_header_value(http_parser *p, const char *s, size_t l)
{
	struct conn_data *data = p->data;

	if (data->state == HOST && !data->host)
		data->host = strndup(s, l);
	else if (data->state == IMS && !data->ims)
		data->ims = strndup(s, l);
	else if (data->state == RANGE)
		parse_range(data, s, l);

	// ignore others

	return 0;
}

void
httpdate(time_t t, char *buf)
{
	strftime(buf, 64, "%a, %d %b %Y %H:%M:%S %Z", gmtime(&t));
}

static time_t
parse_http_date(char *s)
{
	struct tm tm;

	if (strlen(s) != 29)
		return 0;

	if (!strptime(s, "%a, %d %b %Y %T GMT", &tm))
		return 0;

	return timegm(&tm);
}


const char *
peername(int fd)
{
	struct sockaddr_storage ss;
	socklen_t slen = sizeof ss;
	static char addrbuf[NI_MAXHOST];

	if (getpeername(fd, (struct sockaddr *)&ss, &slen) < 0)
		return "0.0.0.0";
	if (getnameinfo((struct sockaddr *)&ss, slen,
	    addrbuf, sizeof addrbuf, 0, 0, NI_NUMERICHOST) < 0)
		return "0.0.0.0";

	if (strncmp("::ffff:", addrbuf, 7) == 0)
		return addrbuf + 7;

	return addrbuf;
}

static inline intmax_t
content_length(struct conn_data *data)
{
	return data->last - data->first;
}

time_t now;
char timestamp[64];

void
accesslog(http_parser *p, int status)
{
	if (quiet)
		return;

	struct conn_data *data = p->data;

	char buf[64];
	strftime(buf, 64, "[%d/%b/%Y:%H:%M:%S %z]", localtime(&now));

//	REMOTEHOST - - [DD/MON/YYYY:HH:MM:SS -TZ] "METHOD PATH" STATUS BYTES
// ?    REFERER USER_AGENT
	printf("%s - - %s \"%s ",
	    peername(data->fd),
	    buf,
	    http_method_str(p->method));

	for (char *s = data->path; *s; s++)
		if (*s < 32 || *s >= 127 || *s == '"')
			printf("%%%02x", *s);
		else
			putchar(*s);

	printf("\" %d %jd\n",
	    status,
	    p->method == HTTP_HEAD ? 0 : content_length(data));
}

int send_error(http_parser *p, int status, const char *msg);

void
send_response(http_parser *p, int status, const char *msg,
    const char *extra_headers, const char *content)
{
	struct conn_data *data = p->data;
	char buf[2048];

	if (content) {
		data->first = 0;
		data->last = strlen(content);
	}

	if (p->method == HTTP_HEAD)
		content = "";

	int len = 0;

	len += snprintf(buf, sizeof buf,
	    "HTTP/%d.%d %d %s\r\n"
	    "Date: %s\r\n"
	    "%s",
	    p->http_major,
	    p->http_minor,
	    status, msg,
	    timestamp,
	    extra_headers);

	if (len >= (int)sizeof buf) {
		send_error(p, 413, "Payload Too Large");
		return;
	}

	if (!(status == 204 || status == 304)) {
		len += snprintf(buf + len, sizeof buf - len,
		    "Content-Length: %jd\r\n",
		    content_length(data));

		if (len >= (int)sizeof buf) {
			send_error(p, 413, "Payload Too Large");
			return;
		}
	}

	len += snprintf(buf + len, sizeof buf - len,
	    "\r\n"
	    "%s",
	    content ? content : "");

	if (len >= (int)sizeof buf) {
		send_error(p, 413, "Payload Too Large");
		return;
	}

	write(data->fd, buf, len);
	accesslog(p, status);
}

int
send_error(http_parser *p, int status, const char *msg)
{
	char content[512];
	snprintf(content, sizeof content, "%03d %s\r\n", status, msg);

	send_response(p, status, msg, "", content);

	return 0;
}

void
send_dir_redirect(http_parser *p)
{
	struct conn_data *data = p->data;

	char headers[PATH_MAX + 64];
	snprintf(headers, sizeof headers, "Location: %s/\r\n", data->path);

	send_response(p, 301, "Moved Permanently", headers,
	    "301 Moved Permanently\r\n");
}

void
send_not_modified(http_parser *p, time_t modified)
{
	char lastmod[64], headers[128];
	httpdate(modified, lastmod);
	snprintf(headers, sizeof headers, "Last-Modified: %s\r\n", lastmod);

	send_response(p, 304, "Not Modified", headers, "");
}

void
send_rns(http_parser *p, off_t filesize)
{
	char headers[64];
	snprintf(headers, sizeof headers, "Content-Range: bytes */%jd\r\n",
	    (intmax_t)filesize);

	send_response(p, 416, "Requested Range Not Satisfiable", headers, "");
}

void
print_urlencoded(FILE *stream, char *s)
{
	while (*s)
		switch (*s) {
		case ';':
		case '/':
		case '?':
		case ':':
		case '@':
		case '=':
		case '&':
		case '"':
		case '#':
		case '<':
		case '>':
		case '%':
		escape:
			fprintf(stream, "%%%02x", (unsigned char)*s++);
			break;
		default:
			if (*s <= 32 || (unsigned char)*s >= 127)
				goto escape;
			fputc(*s++, stream);
		}
}

void
print_htmlencoded(FILE *stream, char *s)
{
	while (*s)
		switch (*s) {
		case '&':
		case '"':
		case '<':
		case '>':
			fprintf(stream, "&#x%x;", *s++);
			break;
		default:
			fputc(*s++, stream);
		}
}

void
send_ok(http_parser *p, time_t modified, const char *mimetype, off_t filesize)
{
	struct conn_data *data = p->data;

	char headers[512];
	char lastmod[64];
	httpdate(modified, lastmod);

	if (data->first == 0 && data->last == filesize) {
		snprintf(headers, sizeof headers,
		    "Content-Type: %s\r\n"
		    "Last-Modified: %s\r\n",
		    mimetype,
		    lastmod);
		send_response(p, 200, "OK", headers, 0);
	} else {
		snprintf(headers, sizeof headers,
		    "Content-Type: %s\r\n"
		    "Content-Range: bytes %jd-%jd/%jd\r\n"
		    "Last-Modified: %s\r\n",
		    mimetype,
		    (intmax_t)data->first,
		    (intmax_t)data->last - 1,
		    (intmax_t)filesize,
		    lastmod);
		send_response(p, 206, "Partial Content", headers, 0);
	}
}

const char *
mimetype(char *ext)
{
	static char type[16];

	if (!ext)
		return default_mimetype;

	char *x = strstr(custom_mimetypes, ext);
	if (!x)
		x = strstr(mimetypes, ext);

	if (x && x[-1] == ':' && x[strlen(ext)] == '=') {
		char *t = type;
		for (char *c = x + strlen(ext) + 1; *c && *c != ':'; )
			*t++ = *c++;
		*t = 0;
		return type;
	}

	return default_mimetype;
}

static inline int
unhex(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else
		return -1;
}

static int
on_message_complete(http_parser *p) {
	struct conn_data *data = p->data;

	data->state = SENDING;

	if (p->http_major == 0 && p->http_minor == 9)
		return send_error(p, 400, "Bad Request");

	char path[PATH_MAX];
	char name[PATH_MAX + 128];
	char *s = data->path, *t = path, *pe = path + sizeof path - 1;

	for (size_t i = 0; s[i]; i++) {
		if (s[i] == '%') {
			int c1 = unhex(s[i+1]);
			if (c1 < 0)
				return send_error(p, 400, "Bad Request");

			int c2 = unhex(s[i+2]);
			if (c2 < 0)
				return send_error(p, 400, "Bad Request");

			char d = (c1 << 4) | c2;

			if (d == 0 || d == '/')
				return send_error(p, 400, "Bad Request");

			*t++ = d;
			i += 2;
		} else if (s[i] == 0) {
			return send_error(p, 400, "Bad Request");
		} else if (s[i] == '?') {
			break;
		} else {
			*t++ = s[i];
		}

		if (t >= pe)
			return send_error(p, 413, "Payload Too Large");
	}
	*t = 0;

	if (!(p->method == HTTP_GET || p->method == HTTP_HEAD))
		return send_error(p, 405, "Method Not Allowed");

	if (path[0] != '/' || strstr(path, "/../"))
		return send_error(p, 403, "Forbidden");

	if (tilde && path[1] == '~' && path[2]) {
		char *e = strchr(path + 1, '/');
		if (e)
			*e = 0;

		struct passwd *pw = getpwnam(path + 2);
		if (!pw || pw->pw_uid < 1000)
			return send_error(p, 404, "Not Found");

		snprintf(name, sizeof name, "%s/public_html/%s",
		    pw->pw_dir, e ? e + 1 : "");

		if (e)
			*e = '/';
	} else if (vhost) {
		char *host = data->host;
		if (!host) {
			host = default_vhost;
		} else {
			char *s = host;
			for (; *s && *s != ':' && *s != '/'; s++)
				*s = tolower(*s);
			*s = 0;
		}
		if (!*host || *host == '.' || strstr(host, ".."))
			return send_error(p, 403, "Forbidden");

		struct stat dst;
		snprintf(name, sizeof name, "%s/%s", wwwroot, host);
		if (stat(name, &dst) < 0 || !S_ISDIR(dst.st_mode))
			host = default_vhost;

		snprintf(name, sizeof name, "%s/%s%s", wwwroot, host, path);
	} else {
		snprintf(name, sizeof name, "%s%s", wwwroot, path);
	}

	int stream_fd = open(name, O_RDONLY);

	if (stream_fd < 0) {
		if (errno == EACCES || errno == EPERM)
			return send_error(p, 403, "Forbidden");
		else if (errno == ENOENT || errno == ENOTDIR)
			return send_error(p, 404, "Not Found");
		else if (errno == ENAMETOOLONG)
			return send_error(p, 413, "Payload Too Large");
		else {
			perror("open");
			return send_error(p, 500, "Internal Server Error");
		}
	}

	struct stat st;
	if (fstat(stream_fd, &st) < 0)
		return send_error(p, 500, "Internal Server Error");

	if (only_public && !(st.st_mode & S_IROTH))
		return send_error(p, 403, "Forbidden");

	if (S_ISDIR(st.st_mode)) {
		int x;
		if (path[strlen(path)-1] == '/' &&
		    (x = openat(stream_fd, "index.html", O_RDONLY)) >= 0) {
			close(stream_fd);
			stream_fd = x;
			if (fstat(stream_fd, &st) < 0)
				return send_error(p, 500, "Internal Server Error");
			if (only_public && !(st.st_mode & S_IROTH))
				return send_error(p, 403, "Forbidden");
			goto file;
		}

		if (path[strlen(path)-1] != '/') {
			close(stream_fd);
			data->stream_fd = -1;

			send_dir_redirect(p);
			return 0;
		}

		if (!show_index) {
			close(stream_fd);
			data->stream_fd = -1;

			return send_error(p, 403, "Forbidden");
		}

		char *buf;
		size_t len;

		FILE *stream = open_memstream(&buf, &len);
		if (!stream)
			return 1;

		fprintf(stream, "<!doctype html><meta charset=\"utf-8\">"
		    "<title>Index of ");
		print_htmlencoded(stream, path);
		fprintf(stream, "</title>"
		    "<h1>Index of ");
		print_htmlencoded(stream, path);
		fprintf(stream, "</h1>\n<hr>\n<pre>\n");

		struct dirent **namelist;
		int n = scandir(name, &namelist, 0, alphasort);

		for (int i = 0; i < n; i++) {
			char *file = namelist[i]->d_name;
			if (file[0] == '.' && file[1] == 0)
				continue;

			struct stat ist;
			if (fstatat(stream_fd, file, &ist, AT_SYMLINK_NOFOLLOW) < 0)
				continue;

			if (only_public && !(ist.st_mode & S_IROTH))
				continue;

			fprintf(stream, "<a href=\"");
			print_urlencoded(stream, file);
			fprintf(stream, "%s\">",
			    S_ISDIR(ist.st_mode) ? "/" : "");
			print_htmlencoded(stream, file);
			fprintf(stream, "%s</a>",
			    S_ISDIR(ist.st_mode) ? "/" : "");

			int len = strlen(file) + !!S_ISDIR(ist.st_mode);
			fprintf(stream, "%-*.*s ", 48 - len, 48 - len, "");

			char timestamp[64];
			strftime(timestamp, sizeof timestamp,
			    "%Y-%m-%d %H:%M", localtime(&ist.st_mtime));

			if (S_ISDIR(ist.st_mode))
				fprintf(stream, " %s %12s\n", timestamp, "-");
			else
				fprintf(stream, " %s %12jd\n", timestamp,
				    (intmax_t)ist.st_size);

		}

		while (n--)
			free(namelist[n]);
		free(namelist);

		fprintf(stream, "</pre>\n<hr>\n");
		fclose(stream);

		close(stream_fd);
		data->stream_fd = -1;

		data->buf = buf;
		data->first = 0;
		data->last = len;
		send_ok(p, now, "text/html", len);

		return 0;
	}

file:
	if (data->ims) {
		time_t t = parse_http_date(data->ims);
		if (t >= st.st_mtime) {
			send_not_modified(p, st.st_mtime);
			return 0;
		}
	}

	data->stream_fd = stream_fd;

	char *ext = strrchr(path, '.');
	if (ext && strchr(ext, '/'))
		ext = 0;

	if (data->first == -666 && data->last == -666) {
		send_rns(p, st.st_size);
		return 0;
	}

	if (data->first < 0)
		data->first = st.st_size + data->first;
	if (data->last == -1)
		data->last = st.st_size;


	if (data->first > data->last) {
		send_rns(p, st.st_size);
		return 0;
	}

	if (data->first < 0)
		data->first = 0;
	if (data->last > st.st_size)
		data->last = st.st_size;

	send_ok(p, st.st_mtime, mimetype(ext), st.st_size);

	// XXX send short file directly?

	return 0;
}

static http_parser_settings settings = {
	.on_message_complete = on_message_complete,
	.on_header_field = on_header_field,
	.on_header_value = on_header_value,
	.on_url = on_url,
};

struct pollfd client[MAX_CLIENTS];
struct http_parser parsers[MAX_CLIENTS];
struct conn_data datas[MAX_CLIENTS];

void
close_connection(int i)
{
	if (client[i].fd >= 0)
		close(client[i].fd);
	client[i].fd = -1;

	free(datas[i].buf);
	free(datas[i].path);
	free(datas[i].ims);
	free(datas[i].host);

	datas[i] = (struct conn_data){ 0 };
}

void
finish_response(int i)
{
	if (datas[i].stream_fd >= 0)
		close(datas[i].stream_fd);
	datas[i].stream_fd = -1;

	free(datas[i].buf);
	free(datas[i].path);
	free(datas[i].ims);
	free(datas[i].host);

	datas[i].buf = 0;
	datas[i].path = 0;
	datas[i].ims = 0;
	datas[i].host = 0;

	datas[i].off = 0;
	datas[i].first = 0;
	datas[i].last = -1;
	datas[i].state = NONE;

	client[i].events = POLLRDNORM;

	if (parsers[i].flags & F_CONNECTION_CLOSE)
		close_connection(i);
	else if (parsers[i].flags & F_CONNECTION_KEEP_ALIVE)
		;
	else if ((parsers[i].http_major == 1 && parsers[i].http_minor == 0) ||
	    parsers[i].http_major == 0)
		close_connection(i);    // HTTP 1.0 default
}

void
accept_client(int i, int fd)
{
	fcntl(fd, F_SETFL, O_NONBLOCK);

	client[i].fd = fd;

	http_parser_init(&parsers[i], HTTP_REQUEST);
	datas[i] = (struct conn_data){ 0 };
	datas[i].fd = fd;
	datas[i].stream_fd = -1;
	datas[i].last = -1;
	datas[i].deadline = now + TIMEOUT;

	parsers[i].data = &datas[i];

	client[i].events = POLLRDNORM;
}

void
write_client(int i)
{
	struct conn_data *data = &datas[i];
	int sockfd = client[i].fd;
	ssize_t w = 0;

	if (data->stream_fd >= 0) {
#ifndef __linux__
		char buf[16*4096];
		ssize_t n = pread(data->stream_fd, buf, sizeof buf, data->off);
		if (n < 0) {
			if (errno == EAGAIN)
				return;
			close_connection(i);
		} else if (n == 0) {
			finish_response(i);
		} else if (n > 0) {
			w = write(sockfd, buf, n);
			if (w > 0)
				data->off += w;
			if (data->off == data->last)
				finish_response(i);
			else if (w == 0)
				close_connection(i);  // file was truncated!
		}
#else
		w = sendfile(sockfd, data->stream_fd,
		    &(data->off), data->last - data->off);
		if (data->off == data->last)
			finish_response(i);
		else if (w == 0)
			close_connection(i);  // file was truncated!
#endif
	} else if (data->buf) {
		if (data->off == data->last) {
			finish_response(i);
		} else {
			w = write(sockfd, data->buf, data->last - data->off);
			if (w > 0)
				data->off += w;
		}
	} else {
		finish_response(i);
		w = 0;
	}

	if (w < 0) {
		if (errno == EAGAIN)
			return;
		close_connection(i);  // in particular, EPIPE and ECONNRESET
	}
}

void
read_client(int i)
{
	struct conn_data *data = &datas[i];
	int sockfd = client[i].fd;
	ssize_t n;
	char buf[1024];

	if ((n = read(sockfd, buf, sizeof buf)) < 0) {
		if (errno == ECONNRESET) {
			close_connection(i);
		} else if (errno == EAGAIN) {
			// try again
		} else {
			perror("read error");
			close_connection(i);
		}
	} else if (n == 0) {
		close_connection(i);
	} else {
		http_parser_execute(&parsers[i], &settings, buf, n);

		if (parsers[i].http_errno) {
			printf("err=%s\n",
			    http_errno_name(parsers[i].http_errno));
			close_connection(i);
		} else {
			// switch to write mode when needed
			if (data->state == SENDING) {
				client[i].events = POLLRDNORM | POLLWRNORM;
				data->off = data->first;

				if (parsers[i].method == HTTP_HEAD)
					finish_response(i);
			}
		}

	}
}

sig_atomic_t stop;

void
do_stop(int sig)
{
	(void)sig;
	stop = 1;
}

int
main(int argc, char *argv[])
{
	const char *port = default_port;
	char *host = 0;
	char *uds = 0;

	int c;
	while ((c = getopt(argc, argv, "h:m:p:qu:IHM:PRV")) != -1)
		switch (c) {
		case 'h': host = optarg; break;
		case 'm': custom_mimetypes = optarg; break;
		case 'p': port = optarg; break;
		case 'u': uds = optarg; break;
		case 'q': quiet = 1; break;
		case 'I': show_index = 0; break;
		case 'H': tilde = 1; break;
		case 'M': default_mimetype = optarg; break;
		case 'P': only_public = 1; break;
		case 'R': reuse_port = 1; break;
		case 'V': vhost = 1; break;
		default:
			fprintf(stderr,
			    "Usage: %s [-h HOST] [-p PORT] [-u SOCKET] "
			    "[-m :.ext=mime/type:...] [-M DEFAULT_MIMETYPE] "
			    "[-IHPRVq] [DIRECTORY]\n", argv[0]);
			exit(1);
		}

	if (argc > optind)
		wwwroot = argv[optind];

	struct sigaction pipe_act = { .sa_handler = SIG_IGN };
	sigemptyset(&pipe_act.sa_mask);
	sigaction(SIGPIPE, &pipe_act, 0);

	struct sigaction act = { .sa_handler = do_stop };
	sigemptyset(&act.sa_mask);
	sigaction(SIGINT, &act, 0);
	sigaction(SIGTERM, &act, 0);

	int i, maxi, listenfd, sockfd;
	int nready;
	int r = 0;

	if (uds) {
		struct sockaddr_un addr = { 0 };
		addr.sun_family = AF_UNIX;
		strncpy(addr.sun_path, uds, sizeof addr.sun_path - 1);
		listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (listenfd < 0) {
			perror("socket");
			exit(111);
		}
		unlink(uds);
		r = bind(listenfd, (struct sockaddr *)&addr, sizeof addr);
		if (r < 0) {
			perror("bind");
			exit(111);
		}
	} else {
		struct addrinfo hints = {
			.ai_socktype = SOCK_STREAM,
#ifdef AI_V4MAPPED
			.ai_family = AF_INET6,
			.ai_flags = AI_PASSIVE | AI_V4MAPPED
#else
			.ai_family = AF_UNSPEC,
			.ai_flags = AI_PASSIVE,
#endif
		}, *res;

		r = getaddrinfo(host, port, &hints, &res);
		if (r) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
			exit(111);
		}

		listenfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (listenfd < 0) {
			perror("socket");
			exit(111);
		}

		if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
		    &(int){ 1 }, sizeof (int)) < 0) {
			perror("setsockopt(SO_REUSEADDR)");
			exit(111);
		}

#ifdef SO_REUSEPORT
		if (reuse_port &&
		    setsockopt(listenfd, SOL_SOCKET, SO_REUSEPORT,
		    &(int){ 1 }, sizeof (int)) < 0) {
			perror("setsockopt(SO_REUSEPORT)");
			exit(111);
		}
#endif

		r = bind(listenfd, res->ai_addr, res->ai_addrlen);
		if (r < 0) {
			perror("bind");
			exit(111);
		}

		freeaddrinfo(res);
	}

	r = listen(listenfd, SOMAXCONN);
	if (r < 0) {
		perror("listen");
		exit(111);
	}

	if (!quiet) {
		char addrbuf[NI_MAXHOST] = "(unknown)";
		char *addr = addrbuf;
		char portbuf[PATH_MAX] = "(unknown)";
		struct sockaddr_storage ss;
		socklen_t slen = sizeof ss;
		if (getsockname(listenfd, (struct sockaddr *)&ss, &slen) == 0 &&
		    getnameinfo((struct sockaddr *)&ss, slen,
		    addrbuf, sizeof addrbuf, portbuf, sizeof portbuf,
		    NI_NUMERICHOST | NI_NUMERICSERV) == 0)
			addr = addrbuf;
		if (strncmp("::ffff:", addr, 7) == 0)
			addr += 7;

		printf("hittpd listening on %s:%s\n", addr, portbuf);
	}

	client[0].fd = listenfd;
	client[0].events = POLLRDNORM;

	for (i = 1; i < MAX_CLIENTS; i++)
		client[i].fd = -1;  /* -1 indicates available entry */

	maxi = 0; /* max index into client[] array */

	while (!stop) {
		nready = poll(client, maxi + 1, maxi ? TIMEOUT*1000 : -1);

		if (nready < 0) {
			if (errno == EINTR) {
				continue;   // and stop maybe
			} else {
				perror("poll");
				exit(111);
			}
		}

		now = time(0);
		httpdate(now, timestamp);

		if (nready == 0) {
			// clear timeouted
			for (i = 1; i <= maxi; i++)
				if (client[i].fd >= 0)
					if (now > datas[i].deadline)
						close_connection(i);

			// compress
			int i = 1, j = maxi;

			while (i <= j) {
				while (i <= maxi && client[i].fd >= 0)
					i++;

				if (i <= maxi) {
					while (j >= 1 && client[i].fd == -1)
						j--;

					if (i < j) {
						client[i] = client[j];
						datas[i] = datas[j];
						parsers[i] = parsers[j];
						parsers[i].data = &datas[i];

						client[j].fd = -1;

						j--;
					}
				}
			}

			maxi = j;
		}

		if (client[0].revents & POLLRDNORM) {
			/* new client connection */
			for (i = 1; i < MAX_CLIENTS; i++)
				if (client[i].fd < 0) {
					int connfd = accept(listenfd, 0, 0);
					if (connfd >= 0)
						accept_client(i, connfd);
					break;
				}
			if (i == MAX_CLIENTS)
				printf("too many clients\n");
			if (i > maxi)
				maxi = i; /* max index in client[] array */
			if (--nready <= 0)
				continue; /* no more readable descriptors */
		}
		for (i = 1; i <= maxi; i++) { /* check all clients for data */
			if ((sockfd = client[i].fd) < 0)
				continue;

			if (client[i].revents & POLLWRNORM) {
				if (datas[i].state != SENDING) {
					client[i].events = POLLRDNORM;
					continue;
				}

				write_client(i);
				datas[i].deadline = now + TIMEOUT;

				if (--nready <= 0)
					break; /* no more readable descriptors */
			}
			else if (client[i].revents & (POLLRDNORM | POLLERR)) {
				read_client(i);
				datas[i].deadline = now + TIMEOUT;

				if (--nready <= 0)
					break; /* no more readable descriptors */
			}
		}
	}
}
