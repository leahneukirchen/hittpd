/* hittpd - efficient, no-frills HTTP 1.1 daemon */

/* Copyright 2020 Leah Neukirchen <leah@vuxu.org>
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

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE

#ifdef USE_SENDFILE
#include <sys/sendfile.h>
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
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

struct conn_data {
	enum { NONE, HOST, IMS, RANGE, OTHER, BAD_REQUEST, SENDING } state;
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
    ":.txt=text/plain";

char default_mimetype[] = "text/plain";   // "application/octet-stream"

char wwwroot[] = "/tmp";
char default_vhost[] = "_default";

int tilde = 0;
int vhost = 0;

static int
on_url(http_parser *p, const char *s, size_t l)
{
	struct conn_data *data = p->data;

	if (l == 0)
		return 1;

	char *path = malloc(l + 1);
	if (!path)
		return 1;

	char *t = path;

	// XXX move decoding below, to not show up in access log

	for (size_t i = 0; i < l; i++) {
		if (s[i] == '%') {
			char c1 = s[i+1];

			if (c1 >= '0' && c1 <= '9')
				c1 = c1 - '0';
			else if (c1 >= 'A' && c1 <= 'F')
				c1 = c1 - 'A' + 10;
			else if (c1 >= 'a' && c1 <= 'f')
				c1 = c1 - 'a' + 10;
			else {
				data->state = BAD_REQUEST;
				return 0;
			}

			char c2 = s[i+2];

			if (c2 >= '0' && c2 <= '9')
				c2 = c2 - '0';
			else if (c2 >= 'A' && c2 <= 'F')
				c2 = c2 - 'A' + 10;
			else if (c2 >= 'a' && c2 <= 'f')
				c2 = c2 - 'a' + 10;
			else {
				data->state = BAD_REQUEST;
				return 0;
			}

			char d = (c1 << 4) | c2;

			if (d == 0 || d == '/')
				data->state = BAD_REQUEST;

                        *t++ = d;
			i += 2;
		} else if (s[i] == 0) {
			data->state = BAD_REQUEST;
		} else {
			*t++ = s[i];
		}
	}
	*t = 0;

	data->path = path;
	return 0;
}

static int
on_header_field(http_parser *p, const char *s, size_t l)
{
	struct conn_data *data = p->data;

	if (data->state == BAD_REQUEST)
		return 0;

	if (l == 4 && strncasecmp(s, "host", l) == 0)
		data->state = HOST;
	else if (l == 17 && strncasecmp(s, "if-modified-since", l) == 0)
		data->state = IMS;
	else if (l == 5 && strncasecmp(s, "range", l) == 0)
		data->state = RANGE;
	else
		data->state = OTHER;	// ignore others

	return 0;
}

void
parse_range(struct conn_data *data, const char *s, size_t l)
{
	long n;

	if (sscanf(s, "bytes=%lu-%lu", &(data->first), &(data->last)) == 2) {
		data->last++;                      // range counts inclusive
		return;
	} else if (sscanf(s, "bytes=-%lu", &n) == 1 && n > 0) {
		data->first = -n;
		data->last = -1;
		return;
	} else if (sscanf(s, "bytes=%lu-", &(data->first)) == 1 && s[l-1] == '-') {
		data->last = -1;
		return;
	} else {
		data->first = data->last = -666;
	}
}

static int
on_header_value(http_parser *p, const char *s, size_t l)
{
	struct conn_data *data = p->data;

	if (data->state == HOST)
		data->host = strndup(s, l);
	else if (data->state == IMS)
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
peername(http_parser *p)
{
	struct conn_data *data = p->data;

        struct sockaddr_storage ss;
        socklen_t slen = sizeof ss;
	static char addrbuf[NI_MAXHOST];

        if (getpeername(data->fd, (struct sockaddr *)(void *)&ss, &slen) < 0)
		return "0.0.0.0";
	if (getnameinfo((struct sockaddr *)(void *)&ss, slen,
	    addrbuf, sizeof addrbuf, 0, 0, NI_NUMERICHOST) < 0)
		return "0.0.0.0";

	if (strncmp("::ffff:", addrbuf, 7) == 0)
		return addrbuf + 7;

	return addrbuf;
}

void
accesslog(http_parser *p, int status)
{
	struct conn_data *data = p->data;

	char buf[64];
	time_t t = time(0);
	strftime(buf, 64, "[%d/%b/%Y:%H:%M:%S %z]", localtime(&t));

//	REMOTEHOST - - [DD/MON/YYYY:HH:MM:SS -TZ] "METHOD PATH" STATUS BYTES
// ?    REFERER USER_AGENT
	printf("%s - - %s \"%s %s\" %d %ld\n",
	    peername(p),
	    buf,
	    http_method_str(p->method),
	    data->path,
	    status,
	    p->method == HTTP_HEAD ? 0 : data->last - data->first);
}

void
send_dir_redirect(http_parser *p)
{
	struct conn_data *data = p->data;
	char buf[512];

	char now[64];
	httpdate(time(0), now);

	int len = snprintf(buf, sizeof buf,
	    "HTTP/1.%d 301 Moved Permanently\r\n"
	    "Content-Length: 0\r\n"
	    "Date: %s\r\n"
	    "Location: %s/\r\n"
	    "\r\n",
	    p->http_minor,
	    now,
	    data->path);

	// XXX include redirect link?

	write(data->fd, buf, len);
	accesslog(p, 301);
}

void
send_not_modified(http_parser *p, time_t modified)
{
	struct conn_data *data = p->data;
	char buf[512];

	char now[64], lastmod[64];
	httpdate(time(0), now);
	httpdate(modified, lastmod);

	int len = snprintf(buf, sizeof buf,
	    "HTTP/1.%d 304 Not Modified\r\n"
	    "Date: %s\r\n"
	    "Last-Modified: %s\r\n"
	    "\r\n",
	    p->http_minor,
	    now,
	    lastmod);

	write(data->fd, buf, len);
	accesslog(p, 304);
}

void
send_error(http_parser *p, int status, const char *msg)
{
	struct conn_data *data = p->data;
	char buf[512];

	char now[64];
	httpdate(time(0), now);

	int len = snprintf(buf, sizeof buf,
	    "HTTP/1.%d %d %s\r\n"
	    "Content-Length: %ld\r\n"
	    "Date: %s\r\n"
	    "\r\n",
	    p->http_minor,
	    status, msg,
	    4 + strlen(msg) + 2,
	    now);

	if (p->method != HTTP_HEAD)
		len += snprintf(buf + len, sizeof buf - len,
		    "%03d %s\r\n",
		    status, msg);

	write(data->fd, buf, len);
	accesslog(p, status);
}

void
send_rns(http_parser *p, off_t filesize)
{
	struct conn_data *data = p->data;
	char buf[512];

	char now[64];
	httpdate(time(0), now);

	int len = snprintf(buf, sizeof buf,
	    "HTTP/1.%d 416 Requested Range Not Satisfiable\r\n"
	    "Content-Length: 0\r\n"
	    "Date: %s\r\n"
	    "Content-Range: bytes */%ld\r\n"
	    "\r\n",
	    p->http_minor,
	    now,
	    filesize);

	data->first = data->last = 0;

	write(data->fd, buf, len);
	accesslog(p, 416);
}

void
print_urlencoded(FILE *stream, char *s)
{
	while (*s)
		switch(*s) {
		case ';':
		case '/':
		case '?':
		case ':':
		case '@':
		case '=':
		case '&':
		case '"':
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
		switch(*s) {
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
	char buf[512];

	char now[64], lastmod[64];
	httpdate(time(0), now);
	httpdate(modified, lastmod);

	int len;

	if (data->first == 0 && data->last == filesize) {
		len = snprintf(buf, sizeof buf,
		    "HTTP/1.%d 200 OK\r\n"
		    "Content-Type: %s\r\n"
		    "Content-Length: %ld\r\n"
		    "Last-Modified: %s\r\n"
		    "Date: %s\r\n"
		    "\r\n",
		    p->http_minor,
		    mimetype,
		    data->last - data->first,
		    lastmod,
		    now);

		write(data->fd, buf, len);
		accesslog(p, 200);
	} else {
		len = snprintf(buf, sizeof buf,
		    "HTTP/1.%d 206 Partial content\r\n"
		    "Content-Type: %s\r\n"
		    "Content-Length: %ld\r\n"
		    "Last-Modified: %s\r\n"
		    "Date: %s\r\n"
		    "Content-Range: bytes %ld-%ld/%ld\r\n"
		    "\r\n",
		    p->http_minor,
		    mimetype,
		    data->last - data->first,
		    lastmod,
		    now,
		    data->first, data->last - 1, filesize);

		write(data->fd, buf, len);
		accesslog(p, 206);
	}
}

char *
mimetype(char *ext)
{
	static char type[16];

	if (!ext)
		return default_mimetype;

	char *x = strstr(mimetypes, ext);

	if (x && x[-1] == ':' && x[strlen(ext)] == '=') {
		char *t = type;
		for (char *c = x + strlen(ext) + 1; *c && *c != ':'; )
			*t++ = *c++;
		*t = 0;
		return type;
	}

	return default_mimetype;
}

static int
on_message_complete(http_parser *p) {
	struct conn_data *data = p->data;
	printf("complete. host: %s path: %s\n", data->host, data->path);

	if (data->state == BAD_REQUEST) {
		data->state = SENDING;
		send_error(p, 400, "Bad Request");
		return 0;
	}

	data->state = SENDING;

	if (!(p->method == HTTP_GET || p->method == HTTP_HEAD)) {
		send_error(p, 405, "Method Not Allowed");
		return 0;
	}

	if (data->path[0] != '/' || strstr(data->path, "/../")) {
		send_error(p, 403, "Forbidden");
		return 0;
	}

	char name[PATH_MAX];

	if (tilde && data->path[1] == '~' && data->path[2]) {
		char *e = strchr(data->path + 1, '/');
		if (e)
			*e = 0;

		struct passwd *pw = getpwnam(data->path + 2);
		if (!pw || pw->pw_uid < 1000) {
			send_error(p, 404, "Not Found");
			return 0;
		}

//		snprintf(name, sizeof name, "%s/tmp/%s",
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
		if (strstr(host, "..")) {
			send_error(p, 403, "Forbidden");
			return 0;
		}

		struct stat dst;
		snprintf(name, sizeof name, "%s/%s", wwwroot, host);
		if (stat(name, &dst) < 0 || !S_ISDIR(dst.st_mode))
			host = default_vhost;

		snprintf(name, sizeof name, "%s/%s%s",
		    wwwroot, host, data->path);
	} else {
		snprintf(name, sizeof name, "%s%s",
		    wwwroot, data->path);
	}

	int stream_fd = open(name, O_RDONLY);

	if (stream_fd < 0) {
		if (errno == EACCES || errno == EPERM)
			send_error(p, 403, "Forbidden");
		else if (errno == ENOENT || errno == ENOTDIR)
			send_error(p, 404, "Not Found");
		else {
			perror("open");
			send_error(p, 500, "Internal Server Error");
		}
		return 0;
	}

	struct stat st;
	if (fstat(stream_fd, &st) < 0) {
		send_error(p, 500, "Internal Server Error");
		return 0;
	}

	if (S_ISDIR(st.st_mode)) {
		int x;
		if (data->path[strlen(data->path)-1] == '/' &&
		    (x = openat(stream_fd, "index.html", O_RDONLY)) >= 0) {
			close(stream_fd);
			stream_fd = x;
			if (fstat(stream_fd, &st) < 0) {
				send_error(p, 500, "Internal Server Error");
				return 0;
			}
			goto file;
		}

		close(stream_fd);
		data->stream_fd = -1;

		if (data->path[strlen(data->path)-1] != '/') {
			send_dir_redirect(p);
			return 0;
		}

		char *buf;
		size_t len;

		FILE *stream = open_memstream(&buf, &len);
		if (!stream)
			return 1;


		fprintf(stream, "<!doctype html><meta charset=\"utf-8\">"
		    "<title>Index of ");
		print_htmlencoded(stream, data->path);
		fprintf(stream, "</title>"
		    "<h1>Index of ");
		print_htmlencoded(stream, data->path);
		fprintf(stream, "</h1>\n<ul>\n");

		struct dirent **namelist;
		int n = scandir(name, &namelist, 0, alphasort);

		for (int i = 0; i < n; i++) {
			if (namelist[i]->d_name[0] == '.' &&
			    namelist[i]->d_name[1] == 0)
				continue;

			fprintf(stream, "<li><a href=\"");
			print_urlencoded(stream, namelist[i]->d_name);
			fprintf(stream, "%s\">",
			    namelist[i]->d_type == DT_DIR ? "/" : "");
			print_htmlencoded(stream, namelist[i]->d_name);
			fprintf(stream, "%s</a></li>\n",
			    namelist[i]->d_type == DT_DIR ? "/" : "");
		}

		while (n--)
			free(namelist[n]);
		free(namelist);

		fprintf(stream, "</ul>\n");
		fclose(stream);

		data->buf = buf;
		data->first = 0;
		data->last = len;
		send_ok(p, time(0), "text/html", len);

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

	char *ext = strrchr(data->path, '.');
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

#define OPEN_MAX 1024

struct pollfd client[OPEN_MAX];
struct http_parser parsers[OPEN_MAX];
struct conn_data datas[OPEN_MAX];

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

	client[i].events = POLLRDNORM;

	// HTTP 1.0 needs to close connection by server
	// XXX unless explicit keep-alive is set
	if (parsers[i].http_major == 1 && parsers[i].http_minor == 0)
		close_connection(i);
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
	datas[i].deadline = time(0) + TIMEOUT;

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
#ifndef USE_SENDFILE
		char buf[16*4096];
		size_t n = pread(data->stream_fd, buf, sizeof buf, data->off);
		if (n < 0)
			; // XXX
		else if (n == 0) {
			finish_response(i);
		} else if (n > 0) {
			w = write(sockfd, buf, n);
			if (w > 0)
				data->off += w;
		}
#else
		w = sendfile(sockfd, data->stream_fd,
		    &(data->off), data->last - data->off);
		if (w == 0 || data->off == data->last)
			finish_response(i);
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
		if (errno == EPIPE)
			close_connection(i);
		// XXX other error handling
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

int
main()
{
	int i, maxi, listenfd, sockfd;
	int nready;
	int r = 0;

	signal(SIGPIPE, SIG_IGN);

	struct sockaddr_in6 cliaddr, servaddr = { 0 };

	listenfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (r < 0) {
		perror("socket");
		exit(111);
	}

	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
	    &(int){1}, sizeof (int)) < 0) {
		perror("setsockopt(SO_REUSEADDR)");
		exit(111);
	}

	servaddr.sin6_family = AF_INET6;
	servaddr.sin6_port = htons(8081);
	servaddr.sin6_addr = in6addr_any;

	r = bind(listenfd, (struct sockaddr *)&servaddr, sizeof servaddr);
	if (r < 0)
	    perror("bind");

	errno = 0;
	r = listen(listenfd, 32);
	if (r < 0)
	    perror("listen");

	client[0].fd = listenfd;
	client[0].events = POLLRDNORM;

	for (i = 1; i < OPEN_MAX; i++)
		client[i].fd = -1;  /* -1 indicates available entry */

	maxi = 0; /* max index into client[] array */

	while (1) {
		nready = poll(client, maxi + 1, maxi ? TIMEOUT*1000 : -1);

		time_t now = time(0);

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
			for (i = 1; i < OPEN_MAX; i++)
				if (client[i].fd < 0) {
					socklen_t clilen = sizeof cliaddr;
					int connfd = accept(listenfd,
					    (struct sockaddr *)&cliaddr, &clilen);
					accept_client(i, connfd);
					break;
				}
			if (i == OPEN_MAX)
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
