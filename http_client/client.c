#include <assert.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define SERVER_ADDR "localhost"
#define SERVER_PORT 5000
#define HEADER_LEN 256
#define RECV_BUF_SIZE 2048

int board_post(char *buf, size_t len) {
  if (buf == NULL || len == 0)
    return 0;
  static char header_fmt[] =
      "POST /post HTTP/1.1\nHost: %s:%d\nAccept: */*\nContent-Type: "
      "application/json\nContent-Length: %d\n\n";
  char header_buffer[HEADER_LEN];
  int header_size = snprintf(header_buffer, sizeof(header_buffer), header_fmt,
                             SERVER_ADDR, SERVER_PORT, len);
  int rv = -1;
  // make connection to server
  struct addrinfo *info;
  char port[6];
  int size = snprintf(port, sizeof(port) - 1, "%d", SERVER_PORT);
  port[size] = '\0';
  rv = getaddrinfo(SERVER_ADDR, port, NULL, &info);
  if (rv || info == NULL || info->ai_addr == NULL) {
    perror("getaddrinfo");
    return -1;
  }

  int sock = socket(info->ai_family, SOCK_STREAM, IPPROTO_TCP);
  if (sock == -1) {
    perror("socket");
    return -1;
  }
  rv = connect(sock, info->ai_addr, info->ai_addrlen);
  if (rv) {
    perror("connect");
    close(sock);
    return -1;
  }
  freeaddrinfo(info);

  struct iovec iov[2];
  iov[0].iov_base = header_buffer;
  iov[0].iov_len = header_size;
  iov[1].iov_base = buf;
  iov[1].iov_len = len;
  size = writev(sock, iov, sizeof(iov) / sizeof(iov[0]));
  if (size < header_size + len) {
    perror("writev");
    close(sock);
    return -1;
  }
  close(sock);

  return size;
}

size_t board_fetch(char **buf) {
  if (buf == NULL) {
    return -1;
  }
  static char header_fmt[] =
      "GET /fetch HTTP/1.1\nHost: %s:%d\nAccept: */*\n\n";
  char header_buffer[HEADER_LEN];
  int header_size = snprintf(header_buffer, sizeof(header_buffer), header_fmt,
                             SERVER_ADDR, SERVER_PORT);

  int rv = -1;
  // make connection to server
  struct addrinfo *info;
  char port[6];
  int size = snprintf(port, sizeof(port) - 1, "%d", SERVER_PORT);
  port[size] = '\0';
  rv = getaddrinfo(SERVER_ADDR, port, NULL, &info);
  if (rv || info == NULL || info->ai_addr == NULL) {
    perror("getaddrinfo");
    return -1;
  }

  int sock = socket(info->ai_family, SOCK_STREAM, IPPROTO_TCP);
  rv = connect(sock, info->ai_addr, info->ai_addrlen);
  if (rv) {
    perror("connect");
    close(sock);
    return -1;
  }

  rv = send(sock, header_buffer, header_size, 0);
  if (rv != header_size) {
    perror("send");
    close(sock);
    return -1;
  }

  size_t recv_buf_size = RECV_BUF_SIZE;
  size_t recv_buf_off = 0;
  char *recv_buf = NULL;
  recv_buf = malloc(recv_buf_size);
  if (!recv_buf) {
    perror("malloc");
    close(sock);
    return -1;
  }
  while (1) {
    size = recv(sock, recv_buf + recv_buf_off, recv_buf_size - recv_buf_off, 0);
    if (size == 0)
      break;
    recv_buf_off += size;
    if (recv_buf_size - recv_buf_off <= 1) {
      char *newbuf = realloc(recv_buf, 2 * recv_buf_size);
      if (!*newbuf) {
        perror("realloc");
        free(recv_buf);
        close(sock);
        return -1;
      }
      recv_buf = newbuf;
      recv_buf_size *= 2;
    }
  }
  close(sock);

  if (recv_buf_off < 2) {
    return -1;
  }
  // strip the HTTP header
  size_t body_size = 0;
  for (int i = 0; i < recv_buf_off - 1; ++i) {
    if (strncmp(recv_buf + i, "\r\n\r\n", 4) == 0) {
      body_size = recv_buf_off - (i + 4);
      *buf = malloc(body_size);
      if (!*buf) {
        perror("malloc");
        free(recv_buf);
        return -1;
      }
      memcpy(*buf, recv_buf + i + 4, body_size);
      break;
    }
  }
  free(recv_buf);
  if (body_size == 0) {
    puts("Cannot find HTTP body");
    return -1;
  }

  return body_size;
}

int main(void) {
  char req[] = "{\"hello\": 1}";
  board_post(req, strlen(req));

  // to avoid reordering
  usleep(100000);

  char *response;
  size_t resp_size = board_fetch(&response);
  response[resp_size] = '\0';
  printf("%ld\n", resp_size);
  printf("%s", response);

  return 0;
}