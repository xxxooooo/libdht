#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <dht/node.h>
#include <dht/utils.h>

static void sock_send(const unsigned char *data, size_t len,
                      const struct sockaddr *dest, socklen_t addrlen,
                      void *opaque)
{
    int sock = *(int *)opaque;

    if (sendto(sock, data, len, 0, dest, addrlen) < 0)
        DHT_LOG_MESSAGE(LOG_LEVEL_ERRO, "sendto: %s\n", strerror(errno));
}

int node_run(void)
{
    // 设置日志文件
    dht_set_log_file("dht.log");

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sin;
    struct dht_node node;

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(6881);

    bind(sock, (struct sockaddr *)&sin, sizeof(sin));

    if (dht_node_init(&node, NULL, sock_send, &sock))
        return -1;
    
    dht_node_start(&node);

    while (1) {
        struct timeval tv;
        fd_set rfds;
        int rc;

        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);

        dht_node_timeout(&node, &tv);
        rc = select(sock + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            DHT_LOG_MESSAGE(LOG_LEVEL_ERRO, "select: %s\n", strerror(errno));
            return -1;
        }
        if (rc && FD_ISSET(sock, &rfds)) {
            unsigned char buf[2048];
            struct sockaddr_storage ss;
            socklen_t sl = sizeof(ss);

            rc = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&ss, &sl);
            if (rc < 0) {
                DHT_LOG_MESSAGE(LOG_LEVEL_ERRO, "recvfrom: %s\n", strerror(errno));
                return -1;
            }

            dht_node_input(&node, buf, rc, (struct sockaddr *)&ss, sl);
        }

        dht_node_work(&node);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    return node_run();
}
