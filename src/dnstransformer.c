/* Copyright 2017 Sinan Birbalta <s.birbalta ... gmail.com>
 * This file is part of dnstransformer.
 *
 * The project uses smlog from smrender.
 *
 * dnstransformer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * dnstransformer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dnstransformer. If not, see <http://www.gnu.org/licenses/>.
 */

/*! dnstransformer is a DNS protocol translator which turns UDP/DNS to TCP/DNS
 *  and vice versa. It receives DNS packets on UDP port 53 and forwards them
 *  to a DNS server or another instance of dnstransformer, with TCP. There,
 *  a server mode instance of dnstransformer can convert the query back to UDP.
 *  The destination IP address has to be specified as command line argument.
 *  The responses are sent back again. Currently, only one client/server is
 *  supported.
 *
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

// maximum number of concurrent transactions
#define MAX_TRX 1024

// maximum debug level
//#define DEBUG_RAW

#define LOG_WARN LOG_WARNING
#define FRAMESIZE 65536
#define NOBODY 65534

enum trx_state {
    TRX_STATE_SEND,           // sending or about to be sent
    TRX_STATE_RECV,           // receiving from
    TRX_STATE_DONE            // data was sent and received
};

typedef struct dns_trx {
    struct sockaddr_storage addr; // keep socket address of original UDP sender
    socklen_t addr_len;
    enum trx_state state;         // state of this transaction
    ssize_t data_len;             // data length to send
    char data[FRAMESIZE + 2];     // query data
} dns_trx_t;

void log_msg(int, const char*, ...) __attribute__((format(printf, 2, 3)));
FILE* init_log(const char*, int);

/*! This function decodes the RR type and returns a constant string pointer.
 *  @param type Numeric RR type.
 *  @return Pointer to constant string.
 */
static const char* dns_rr_type(int type) {
    switch (type) {
    case 1:
        return "A";
    case 28:
        return "AAAA";
    case 5:
        return "CNAME";
    case 2:
        return "NS";
    case 12:
        return "PTR";
    case 6:
        return "SOA";
    case 15:
        return "MX";
    case 0xff:
        return "ANY";
    default:
        return "(tbd)";
    }
}

static const char* dns_rcode(int code) {
    switch (code) {
    case 0:
        return "NOERROR";
    case 1:
        return "FORMERR";
    case 2:
        return "SERVFAIL";
    case 3:
        return "NXDOMAIN";
    case 4:
        return "NOTIMP";
    case 5:
        return "REFUSED";
    default:
        return "";
    }
}

/*! Dns_label_to_buf() converts one label of a domain name to a \0-terminated C
 *  character string. Compressed labels (0xc0) are not decompressed but binary
 *  labels (0x40) are decoded. Thus the character string buf may contain \0
 *  bytes. buf will always be \0-terminated.
 *  @param src Pointer to DNS label.
 *  @param buf Pointer to destination buffer.
 *  @param len Total length of buf.
 *  @return Number of bytes copied to buf excluding the terminating \0. Thus,
 *  the total number of bytes copied to buf is always less than len.
 */
static int dns_label_to_buf(const char* src, char* buf, int len) {
    int i = 0, llen;

    len--;
    llen = *src++ & 0xff;
    // uncompressed label
    if (!(llen & 0xc0)) {
        for (; i < llen && len > 0; i++, src++, len--, buf++)
            *buf = *src;
    }
    // compressed label
    else if ((llen & 0xc0) == 0xc0) {
        if (len > 0) {
            *buf++ = '_';
            i++;
            len--;
        }
    }
    // binary label, EDNS0
    else if ((llen & 0xc0) == 0x40) {
        llen = *src & 0xff;
        //*buf++ = *src++;
        if (!llen)
            len = 256;
        llen--;
        llen >>= 3;
        llen++;
        for (; i <= llen && len > 0; i++, src++, len--, buf++)
            *buf = *src;
    }
    *buf = '\0';
    return i;
}

/*! Decodes a domain name consisting of several DNS labels.
 *  @param src Pointer to domain name.
 *  @param buf Pointer to destination buffer.
 *  @param len Total length of buf.
 *  @return The total number of bytes within buf including the terminating \0
 *  which is also the total number of bytes decoded within src.
 */
static int dns_name_to_buf(const char* src, char* buf, int len) {
    int llen, nlen;

    for (nlen = 0;; src += llen + 1) {
        if (!(llen = dns_label_to_buf(src, buf, len)))
            break;
        buf += llen;
        *buf = '.';
        buf++;
        len -= llen + 1;
        nlen += llen + 1;
    }
    return nlen + 1;
}

/*! This function binds a TCP or UDP socket to the specified port, but does not
 * listen on the socket!
 * @param port Port number
 * @param type SOCK_DGRAM for UDP or SOCK_STREAM for TCP
 * @param family should be either AF_INET6 or AF_INET or AF_UNSPEC.
 * @return Returns a valid socket file descriptor or -1 in case of error.
 */
static int init_server_socket(char* port, int type, int family) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sock = -1, s;

    char host_s[24];
    char port_s[6];

    int flag = 1; // for TCP_NODELAY

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = family;
    hints.ai_socktype = type;
//    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0; /* Any protocol */

    // listen on every IP address
    s = getaddrinfo("0.0.0.0", port, &hints, &result);
    if (s != 0) {
        log_msg(LOG_ERR, "init_server_socket getaddrinfo: %s\n",
                gai_strerror(s));
        return -1;
    }

    /* getaddrinfo() returns a list of address structures.
     Try each address until we successfully bind.
     If socket (or bind) fails, we (close the socket and) try the next address.
     */

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1)
            continue;

        if (bind(sock, rp->ai_addr, rp->ai_addrlen) == 0) {

            getnameinfo(rp->ai_addr, rp->ai_addrlen, host_s, 24, port_s, 6,
            NI_NUMERICHOST | NI_NUMERICSERV);

            switch (type) {
            case SOCK_DGRAM:
                log_msg(LOG_NOTICE, "Bound to UDP host %s port %s", host_s,
                        port_s);
                break;
            case SOCK_STREAM:
                log_msg(LOG_NOTICE, "Bound to TCP host %s port %s", host_s,
                        port_s);
                break;
            default:
                log_msg(LOG_NOTICE,
                        "Bound to <unknown protocol> host %s port %s", host_s,
                        port_s);
                break;
            }

            break;
        }

        close(sock);
    }

    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));

    if (rp == NULL) { /* No address succeeded */
        log_msg(LOG_ERR, "Could not bind on port %s: %s\n", port,
                strerror(errno));
        return -1;
    }

    freeaddrinfo(result);

    return sock;
}

/*! This function connects a TCP or UDP socket to the specified host/port.
 * For TCP this function blocks until the connection is established.
 * @param host name or IP address (also accepts IPv6 format)
 * @param port Port number
 * @param type SOCK_DGRAM for UDP or SOCK_STREAM for TCP
 * @param family should be either AF_INET6 or AF_INET or AF_UNSPEC
 * @return Returns a valid socket file descriptor or -1 in case of error.
 */
static int init_client_socket(char *host, char *port, int type, int family) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sock = -1, s;

    int flag = 1; // for TCP_NODELAY

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = family;
    hints.ai_socktype = type;
//    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0; /* Any protocol */

    s = getaddrinfo(host, port, &hints, &result);
    if (s != 0) {
        log_msg(LOG_ERR, "init_client_socket getaddrinfo: %s\n",
                gai_strerror(s));
        return -1;
    }

    /* getaddrinfo() returns a list of address structures.
     Try each address until we successfully bind.
     If socket (or bind) fails, we (close the socket and) try the next address.
     */

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1)
            continue;

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            log_msg(LOG_NOTICE, "Connected to %s:%s", host, port);
            break;
        }

        close(sock);
    }

    if (rp == NULL) { /* No address succeeded */

        log_msg(LOG_ERR, "Could not connect to port %s on %s: %s\n", port, host,
                strerror(errno));
        return -1;
    }

    freeaddrinfo(result);

    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));

    return sock;
}

#ifdef DEBUG_RAW
void print_hex_memory(void *mem, int len) {
    unsigned char *p = (unsigned char *)mem;
    for (int i=0;i<len;i++) {
        if ((i%16==0) && i)
        printf("\n");
        printf("0x%02x ", p[i]);
    }
    printf("\n");
}
#endif

static ssize_t send_dns_tcp(int sock, dns_trx_t *trx) {
    ssize_t len;

    log_msg(LOG_DEBUG, "Sending TCP data length %ld", trx->data_len);
#ifdef DEBUG_RAW
    print_hex_memory(trx->data, trx->data_len);
#endif

    if ((len = (int) send(sock, trx->data, (size_t) trx->data_len, 0)) == -1) {
        log_msg(LOG_ERR, "sending data on %d to NS failed: %s", sock,
                strerror(errno));
        return -1;
    }

    if (len < trx->data_len) {
        log_msg(LOG_WARN, "TCP send truncated: sent %ld/%ld", len,
            trx->data_len);
        memmove(trx->data, trx->data + len, (size_t) (trx->data_len - len));
    }

    trx->data_len -= len;
    return len;
}

/*! Send the transaction to the peer connected with sock or to the one specified
 * by dest_addr (see param descriptions).
 * @param sock valid UDP socket
 * @param trx transaction which contains the DNS query as binary data to send
 * @param dest_addr address to send to. If socket is connected, this can be NULL
 * @param addrlen length of dest_addr, must be 0 if dest_addr == NULL
 */
static int send_dns_udp(int sock, dns_trx_t *trx,
        const struct sockaddr *dest_addr, socklen_t addrlen) {
    int len = 0;

    if ((len = (int) sendto(sock, &trx->data, (size_t) trx->data_len, 0,
        dest_addr, addrlen)) == -1) {
        log_msg(LOG_ERR, "sendto() on %d failed: %s. Dropping data", sock,
                strerror(errno));

        return -1;
    }
    trx->data_len -= len;

    log_msg(LOG_INFO, "sent %d/%ld bytes on %d, id = 0x%04x,"
            "RCODE = %s", len, trx->data_len, sock,
            (int) ntohs(*((uint16_t*) (trx->data))),
            dns_rcode(trx->data[3] & 15));
    return len;
}

/*! Simple logging function which outputs some information about a (newly
 * created) DNS transaction.
 * @param dt Pointer to the transaction.
 */
static void log_udp_in(const dns_trx_t* dt) {
    char host[64], name[256], port[6];
    int len, qtype;

    if (getnameinfo((struct sockaddr*) &dt->addr, dt->addr_len, host, 64, port,
            6, NI_NUMERICHOST))
        return;

    len = dns_name_to_buf(dt->data + 12, name, sizeof(name));
    qtype = ntohs(*((uint16_t*) (dt->data + 12 + len)));
    log_msg(LOG_INFO,
            "%ld bytes incoming from %s, port %s, id = 0x%04x, '%s'/%s",
            dt->data_len, host, port, (int) ntohs(*((uint16_t*) dt->data)),
            name, dns_rr_type(qtype));
}

/*! Simple logging function which outputs some information about a (newly
 * created) DNS transaction.
 * @param dt Pointer to the transaction.
 */
static void log_tcp_in(const dns_trx_t* dt) {
    char host[64], name[256], port[6];
    int len, qtype;

    if (getnameinfo((struct sockaddr*) &dt->addr, dt->addr_len, host, 64, port,
            6, NI_NUMERICHOST))
        return;

    len = dns_name_to_buf(dt->data + 14, name, sizeof(name));
    qtype = ntohs(*((uint16_t*) (dt->data + 14 + len)));
    log_msg(LOG_INFO,
            "%ld bytes incoming from %s, port %s, id = 0x%04x, '%s'/%s",
            dt->data_len, host, port, (int)ntohs(*((uint16_t*) (dt->data + 2))),
            name, dns_rr_type(qtype));
}

static void log_tcp_socket(int tcp_sock) {
    struct tcp_info tcpInfo;
    socklen_t tcpInfo_length = sizeof(struct tcp_info);
    int sndbuf;
    socklen_t sndbuf_size = sizeof(sndbuf);

    if (getsockopt(tcp_sock, IPPROTO_TCP, TCP_INFO, &tcpInfo,
            &tcpInfo_length) == -1) {
        log_msg(LOG_WARN, "getsockopt() error %d: %s", errno,
                strerror(errno));
        return;
    }
    if (getsockopt(tcp_sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, &sndbuf_size)
            == -1) {
        log_msg(LOG_ERR, "setsockopt %d: %s", errno, strerror(errno));
        return;
    }

    log_msg(LOG_DEBUG,"snd_cwnd: %d, snd_mss: %d, snd_wscale: %d, "
        "total_retrans: %d, rto: %d, rtt: %d, rcv_rtt: %d, state: %d.",
        tcpInfo.tcpi_snd_cwnd, tcpInfo.tcpi_snd_mss, tcpInfo.tcpi_snd_wscale,
        tcpInfo.tcpi_total_retrans, tcpInfo.tcpi_rto, tcpInfo.tcpi_rtt,
        tcpInfo.tcpi_rcv_rtt, tcpInfo.tcpi_state);
}

/*! Dispatches packets between the UDP client and the TCP (name) server.
 * Can connect to a name server or to a server instance of dnstransfomer.
 * Only returns if TCP connection was closed or upon error.
 * @param udp_sock File descriptor of UDP socket used for receiving packets from
 * the DNS client.
 * @param tcp_sock TCP socket of the name server or dnstransformer server
 * @param trx Pointer to the transaction table
 * @param trx_cnt amount of elements available in transaction table
 * @return -1 in case of error or if a disconnect was received.
 */
static int dispatch_packets_client(int udp_sock, int tcp_sock, dns_trx_t *trx,
        int trx_cnt) {
    int nfds, so_err, iInUDP = 0, iOutTCP = 0, iInTCP = 0,
            running = 1, ntruncated = 0, sndbuf = 50000;
    uint16_t len_expected = 0;
    ssize_t len;
    socklen_t so_err_len = sizeof(so_err);
    fd_set rset, wset;
    dns_trx_t *pInUDP = trx, *pOutTCP = trx, *pInTCP = trx;

    /* example state of pointers while running
     * ________
     * |------|
     * |------|<-- pInUDP >= pOutTCP
     * |------|
     * |------|<-- pOutTCP >= pInTCP
     * |------|
     * |------|<-- pInTCP
     * |______|
     *        ^--- trx(always at the bottom)
     */

    log_tcp_socket(tcp_sock);

    if (setsockopt(tcp_sock, SOL_SOCKET, SO_SNDBUF,
           &sndbuf, sizeof(sndbuf)) < 0) {
        log_msg(LOG_ERR, "setsockopt %d: %s", errno, strerror(errno));
        exit(2);
    }
    while (running) {
        log_tcp_socket(tcp_sock);
        FD_ZERO(&rset);
        FD_ZERO(&wset);

        // wait on UDP for input packets
        FD_SET(udp_sock, &rset);
        nfds = udp_sock;

        log_msg(LOG_DEBUG, "iInUDP = %d, iOutTCP = %d, iInTCP = %d", iInUDP,
                iOutTCP, iInTCP);

        // is a trx waiting to send to TCP?
        // note: need to check pInUDP for iInUDP == 1 && iOutTCP == 0
//        if (pInUDP->state == TRX_STATE_SEND
//                || pOutTCP->state == TRX_STATE_SEND) {
//            FD_SET(tcp_sock, &wset);
//        }
        // expecting to receive data from TCP?
        if (pOutTCP->state == TRX_STATE_RECV) {
            FD_SET(tcp_sock, &rset);
        }

        nfds = udp_sock > tcp_sock ? udp_sock : tcp_sock;

        if ((nfds = select(nfds + 1, &rset, &wset, NULL, NULL)) == -1) {
            log_msg(LOG_ERR, "select() failed: %s", strerror(errno));
            return -1;
        }

        log_msg(LOG_DEBUG, "ISSET: udp r:%d. TCP r:%d, w:%d",
                FD_ISSET(udp_sock, &rset), FD_ISSET(tcp_sock, &rset),
                FD_ISSET(tcp_sock, &wset));

        /* test for incoming packet on udp */
        if (FD_ISSET(udp_sock, &rset)) {
            // do incoming queries overtake waiting queries?
            if ((iInUDP + 1) % trx_cnt == iInTCP) {
                log_msg(LOG_WARN, "query queue full, retrying immediately");
            } else {
                iInUDP = (iInUDP + 1) % trx_cnt;
                pInUDP = trx + iInUDP;

                pInUDP->addr_len = sizeof(pInUDP->addr);
                if ((pInUDP->data_len = recvfrom(udp_sock, &pInUDP->data[2],
                        sizeof(pInUDP->data) - 2, 0,
                        (struct sockaddr*) &pInUDP->addr, &pInUDP->addr_len))
                        == -1) {
                    log_msg(LOG_ERR, "recvfrom() on UDP socket failed: %s",
                            strerror(errno));
                    return -1;
                }

                if (pInUDP->data_len >= 12) {
                    log_tcp_in(pInUDP);
                    // set length header for DNS/TCP
                    *((uint16_t*) &pInUDP->data[0]) =
                        htons((uint16_t) pInUDP->data_len);
                    pInUDP->data_len += 2;
                    // signal that this transaction wishes to be sent
                    pInUDP->state = TRX_STATE_SEND;
                } else {
                    log_msg(LOG_WARN, "ignoring short datagram (len = %ld)",
                            pInUDP->data_len);
                }
            }
        }

        /* incoming data on tcp */
        if (FD_ISSET(tcp_sock, &rset)) {
            log_msg(LOG_DEBUG, "TCP incoming");

            // we assume to receive data for the next query only if
            // the last data received was not truncated.
            if (!ntruncated) {
                iInTCP = (iInTCP + 1) % trx_cnt;
                pInTCP = trx + iInTCP;

                // response length is independent from query length and it is
                // used to count the amount of data received
                pInTCP->data_len = 0;
                len_expected = 0;

                // for DNS over TCP, query size was added to the packet
                if ((len = recv(tcp_sock, &len_expected, 2, 0)) == -1) {
                    log_msg(LOG_ERR,
                            "failed to recv() len on TCP socket: %s. Closing",
                            strerror(errno));
                    (void) close(tcp_sock);
                    return -1;
                }

                if (len == 0) {
                    // assume the peer wants to close the connection
                    log_msg(LOG_NOTICE, "Connection closed by remote.");
                    return -1;
                }

                len_expected = ntohs(len_expected);
            }

            if ((len = recv(tcp_sock, pInTCP->data + pInTCP->data_len,
                    len_expected, 0)) == -1) {
                log_msg(LOG_ERR, "failed to recv() on TCP socket: %s. Closing",
                        strerror(errno));
                (void) close(tcp_sock);
                return -1;
            }

            len_expected -= len;
            pInTCP->data_len += len;

            if (len_expected > 0) {
                ntruncated++;
                log_msg(LOG_INFO, "received %d truncated packet(s)."
                        " Waiting for %d more bytes (%ld received)...\n",
                        ntruncated, len_expected, len);
                if (ntruncated > 2) {
                    log_msg(LOG_EMERG, "more than 2 times truncated data"
                            " received. Quitting.");
                    return -1;
                }
                continue;
            }

            ntruncated = 0;
            log_msg(LOG_DEBUG, "got %ld bytes of data on TCP socket",
                    pInTCP->data_len + 2);

            pInTCP->state = TRX_STATE_RECV;

            /* send to UDP */

            if (send_dns_udp(udp_sock, pInTCP, (struct sockaddr*) &pInTCP->addr,
                    pInTCP->addr_len) == -1) {
                log_msg(LOG_ERR, "dropping data and closing TCP");
                (void) close(tcp_sock);
                return -1;
            }

            pInTCP->data_len = 0;
            pInTCP->state = TRX_STATE_DONE;
        }

        /* tcp socket is ready for sending */
        //if (FD_ISSET(tcp_sock, &wset)) {
        while (iOutTCP != iInUDP) {
            iOutTCP = (iOutTCP + 1) % trx_cnt;
            pOutTCP = trx + iOutTCP;

            if (pOutTCP->state != TRX_STATE_SEND) {
                break;
            }

            if (getsockopt(tcp_sock, SOL_SOCKET, SO_ERROR, &so_err, &so_err_len)
                    == -1) {
                log_msg(LOG_ERR,
                        "getsockopt on tcp socket failed: %s. Closing.",
                        strerror(errno));
                (void) close(tcp_sock);
                return -1;
            } else if (so_err) {
                log_msg(LOG_ERR, "could not connect to NS: SO_ERROR = %d."
                        " Closing.", so_err);
                (void) close(tcp_sock);
                return -1;
            } else {
                if ((len = send_dns_tcp(tcp_sock, pOutTCP)) == -1) {
                    log_msg(LOG_ERR, "dropping data and closing tcp");
                    (void) close(tcp_sock);
                    return -1;
                }
                if (pOutTCP->data_len == 0) {
                    // data was sent completely
                    pOutTCP->state = TRX_STATE_RECV;
                }
            }
        }
    }
    return 0;
}

/**
 * Same as dispatch_packets_client but with two UDP sockets, no TCP 
 */
static int dispatch_packets_udp_client(int local_sock, int remote_sock,
        dns_trx_t *trx, int trx_cnt) {
    int nfds, so_err, iInClient = 0, iOutRemote = 0, iInRemote = 0,
            running = 1;
    ssize_t len;
    socklen_t so_err_len = sizeof(so_err);
    fd_set rset, wset;
    dns_trx_t *pInClient = trx, *pOutRemote = trx, *pInRemote = trx;

    /* example state of pointers while running
     * ________
     * |------|
     * |------|<-- pInUDP >= pOutRemote
     * |------|
     * |------|<-- pOutRemote >= pInRemote
     * |------|
     * |------|<-- pinLocal
     * |______|
     *        ^--- trx(always at the bottom)
     */
    log_msg(LOG_DEBUG, "Running udp client");
    while (running) {
        FD_ZERO(&rset);
        FD_ZERO(&wset);

        // wait on UDP for input packets
        FD_SET(local_sock, &rset);
        nfds = local_sock;

        log_msg(LOG_DEBUG, "iInClient = %d, iOutRemote = %d, iInRemote = %d",
                iInClient, iOutRemote, iInRemote);

        // is a trx waiting to send to server?
        // note: need to check pInUDP for iInClient == 1 && iOutRemote == 0
        if (pInClient->state == TRX_STATE_SEND
                || pOutRemote->state == TRX_STATE_SEND) {
            FD_SET(remote_sock, &wset);
            nfds = local_sock > remote_sock ? local_sock : remote_sock;
        }
        // expecting to receive data from remote?
        if (pOutRemote->state == TRX_STATE_RECV) {
            FD_SET(remote_sock, &rset);
            nfds = local_sock > remote_sock ? local_sock : remote_sock;
        }

        if ((nfds = select(nfds + 1, &rset, &wset, NULL, NULL)) == -1) {
            log_msg(LOG_ERR, "select() failed: %s", strerror(errno));
            return -1;
        }

        /* socket for remote is ready for sending */
        if (FD_ISSET(remote_sock, &wset)) {
            log_msg(LOG_DEBUG, "Sending on %d", remote_sock);

            iOutRemote = (iOutRemote + 1) % trx_cnt;
            pOutRemote = trx + iOutRemote;

            so_err_len = sizeof(so_err);
            if (getsockopt(remote_sock, SOL_SOCKET, SO_ERROR, &so_err,
                    &so_err_len) == -1) {
                log_msg(LOG_ERR,
                        "getsockopt on socket for remote failed: %s. Closing.",
                        strerror(errno));
                (void) close(remote_sock);
                return -1;
            } else if (so_err) {
                log_msg(LOG_ERR, "Could not connect to NS: SO_ERROR = %d."
                        " Closing.", so_err);
                (void) close(remote_sock);
                return -1;
            } else {
                if ((len = send_dns_tcp(remote_sock, pOutRemote)) == -1) {
                    log_msg(LOG_ERR, "Dropping data and closing socket to"
                        " remote");
                    (void) close(remote_sock);
                    return -1;
                }
                if (pOutRemote->data_len == 0) {
                    // data was sent completely
                    pOutRemote->state = TRX_STATE_RECV;
                }
            }
        }

        /* incoming packet from UDP socket */
        if (FD_ISSET(local_sock, &rset)) {
            log_msg(LOG_DEBUG, "Got UDP query on %d", local_sock);
            // do incoming queries overtake waiting queries?
            if ((iInClient + 1) % trx_cnt == iInRemote) {
                log_msg(LOG_WARN, "Query queue full, retrying immediately");
            } else {
                iInClient = (iInClient + 1) % trx_cnt;
                pInClient = trx + iInClient;

                pInClient->addr_len = sizeof(pInClient->addr);
                if ((pInClient->data_len = recvfrom(local_sock,
                    &pInClient->data, sizeof(pInClient->data), 0,
                    (struct sockaddr*) &pInClient->addr, &pInClient->addr_len))
                    == -1) {
                    log_msg(LOG_ERR, "recvfrom() on UDP socket failed: %s",
                            strerror(errno));
                    return -1;
                }

                if (pInClient->data_len >= 12) {
                    log_udp_in(pInClient);
                    // signal that this transaction wishes to be sent
                    pInClient->state = TRX_STATE_SEND;
                } else {
                    log_msg(LOG_WARN, "Ignoring short datagram (len = %ld)",
                            pInClient->data_len);
                }
            }
        }

        /* incoming data from server or another proxy instance */
        if (FD_ISSET(remote_sock, &rset)) {
            log_msg(LOG_DEBUG, "Incoming on %d", remote_sock);

            iInRemote = (iInRemote + 1) % trx_cnt;
            pInRemote = trx + iInRemote;

            if ((len = recv(remote_sock, pInRemote->data,
                sizeof(pInClient->data), 0)) == -1) {
                log_msg(LOG_ERR, "failed to recv() on remote (socket %s). "
                    "Closing", strerror(errno));
                (void) close(remote_sock);
                return -1;
            }

            pInRemote->data_len = len;

            log_msg(LOG_DEBUG, "got %ld bytes of data from remote",
                    pInRemote->data_len);

            pInRemote->state = TRX_STATE_RECV;

            /* send to local socket */

            log_msg(LOG_DEBUG, "Replying on %d", local_sock);

            if (send_dns_udp(local_sock, pInRemote,
                    (struct sockaddr*) &pInRemote->addr, pInRemote->addr_len)
                    == -1) {
                log_msg(LOG_ERR, "dropping data and closing TCP");
                (void) close(local_sock);
                return -1;
            }

            pInRemote->data_len = 0;
            pInRemote->state = TRX_STATE_DONE;
        }

    }
    return 0;
}

/*! Wait for connection on socket that's passed by its file descriptor. The
 * original socket is not modified.
 * @return the socket after the connection has been established or -1 on error
 */
static int wait_for_client(int tcp_sock) {
    int err, sndbuf = 50000; // TCP send buffer in bytes
    char host_s[24], port_s[6];

    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_size = sizeof(struct sockaddr_storage);

    log_tcp_socket(tcp_sock);

    if (setsockopt(tcp_sock, SOL_SOCKET, SO_SNDBUF,
           &sndbuf, sizeof(sndbuf)) < 0) {
        log_msg(LOG_ERR, "setsockopt %d: %s", errno, strerror(errno));
        return -1;
    }

    if (listen(tcp_sock, 2) == -1) {
        log_msg(LOG_ERR, "Failed to listen on TCP socket: %s", strerror(errno));
        close(tcp_sock);
        return -1;
    }

    if ((tcp_sock = accept(tcp_sock, (struct sockaddr *) &peer_addr,
            &peer_addr_size)) == -1) {
        log_msg(LOG_ERR, "Failed to accept on TCP socket. Closing");
        (void) close(tcp_sock);
        return -1;
    }

    // get information about the connected client
    if ((err = getnameinfo((struct sockaddr *) &peer_addr, peer_addr_size,
            host_s, 24, port_s, 6, NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
        log_msg(LOG_ERR, "getnameinfo() failed after connection was "
                "established: %s", gai_strerror(err));
        return -1;
    }

    log_msg(LOG_NOTICE, "Connection established to TCP client %s on port %s.",
            host_s, port_s);
    
    return tcp_sock;
}

/*! This is the server dispatcher. Receives packets from dnstransformer client
 * and sends single packets to the UDP name server on localhost, waits for the
 * answer then forwards the packet to the client so the order will always be
 * sustained and only one UDP packet is "in the air". The name server should be
 * on localhost because the UDP server-connection limits connection speed for
 * the client and the function stops reading from TCP until it sent the last
 * packet over the TCP connection.
 * @param udp_sock File descriptor of UDP socket used for sending and receiving
 *        to the name server.
 * @param tcp_sock TCP socket that was previously bound to an address.
 * @param keep_bound if 0, exit the program after the connection is closed by
 *        the client. Otherwise, waits and accepts another connection request.
 * @return -1 in case of error or 0 if the connection was closed.
 */
static int dispatch_packets_server(int udp_sock, int tcp_sock, int keep_bound) {
    int err, running = 1, ntruncated = 0;
    uint16_t len_expected = 0;
    ssize_t len;
    socklen_t so_err_len = sizeof(err);
    dns_trx_t trx = { .state = TRX_STATE_DONE, .data_len = 0 };

    int connected_sock = wait_for_client(tcp_sock);

    if (connected_sock == -1) {
        return -1;
    }

    while (running) {
        if (!ntruncated) {

            // for DNS over TCP, query size was added to the packet
            if ((len = recv(connected_sock, &len_expected, 2, 0)) == -1) {
                log_msg(LOG_ERR,
                        "Failed to recv() len on TCP socket: %s. Closing",
                        strerror(errno));
                (void) close(connected_sock);
                return -1;
            }

            if (len == 0) {
                // assume peer wants to close the connection
                log_msg(LOG_NOTICE, "Connection closed by remote.");

                if (keep_bound) {
                    connected_sock = wait_for_client(tcp_sock);

                    if (connected_sock == -1) {
                        return -1;
                    }
                    continue;
                }
                else {
                    return 0;
                }
            }

            // convert size field from network to host byte order and remember
            len_expected = ntohs(len_expected);
        }

        if ((len = recv(connected_sock, trx.data + trx.data_len, len_expected,
                0)) == -1) {
            log_msg(LOG_ERR, "Failed to recv() on TCP socket: %s. Closing",
                    strerror(errno));
            (void) close(connected_sock);
            return -1;
        }

        len_expected -= len;
        trx.data_len += len;

        if (len_expected > 0) {
            ntruncated++;
            log_msg(LOG_INFO, "Received %d truncated query(s)."
                    " Waiting for %ud more bytes (%ld received)...\n",
                    ntruncated, len_expected, len);
            if (ntruncated > 2) {
                log_msg(LOG_EMERG, "More than 2 times truncated data"
                        " received. Quitting.");
                return -1;
            }
            continue;
        }

        ntruncated = 0;
        log_msg(LOG_DEBUG, "Got %ld bytes of data on TCP socket",
                trx.data_len + 2);

        trx.state = TRX_STATE_RECV;

        /* send to UDP */

        if (send_dns_udp(udp_sock, &trx, NULL, 0) == -1) {
            log_msg(LOG_ERR, "Dropping data and closing TCP");
            (void) close(connected_sock);
            return -1;
        }

        /* wait for UDP answer */

        if ((trx.data_len = recv(udp_sock, &trx.data[2], sizeof(trx.data) - 2,
                0)) == -1) {
            log_msg(LOG_ERR, "recv() on UDP socket failed: %s",
                    strerror(errno));
            return -1;
        }

        if (trx.data_len >= 12) {
            log_udp_in(&trx);

            // set length header for DNS/TCP
            *((uint16_t*) &trx.data[0]) = htons((uint16_t) trx.data_len);
            trx.data_len += 2;
            // signal that the transaction wishes to be sent
            trx.state = TRX_STATE_SEND;
        } else {
            log_msg(LOG_WARN, "Ignoring short datagram (len = %ld)",
                    trx.data_len);
        }

        log_msg(LOG_DEBUG, "Got %ld bytes as UDP response", trx.data_len);

        if (getsockopt(connected_sock, SOL_SOCKET, SO_ERROR, &err, &so_err_len)
                == -1) {
            log_msg(LOG_ERR, "getsockopt on TCP socket failed: %s. Closing.",
                    strerror(errno));
            (void) close(connected_sock);
            return -1;
        } else if (err) {
            log_msg(LOG_ERR, "Could not connect to client: SO_ERROR = %d."
                    " Closing.", err);
            (void) close(connected_sock);
            return -1;
        } else {

            log_tcp_socket(connected_sock);

            if (send_dns_tcp(connected_sock, &trx) == -1) {
                log_msg(LOG_ERR, "Dropping data and closing TCP");
                (void) close(connected_sock);
                return -1;
            }
            if (trx.data_len == 0) {
                // data was sent completely
                trx.state = TRX_STATE_DONE;
            }
        }
    }
    return 0;
}

/*! This is the server dispatcher in UDP mode. Receives packets from
 * dnstransformer client and sends single packets to the UDP name server on 
 * localhost, waits for the answer then forwards the packet to the client, so
 * the order will always be sustained and only one UDP packet is "in the air".
 * The name server should have a very low latency (localhost) because the UDP
 * communication limits connection speed for the client. It stops reading from 
 * the client socket until the current query is answered by the name server and
 * sent to the client.
 * @param client_sock File descriptor of UDP socket used for sending and 
 * and receiving to/from the client.
 * @param ns_sock File descriptor of UDP socket used for sending and 
 * and receiving to/from the name server.
 * @return -1 in case of error or 0 if the connection was closed.
 */
static int dispatch_packets_udp_server(int client_sock, int ns_sock) {
    int err, running = 1;
    ssize_t len = 0;
    socklen_t so_err_len;
    dns_trx_t trx = { .state = TRX_STATE_DONE, .data_len = 0 };
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_size = sizeof(struct sockaddr_storage);

    while (running) {

        if ((len = recvfrom(ns_sock, trx.data, sizeof(trx.data), 0,
                (struct sockaddr*) &peer_addr, &peer_addr_size)) == -1) {
            log_msg(LOG_ERR, "failed to recv() on TCP socket: %s. Closing",
                    strerror(errno));
            (void) close(ns_sock);
            return -1;
        }

        trx.data_len = len;

        log_msg(LOG_DEBUG, "got %ld bytes of data on TCP socket", trx.data_len);

        trx.state = TRX_STATE_RECV;

        /* send to UDP */

        if (send_dns_udp(client_sock, &trx, NULL, 0) == -1) {
            log_msg(LOG_ERR, "Dropping data and closing TCP");
            (void) close(ns_sock);
            return -1;
        }

        /* wait for UDP answer */

        if ((trx.data_len = recv(client_sock, &trx.data, sizeof(trx.data), 0))
                == -1) {
            log_msg(LOG_ERR, "recv() on UDP socket failed: %s",
                    strerror(errno));
            return -1;
        }

        if (trx.data_len >= 12) {
            log_udp_in(&trx);

            // mark the transaction to be sent
            trx.state = TRX_STATE_SEND;
        } else {
            log_msg(LOG_WARN, "Ignoring short datagram (len = %ld)",
                    trx.data_len);
        }

        log_msg(LOG_DEBUG, "Got %ld bytes as UDP response", trx.data_len);

        so_err_len = sizeof(err);
        if (getsockopt(ns_sock, SOL_SOCKET, SO_ERROR, &err, &so_err_len)
                == -1) {
            log_msg(LOG_ERR, "getsockopt on TCP socket failed: %s. Closing.",
                    strerror(errno));
            (void) close(ns_sock);
            return -1;
        } else if (err) {
            log_msg(LOG_ERR, "could not connect to client: SO_ERROR = %d."
                    " Closing.", err);
            (void) close(ns_sock);
            return -1;
        } else {
            if (send_dns_udp(ns_sock, &trx, (struct sockaddr*) &peer_addr,
                    peer_addr_size) == -1) {
                log_msg(LOG_ERR, "dropping data and closing TCP");
                (void) close(ns_sock);
                return -1;
            }
            if (trx.data_len == 0) {
                // data was sent completely
                trx.state = TRX_STATE_DONE;
            }
        }
    }
    return 0;
}

static void background(void) {
    pid_t pid, ppid;

    log_msg(LOG_DEBUG, "backgrounding");

    ppid = getpid();
    pid = fork();
    switch (pid) {
    case -1:
        log_msg(LOG_ERR, "fork failed: %s. Staying in foreground",
                strerror(errno));
        return;

    case 0:
        log_msg(LOG_NOTICE, "process backgrounded by parent %d, new pid = %d",
                ppid, getpid());
        (void) umask(0);
        if (setsid() == -1)
            log_msg(LOG_ERR, "could not set process group ID: \"%s\"",
                    strerror(errno));
        if (chdir("/") == -1)
            log_msg(LOG_ERR, "could not change directory to /: \"%s\"",
                    strerror(errno));
        // redirect standard files to /dev/null
        if (!freopen("/dev/null", "r", stdin))
            log_msg(LOG_ERR, "could not reconnect stdin to /dev/null: \"%s\"",
                    strerror(errno));
        if (!freopen("/dev/null", "w", stdout))
            log_msg(LOG_ERR, "could not reconnect stdout to /dev/null: \"%s\"",
                    strerror(errno));
        if (!freopen("/dev/null", "w", stderr))
            log_msg(LOG_ERR, "could not reconnect stderr to /dev/null: \"%s\"",
                    strerror(errno));
        return;

    default:
        log_msg(LOG_DEBUG, "parent %d exits, background pid = %d", ppid, pid);
        exit(EXIT_SUCCESS);
    }
}

static void drop_privileges(void) {
    if (getuid())
        return;

    // drop priviledges if root
    if (setgid(NOBODY) == -1) {
        log_msg(LOG_ERR, "setgid() failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setuid(NOBODY) == -1) {
        log_msg(LOG_ERR, "setuid() failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    log_msg(LOG_INFO, "privileges dropped");
}

static void usage(const char* argv0) {
    printf(
            "UDP/DNS-to-TCP/DNS-to-UDP/DNS-converter v0.5\n"
                    "Transmits all DNS queries over the same TCP connection.\n"
                    "Usage: %s [OPTIONS] [-c|-s] port [<dnstransformer ip/name>"
                    "|<NS ip/name>]\n"
                    "  specify either c or s for client or server mode followed"
                    "by the TCP port.\n"
                    "  -4 .......... Use IPv4 only.\n"
                    "  -6 .......... Use IPv6 only.\n"
                    "  -b .......... Background process and log to syslog.\n"
                    "  -v .......... Increase bug level, up to 3 times.\n"
                    "  -p <port> ... Set UDP port for listening (client) or "
                    "for querying (server),\n"
                    "                default: 53001 (client) or 53 (server).\n"
                    "  -u .......... UDP mode: forward UDP packets instead of "
                    "using a TCP\n"
                    "                connection between server/client.\n"
                    "  -k .......... The TCP server does not exit if a "
                    "connection is closed,\n "
                    "               it waits for another connection request.\n",
            argv0);
}

int main(int argc, char** argv) {
    dns_trx_t* trx;
    int local_sock, remote_sock, family = AF_UNSPEC, c, bground = 0,
            udpmode = 0, debugLevel = LOG_WARNING, servermode = -1, result = 0,
            keep_bound = 0;
    char *remote_port_c = NULL, *local_port_c = NULL;

#ifdef TEST_UTDNS_FUNC
    test_utdns_func();
#endif

#ifdef DEBUG
    (void)init_log("stderr", debugLevel);
#endif

    while ((c = getopt(argc, argv, "46bvhukc:s:p:")) != -1) {
        switch (c) {
        // if both, -4 and -6 are specified, use AF_UNSPEC
        case '4':
            family = family == AF_INET6 ? AF_UNSPEC : AF_INET;
            break;

        case '6':
            family = family == AF_INET ? AF_UNSPEC : AF_INET6;
            break;

        case 'b':
            bground++;
            break;

        case 'v':
            if (debugLevel == LOG_WARNING)
                debugLevel = LOG_NOTICE;
            else if (debugLevel == LOG_NOTICE)
                debugLevel = LOG_INFO;
            else
                debugLevel = LOG_DEBUG;
            break;

        case '?':
        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);

        case 'p':
            local_port_c = strdup(optarg);
            break;

        case 'c':
            servermode = 0;
            remote_port_c = strdup(optarg);
            break;

        case 's':
            servermode = 1;
            remote_port_c = strdup(optarg);
            break;

        case 'u':
            udpmode = 1;
            break;

        case 'k':
            keep_bound = 1;
            break;
        }
    }

    if (argv[optind] == NULL) {
        printf("Specify dnstransformer server or NS IP\n");
        exit(EXIT_FAILURE);
    }

    if (servermode == -1) {
        printf("Specify either -s or -c\n");
        exit(EXIT_FAILURE);
    }

    if (bground) {
        (void) init_log(NULL, debugLevel);
    } else {
        (void) init_log("stderr", debugLevel);
    }

    if (!local_port_c) {
        local_port_c = "53001";
    }

    if ((local_sock = init_client_socket(argv[optind], local_port_c,
            SOCK_DGRAM, family)) == -1) {
        perror("local socket");
        exit(EXIT_FAILURE);
    }

    if (servermode) {
        if (udpmode) {
            remote_sock = init_server_socket(remote_port_c, SOCK_DGRAM, family);
        } else {
            remote_sock = init_server_socket(remote_port_c, SOCK_STREAM,family);
        }
    } else {
        if (udpmode) {
            remote_sock = init_client_socket(argv[optind], remote_port_c,
                SOCK_DGRAM, family);
        } else {
            remote_sock = init_client_socket(argv[optind], remote_port_c,
                SOCK_STREAM, family);
        }
    }

    if (remote_sock == -1) {
        perror("init remote socket");
        exit(EXIT_FAILURE);
    }

    drop_privileges();

    if (bground) {
        background();
    }

    // allocate the "transaction buffer" which is needed because receiving
    // queries via UDP is faster than sending and receiving via TCP.
    // Additionally there could be losses/retransmissions.
    if ((trx = (dns_trx_t *) calloc(MAX_TRX, sizeof(*trx))) == NULL) {
        perror("calloc");
        (void) close(local_sock);
        (void) close(remote_sock);
        return -1;
    }

    // init transactions
    for (c = MAX_TRX - 1; c >= 0; c--) {
        trx[c].state = TRX_STATE_DONE;
    }

    if (servermode) {
        if (udpmode)
            result = dispatch_packets_udp_server(local_sock, remote_sock);
        else
            result = dispatch_packets_server(local_sock, remote_sock, 
                        keep_bound);
    } else {
        if (udpmode)
            result = dispatch_packets_udp_client(local_sock, remote_sock, trx,
            MAX_TRX);
        else
            result = dispatch_packets_client(local_sock, remote_sock, trx,
            MAX_TRX);
    }

    free(trx);
    close(local_sock);
    close(remote_sock);

    return result;
}
