/* Minimal mDNS responder — answers A-record queries for <hostname>.local
 *
 * Uses a raw lwIP UDP PCB on INADDR_ANY:5353, which works correctly with
 * bridge netifs (unlike the ESP-IDF mDNS component).
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <ctype.h>
#include "mdns_responder.h"
#include "esp_log.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/igmp.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"

static const char *TAG = "mdns_resp";

#define MDNS_PORT       5353
#define MDNS_MCAST_ADDR PP_HTONL(0xE00000FBUL) /* 224.0.0.251 */

/* DNS header flags */
#define DNS_FLAG_QR     (1 << 15)  /* Response */
#define DNS_FLAG_AA     (1 << 10)  /* Authoritative */

#define DNS_TYPE_A      1
#define DNS_CLASS_IN    1
#define DNS_CACHE_FLUSH (1 << 15)

#define MAX_HOSTNAME_LEN 63
#define MDNS_TTL         120

static struct udp_pcb *s_pcb = NULL;
static uint32_t s_ip_addr = 0;
static char s_hostname[MAX_HOSTNAME_LEN + 1] = {0};

/* Build the DNS name for "<hostname>.local" in wire format (length-prefixed labels).
 * Returns total bytes written, or 0 on error. */
static int build_query_name(const char *hostname, uint8_t *buf, int buf_len)
{
    int hlen = strlen(hostname);
    /* Need: 1 + hlen + 1 + 5("local") + 1(terminator) */
    int needed = 1 + hlen + 1 + 5 + 1;
    if (needed > buf_len || hlen > MAX_HOSTNAME_LEN) {
        return 0;
    }
    buf[0] = (uint8_t)hlen;
    memcpy(&buf[1], hostname, hlen);
    buf[1 + hlen] = 5;
    memcpy(&buf[2 + hlen], "local", 5);
    buf[7 + hlen] = 0; /* root label */
    return needed;
}

/* Case-insensitive comparison of DNS wire-format name against "<hostname>.local" */
static bool name_matches(const uint8_t *pkt, int pkt_len, int offset)
{
    int hlen = strlen(s_hostname);

    /* Check first label length */
    if (offset >= pkt_len) return false;
    if (pkt[offset] != hlen) return false;
    offset++;

    /* Compare hostname (case-insensitive) */
    if (offset + hlen > pkt_len) return false;
    for (int i = 0; i < hlen; i++) {
        if (tolower(pkt[offset + i]) != tolower(s_hostname[i])) return false;
    }
    offset += hlen;

    /* Check "local" label */
    if (offset >= pkt_len) return false;
    if (pkt[offset] != 5) return false;
    offset++;
    if (offset + 5 > pkt_len) return false;
    if (strncasecmp((const char *)&pkt[offset], "local", 5) != 0) return false;
    offset += 5;

    /* Check root terminator */
    if (offset >= pkt_len) return false;
    return pkt[offset] == 0;
}

/* Skip a DNS name in the packet (handles compression pointers).
 * Returns new offset, or -1 on error. */
static int skip_name(const uint8_t *pkt, int pkt_len, int offset)
{
    while (offset < pkt_len) {
        uint8_t len = pkt[offset];
        if (len == 0) {
            return offset + 1;
        }
        if ((len & 0xC0) == 0xC0) {
            /* Compression pointer — 2 bytes */
            return offset + 2;
        }
        offset += 1 + len;
    }
    return -1;
}

static void mdns_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                          const ip_addr_t *addr, u16_t port)
{
    if (p == NULL || s_ip_addr == 0 || s_hostname[0] == '\0') {
        if (p) pbuf_free(p);
        return;
    }

    /* Linearize if chained */
    uint8_t *pkt = (uint8_t *)p->payload;
    int pkt_len = p->tot_len;
    uint8_t *tmp_buf = NULL;
    if (p->next != NULL) {
        tmp_buf = malloc(pkt_len);
        if (!tmp_buf) { pbuf_free(p); return; }
        pbuf_copy_partial(p, tmp_buf, pkt_len, 0);
        pkt = tmp_buf;
    }

    /* Parse DNS header (12 bytes minimum) */
    if (pkt_len < 12) goto done;

    uint16_t flags  = (pkt[2] << 8) | pkt[3];
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];

    /* Only process queries (QR=0) */
    if (flags & DNS_FLAG_QR) goto done;

    int offset = 12;
    for (int q = 0; q < qdcount && offset < pkt_len; q++) {
        int name_off = offset;

        /* Skip the QNAME */
        offset = skip_name(pkt, pkt_len, offset);
        if (offset < 0 || offset + 4 > pkt_len) goto done;

        uint16_t qtype  = (pkt[offset] << 8) | pkt[offset + 1];
        uint16_t qclass = (pkt[offset + 2] << 8) | pkt[offset + 3];
        offset += 4;

        /* Match: A record, IN class (ignore unicast-response bit) */
        if (qtype == DNS_TYPE_A && (qclass & 0x7FFF) == DNS_CLASS_IN) {
            if (name_matches(pkt, pkt_len, name_off)) {
                /* Build response — RFC 6762: txid=0, no question section */
                int hlen = strlen(s_hostname);
                int name_wire_len = 1 + hlen + 1 + 5 + 1; /* label + "local" + root */
                /* hdr(12) + answer(name + type(2)+class(2)+TTL(4)+rdlen(2)+rdata(4)) */
                int resp_len = 12 + (name_wire_len + 2 + 2 + 4 + 2 + 4);

                struct pbuf *reply = pbuf_alloc(PBUF_TRANSPORT, resp_len, PBUF_RAM);
                if (!reply) goto done;

                uint8_t *r = (uint8_t *)reply->payload;
                memset(r, 0, resp_len);
                int w = 0;

                /* DNS Header: txid=0 (required by RFC 6762), QR+AA, no questions */
                r[w++] = 0; r[w++] = 0; /* txid = 0 */
                uint16_t rflags = DNS_FLAG_QR | DNS_FLAG_AA;
                r[w++] = rflags >> 8; r[w++] = rflags & 0xFF;
                r[w++] = 0; r[w++] = 0; /* QDCOUNT = 0 */
                r[w++] = 0; r[w++] = 1; /* ANCOUNT = 1 */
                r[w++] = 0; r[w++] = 0; /* NSCOUNT */
                r[w++] = 0; r[w++] = 0; /* ARCOUNT */

                /* Answer section */
                w += build_query_name(s_hostname, &r[w], resp_len - w);
                r[w++] = 0; r[w++] = DNS_TYPE_A;
                /* Class IN + cache-flush bit */
                uint16_t aclass = DNS_CLASS_IN | DNS_CACHE_FLUSH;
                r[w++] = aclass >> 8; r[w++] = aclass & 0xFF;
                /* TTL */
                r[w++] = (MDNS_TTL >> 24) & 0xFF;
                r[w++] = (MDNS_TTL >> 16) & 0xFF;
                r[w++] = (MDNS_TTL >> 8) & 0xFF;
                r[w++] = MDNS_TTL & 0xFF;
                /* RDLENGTH = 4 */
                r[w++] = 0; r[w++] = 4;
                /* RDATA = IPv4 address (already in network byte order) */
                memcpy(&r[w], &s_ip_addr, 4);

                /* Send multicast response */
                ip_addr_t mcast;
                IP_ADDR4(&mcast, 224, 0, 0, 251);
                udp_sendto(pcb, reply, &mcast, MDNS_PORT);
                pbuf_free(reply);
                goto done;
            }
        }
    }

done:
    free(tmp_buf);
    pbuf_free(p);
}

esp_err_t mdns_responder_start(const char *hostname, uint32_t ip_addr)
{
    if (s_pcb) return ESP_ERR_INVALID_STATE;

    if (!hostname || strlen(hostname) == 0 || strlen(hostname) > MAX_HOSTNAME_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    strncpy(s_hostname, hostname, MAX_HOSTNAME_LEN);
    s_hostname[MAX_HOSTNAME_LEN] = '\0';
    /* Lowercase the stored hostname for matching */
    for (int i = 0; s_hostname[i]; i++) {
        s_hostname[i] = tolower(s_hostname[i]);
    }
    s_ip_addr = ip_addr;

    s_pcb = udp_new();
    if (!s_pcb) return ESP_ERR_NO_MEM;

    /* Bind to any address on mDNS port */
    err_t err = udp_bind(s_pcb, IP_ADDR_ANY, MDNS_PORT);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "udp_bind failed: %d", err);
        udp_remove(s_pcb);
        s_pcb = NULL;
        return ESP_FAIL;
    }

    s_pcb->mcast_ttl = 255;
    s_pcb->so_options |= SOF_REUSEADDR;

    udp_recv(s_pcb, mdns_recv_cb, NULL);

    ESP_LOGI(TAG, "mDNS responder started: %s.local", s_hostname);
    return ESP_OK;
}

static void join_multicast_all_netifs(void)
{
    ip4_addr_t mcast_addr;
    mcast_addr.addr = MDNS_MCAST_ADDR;
    struct netif *netif;
    NETIF_FOREACH(netif) {
        igmp_joingroup_netif(netif, &mcast_addr);
    }
}

void mdns_responder_set_ip(uint32_t ip_addr)
{
    s_ip_addr = ip_addr;
    join_multicast_all_netifs();
}

void mdns_responder_set_hostname(const char *hostname)
{
    if (hostname && strlen(hostname) <= MAX_HOSTNAME_LEN) {
        strncpy(s_hostname, hostname, MAX_HOSTNAME_LEN);
        s_hostname[MAX_HOSTNAME_LEN] = '\0';
        for (int i = 0; s_hostname[i]; i++) {
            s_hostname[i] = tolower(s_hostname[i]);
        }
    }
}

void mdns_responder_stop(void)
{
    if (s_pcb) {
        udp_remove(s_pcb);
        s_pcb = NULL;
    }
    s_ip_addr = 0;
    s_hostname[0] = '\0';
}
