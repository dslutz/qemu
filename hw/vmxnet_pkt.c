/*
 * QEMU VMWARE VMXNET* paravirtual NICs - packets abstractions
 *
 * Copyright (c) 2012 Ravello Systems LTD (http://ravellosystems.com)
 *
 * Developed by Daynix Computing LTD (http://www.daynix.com)
 *
 * Authors:
 * Dmitry Fleytman <dmitry@daynix.com>
 * Tamir Shomer <tamirs@daynix.com>
 * Yan Vugenfirer <yan@daynix.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "vmxnet_pkt.h"
#include "vmxnet_utils.h"
#include "qemu/iov.h"

#include "net/checksum.h"
#include "net/tap.h"

/*=============================================================================
 *=============================================================================
 *
 *                            TX CODE
 *
 *=============================================================================
 *===========================================================================*/

enum {
    VMXNET_TX_PKT_VHDR_FRAG = 0,
    VMXNET_TX_PKT_L2HDR_FRAG,
    VMXNET_TX_PKT_L3HDR_FRAG,
    VMXNET_TX_PKT_PL_START_FRAG
};

/* TX packet private context */
typedef struct {
    struct virtio_net_hdr virt_hdr;
    bool has_virt_hdr;

    struct iovec *raw;
    uint32_t raw_frags;
    uint32_t max_raw_frags;

    struct iovec *vec;

    uint8_t l2_hdr[ETH_MAX_L2_HDR_LEN];

    uint32_t payload_len;

    uint32_t payload_frags;
    uint32_t max_payload_frags;

    uint16_t hdr_len;
    eth_pkt_types_e packet_type;
    uint8_t l4proto;
} VmxnetTxPkt;

void vmxnet_tx_pkt_init(VmxnetTxPktH *pkt, uint32_t max_frags,
    bool has_virt_hdr)
{
    VmxnetTxPkt *p = g_malloc0(sizeof *p);

    p->vec = g_malloc((sizeof *p->vec) *
        (max_frags + VMXNET_TX_PKT_PL_START_FRAG));

    p->raw = g_malloc((sizeof *p->raw) * max_frags);

    p->max_payload_frags = max_frags;
    p->max_raw_frags = max_frags;
    p->has_virt_hdr = has_virt_hdr;
    p->vec[VMXNET_TX_PKT_VHDR_FRAG].iov_base = &p->virt_hdr;
    p->vec[VMXNET_TX_PKT_VHDR_FRAG].iov_len =
        p->has_virt_hdr ? sizeof p->virt_hdr : 0;
    p->vec[VMXNET_TX_PKT_L2HDR_FRAG].iov_base = &p->l2_hdr;
    p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_base = NULL;
    p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_len = 0;

    *pkt = p;
}

void vmxnet_tx_pkt_uninit(VmxnetTxPktH pkt)
{
    VmxnetTxPkt *p = (VmxnetTxPkt *)pkt;

    if (p) {
        if (p->vec) {
            g_free(p->vec);
        }

        if (p->raw) {
            g_free(p->raw);
        }

        g_free(p);
    }
}

void vmxnet_tx_pkt_update_ip_checksums(VmxnetTxPktH pkt)
{
    uint16_t csum;
    uint32_t ph_raw_csum;
    VmxnetTxPkt *p = (VmxnetTxPkt *)pkt;
    assert(p);
    uint8_t gso_type = p->virt_hdr.gso_type & ~VIRTIO_NET_HDR_GSO_ECN;
    struct ip_header *ip_hdr;

    if (VIRTIO_NET_HDR_GSO_TCPV4 != gso_type &&
        VIRTIO_NET_HDR_GSO_UDP != gso_type) {
        return;
    }

    ip_hdr = p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_base;

    if (p->payload_len + p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_len >
        ETH_MAX_IP_DGRAM_LEN) {
        return;
    }

    ip_hdr->ip_len = cpu_to_be16(p->payload_len +
        p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_len);

    /* Calculate IP header checksum                    */
    ip_hdr->ip_sum = 0;
    csum = net_raw_checksum((uint8_t *)ip_hdr,
        p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_len);
    ip_hdr->ip_sum = cpu_to_be16(csum);

    /* Calculate IP pseudo header checksum             */
    ph_raw_csum = eth_calc_pseudo_hdr_csum(ip_hdr, p->payload_len);
    csum = cpu_to_be16(net_checksum_finish(ph_raw_csum));
    iov_from_buf(&p->vec[VMXNET_TX_PKT_PL_START_FRAG], p->payload_frags,
                 p->virt_hdr.csum_offset, &csum, sizeof(csum));
}

static void vmxnet_tx_pkt_calculate_hdr_len(VmxnetTxPkt *p)
{
    p->hdr_len = p->vec[VMXNET_TX_PKT_L2HDR_FRAG].iov_len +
        p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_len;
}

static bool vmxnet_tx_pkt_parse_headers(VmxnetTxPktH pkt)
{
    VmxnetTxPkt *p = (VmxnetTxPkt *)pkt;
    struct iovec *l2_hdr, *l3_hdr;
    size_t bytes_read;
    size_t full_ip6hdr_len;
    uint16_t l3_proto;

    assert(p);

    l2_hdr = &p->vec[VMXNET_TX_PKT_L2HDR_FRAG];
    l3_hdr = &p->vec[VMXNET_TX_PKT_L3HDR_FRAG];

    bytes_read = iov_to_buf(p->raw, p->raw_frags, 0,
                            l2_hdr->iov_base, ETH_MAX_L2_HDR_LEN);
    if (bytes_read < ETH_MAX_L2_HDR_LEN) {
        l2_hdr->iov_len = 0;
        return false;
    } else {
        l2_hdr->iov_len = eth_get_l2_hdr_length(l2_hdr->iov_base);
    }

    l3_proto = eth_get_l3_proto(l2_hdr->iov_base, l2_hdr->iov_len);

    switch (l3_proto) {
    case ETH_P_IP:
        l3_hdr->iov_base = g_malloc(ETH_MAX_IP4_HDR_LEN);

        bytes_read = iov_to_buf(p->raw, p->raw_frags,
                                l2_hdr->iov_len,
                                l3_hdr->iov_base, sizeof(struct ip_header));

        if (bytes_read < sizeof(struct ip_header)) {
            l3_hdr->iov_len = 0;
            return false;
        }

        l3_hdr->iov_len = IP_HDR_GET_LEN(l3_hdr->iov_base);
        p->l4proto = ((struct ip_header *) l3_hdr->iov_base)->ip_p;

        /* copy optional IPv4 header data */
        bytes_read = iov_to_buf(p->raw, p->raw_frags,
                                l2_hdr->iov_len + sizeof(struct ip_header),
                                l3_hdr->iov_base + sizeof(struct ip_header),
                                l3_hdr->iov_len - sizeof(struct ip_header));
        if (bytes_read < l3_hdr->iov_len - sizeof(struct ip_header)) {
            l3_hdr->iov_len = 0;
            return false;
        }
        break;

    case ETH_P_IPV6:
        if (!eth_parse_ipv6_hdr(p->raw, p->raw_frags, l2_hdr->iov_len,
                               &p->l4proto, &full_ip6hdr_len)) {
            l3_hdr->iov_len = 0;
            return false;
        }

        l3_hdr->iov_base = g_malloc(full_ip6hdr_len);

        bytes_read = iov_to_buf(p->raw, p->raw_frags,
                                l2_hdr->iov_len,
                                l3_hdr->iov_base, full_ip6hdr_len);

        if (bytes_read < full_ip6hdr_len) {
            l3_hdr->iov_len = 0;
            return false;
        } else {
            l3_hdr->iov_len = full_ip6hdr_len;
        }
        break;

    default:
        l3_hdr->iov_len = 0;
        break;
    }

    vmxnet_tx_pkt_calculate_hdr_len(p);
    p->packet_type = get_eth_packet_type(l2_hdr->iov_base);
    return true;
}

static bool vmxnet_tx_pkt_rebuild_payload(VmxnetTxPktH pkt)
{
    VmxnetTxPkt *p = (VmxnetTxPkt *)pkt;

    p->payload_frags = iov_rebuild(&p->vec[VMXNET_TX_PKT_PL_START_FRAG],
                                   p->max_payload_frags,
                                   p->raw, p->raw_frags,
                                   p->hdr_len);

    if (p->payload_frags != (uint32_t) -1) {
        p->payload_len = iov_size(&p->vec[VMXNET_TX_PKT_PL_START_FRAG],
                                  p->payload_frags);
        return true;
    } else {
        return false;
    }
}

bool vmxnet_tx_pkt_parse(VmxnetTxPktH pkt)
{
    return vmxnet_tx_pkt_parse_headers(pkt) &&
           vmxnet_tx_pkt_rebuild_payload(pkt);
}

struct virtio_net_hdr *vmxnet_tx_pkt_get_vhdr(VmxnetTxPktH pkt)
{
    VmxnetTxPkt *p = (VmxnetTxPkt *)pkt;
    assert(p);
    return &p->virt_hdr;
}

static uint8_t vmxnet_tx_pkt_get_gso_type(VmxnetTxPkt *p, bool tso_enable)
{
    uint8_t rc = VIRTIO_NET_HDR_GSO_NONE;
    uint16_t l3_proto;

    l3_proto = eth_get_l3_proto(p->vec[VMXNET_TX_PKT_L2HDR_FRAG].iov_base,
        p->vec[VMXNET_TX_PKT_L2HDR_FRAG].iov_len);

    if (!tso_enable) {
        goto func_exit;
    }

    rc = eth_get_gso_type(l3_proto, p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_base,
                          p->l4proto);

func_exit:
    return rc;
}

void vmxnet_tx_pkt_build_vheader(VmxnetTxPktH pkt, bool tso_enable,
    bool csum_enable, uint32_t gso_size)
{
    VmxnetTxPkt *p = (VmxnetTxPkt *)pkt;
    struct tcp_hdr l4hdr;
    assert(p);

    /* csum has to be enabled if tso is. */
    assert(csum_enable || !tso_enable);

    p->virt_hdr.gso_type = vmxnet_tx_pkt_get_gso_type(p, tso_enable);

    switch (p->virt_hdr.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
    case VIRTIO_NET_HDR_GSO_NONE:
        p->virt_hdr.hdr_len = 0;
        p->virt_hdr.gso_size = 0;
        break;

    case VIRTIO_NET_HDR_GSO_UDP:
        p->virt_hdr.gso_size = IP_FRAG_ALIGN_SIZE(gso_size);
        p->virt_hdr.hdr_len = p->hdr_len + sizeof(struct udp_header);
        break;

    case VIRTIO_NET_HDR_GSO_TCPV4:
    case VIRTIO_NET_HDR_GSO_TCPV6:
        iov_to_buf(&p->vec[VMXNET_TX_PKT_PL_START_FRAG], p->payload_frags,
                   0, &l4hdr, sizeof(l4hdr));
        p->virt_hdr.hdr_len = p->hdr_len + l4hdr.th_off * sizeof(uint32_t);
        p->virt_hdr.gso_size = IP_FRAG_ALIGN_SIZE(gso_size);
        break;

    default:
        assert(false);
    }

    if (csum_enable) {
        switch (p->l4proto) {
        case IP_PROTO_TCP:
            p->virt_hdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
            p->virt_hdr.csum_start = p->hdr_len;
            p->virt_hdr.csum_offset = offsetof(struct tcp_hdr, th_sum);
            break;
        case IP_PROTO_UDP:
            p->virt_hdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
            p->virt_hdr.csum_start = p->hdr_len;
            p->virt_hdr.csum_offset = offsetof(struct udp_hdr, uh_sum);
            break;
        default:
            break;
        }
    }
}

void vmxnet_tx_pkt_setup_vlan_header(VmxnetTxPktH pkt, uint16_t vlan)
{
    bool is_new;
    VmxnetTxPkt *p = (VmxnetTxPkt *)pkt;
    assert(p);

    eth_setup_vlan_headers(p->vec[VMXNET_TX_PKT_L2HDR_FRAG].iov_base,
        vlan, &is_new);

    /* update l2hdrlen */
    if (is_new) {
        p->hdr_len += sizeof(struct vlan_header);
        p->vec[VMXNET_TX_PKT_L2HDR_FRAG].iov_len += sizeof(struct vlan_header);
    }
}

bool vmxnet_tx_pkt_add_raw_fragment(VmxnetTxPktH pkt, hwaddr pa,
    size_t len)
{
    VmxnetTxPkt *p = (VmxnetTxPkt *)pkt;
    hwaddr mapped_len = 0;
    struct iovec *ventry;
    assert(p);
    assert(p->max_raw_frags > p->raw_frags);

    if (!len) {
        return true;
     }

    ventry = &p->raw[p->raw_frags];
    mapped_len = len;

    ventry->iov_base = cpu_physical_memory_map(pa, &mapped_len, false);
    ventry->iov_len = mapped_len;
    p->raw_frags += !!ventry->iov_base;

    if ((NULL == ventry->iov_base) || (len != mapped_len)) {
        return false;
    }

    return true;
}

eth_pkt_types_e vmxnet_tx_pkt_get_packet_type(VmxnetTxPktH pkt)
{
    VmxnetTxPkt *p = (VmxnetTxPkt *)pkt;
    assert(p);

    return p->packet_type;
}

size_t vmxnet_tx_pkt_get_total_len(VmxnetTxPktH pkt)
{
    VmxnetTxPkt *p = (VmxnetTxPkt *)pkt;
    assert(p);

    return p->hdr_len + p->payload_len;
}

void vmxnet_tx_pkt_dump(VmxnetTxPktH pkt)
{
#ifdef VMXNET_TX_PKT_DEBUG
    VmxnetTxPkt *p = (VmxnetTxPkt *)pkt;
    assert(p);

    printf("TX PKT: hdr_len: %d, pkt_type: 0x%X, l2hdr_len: %lu, "
        "l3hdr_len: %lu, payload_len: %u\n", p->hdr_len, p->packet_type,
        p->vec[VMXNET_TX_PKT_L2HDR_FRAG].iov_len,
        p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_len, p->payload_len);
#endif
}

void vmxnet_tx_pkt_reset(VmxnetTxPktH pkt)
{
    VmxnetTxPkt *p = (VmxnetTxPkt *)pkt;
    int i;

    /* no assert, as reset can be called before tx_pkt_init */
    if (!p) {
        return;
    }

    memset(&p->virt_hdr, 0, sizeof(p->virt_hdr));

    if (NULL != p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_base) {
        g_free(p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_base);
        p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_base = NULL;
    }

    assert(p->vec);
    for (i = VMXNET_TX_PKT_L2HDR_FRAG;
         i < p->payload_frags + VMXNET_TX_PKT_PL_START_FRAG; i++) {
        p->vec[i].iov_len = 0;
    }
    p->payload_len = 0;
    p->payload_frags = 0;

    assert(p->raw);
    for (i = 0; i < p->raw_frags; i++) {
        assert(p->raw[i].iov_base);
        cpu_physical_memory_unmap(p->raw[i].iov_base, p->raw[i].iov_len,
                                  false, p->raw[i].iov_len);
        p->raw[i].iov_len = 0;
    }
    p->raw_frags = 0;

    p->hdr_len = 0;
    p->packet_type = 0;
    p->l4proto = 0;
}

static void vmxnet_tx_pkt_do_sw_csum(VmxnetTxPkt *p)
{
    struct iovec *iov = &p->vec[VMXNET_TX_PKT_L2HDR_FRAG];
    uint32_t csum_cntr;
    uint16_t csum = 0;
    /* num of iovec without vhdr */
    uint32_t iov_len = p->payload_frags + VMXNET_TX_PKT_PL_START_FRAG - 1;
    uint16_t csl;
    struct ip_header *iphdr;
    size_t csum_offset = p->virt_hdr.csum_start + p->virt_hdr.csum_offset;

    /* Put zero to checksum field */
    iov_from_buf(iov, iov_len, csum_offset, &csum, sizeof csum);

    /* Calculate L4 TCP/UDP checksum */
    csl = p->payload_len;

    /* data checksum */
    csum_cntr = iov_net_csum_add(iov, iov_len, p->virt_hdr.csum_start, csl);
    /* add pseudo header to csum */
    iphdr = p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_base;
    csum_cntr += eth_calc_pseudo_hdr_csum(iphdr, csl);

    /* Put the checksum obtained into the packet */
    csum = cpu_to_be16(net_checksum_finish(csum_cntr));
    iov_from_buf(iov, iov_len, csum_offset, &csum, sizeof(csum));
}

enum {
    VMXNET_TX_PKT_FRAGMENT_L2_HDR_POS = 0,
    VMXNET_TX_PKT_FRAGMENT_L3_HDR_POS,
    VMXNET_TX_PKT_FRAGMENT_HEADER_NUM
};

#define VMXNET_MAX_FRAG_SG_LIST (64)

static size_t vmxnet_tx_pkt_fetch_fragment(VmxnetTxPkt *p, int *src_idx,
    size_t *src_offset, struct iovec *dst, int *dst_idx)
{
    size_t fetched = 0;
    struct iovec *src = p->vec;

    *dst_idx = VMXNET_TX_PKT_FRAGMENT_HEADER_NUM;

    while (fetched < p->virt_hdr.gso_size) {

        /* no more place in fragment iov */
        if (*dst_idx == VMXNET_MAX_FRAG_SG_LIST) {
            break;
        }

        /* no more data in iovec */
        if (*src_idx == (p->payload_frags + VMXNET_TX_PKT_PL_START_FRAG)) {
            break;
        }


        dst[*dst_idx].iov_base = src[*src_idx].iov_base + *src_offset;
        dst[*dst_idx].iov_len = MIN(src[*src_idx].iov_len - *src_offset,
            p->virt_hdr.gso_size - fetched);

        *src_offset += dst[*dst_idx].iov_len;
        fetched += dst[*dst_idx].iov_len;

        if (*src_offset == src[*src_idx].iov_len) {
            *src_offset = 0;
            (*src_idx)++;
        }

        (*dst_idx)++;
    }

    return fetched;
}

static size_t vmxnet_tx_pkt_do_sw_fragmentation(VmxnetTxPkt *p,
    NetClientState *vc)
{
    struct iovec fragment[VMXNET_MAX_FRAG_SG_LIST];
    size_t fragment_len = 0;
    bool more_frags = false;
    /* some poiners for shorter code */
    void *l2_iov_base, *l3_iov_base;
    size_t l2_iov_len, l3_iov_len;
    int src_idx =  VMXNET_TX_PKT_PL_START_FRAG, dst_idx;
    size_t src_offset = 0;
    size_t bytes_sent = 0;
    size_t fragment_offset = 0;

    l2_iov_base = p->vec[VMXNET_TX_PKT_L2HDR_FRAG].iov_base;
    l2_iov_len = p->vec[VMXNET_TX_PKT_L2HDR_FRAG].iov_len;
    l3_iov_base = p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_base;
    l3_iov_len = p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_len;

    /* Copy headers */
    fragment[VMXNET_TX_PKT_FRAGMENT_L2_HDR_POS].iov_base = l2_iov_base;
    fragment[VMXNET_TX_PKT_FRAGMENT_L2_HDR_POS].iov_len = l2_iov_len;
    fragment[VMXNET_TX_PKT_FRAGMENT_L3_HDR_POS].iov_base = l3_iov_base;
    fragment[VMXNET_TX_PKT_FRAGMENT_L3_HDR_POS].iov_len = l3_iov_len;


    /* Put as much data as possible and send */
    do {
        fragment_len = vmxnet_tx_pkt_fetch_fragment(p, &src_idx, &src_offset,
            fragment, &dst_idx);

        more_frags = (fragment_offset + fragment_len < p->payload_len);

        eth_setup_ip4_fragmentation(l2_iov_base, l2_iov_len, l3_iov_base,
            l3_iov_len, fragment_len, fragment_offset, more_frags);

        eth_fix_ip4_checksum(l3_iov_base, l3_iov_len);

        bytes_sent += qemu_sendv_packet(vc, fragment, dst_idx);

        fragment_offset += fragment_len;

    } while (more_frags);

    return bytes_sent;
}

size_t vmxnet_tx_pkt_send(VmxnetTxPktH pkt, NetClientState *vc)
{
    size_t bytes_sent = 0;
    VmxnetTxPkt *p = (VmxnetTxPkt *)pkt;
    assert(p);

    if (!p->has_virt_hdr && p->virt_hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
        vmxnet_tx_pkt_do_sw_csum(p);
    }

    /*
     * Since underlying infrastructure does not support IP datagrams longer
     * than 64K we should drop such packets and don't even try to send
     */
    if (VIRTIO_NET_HDR_GSO_NONE != p->virt_hdr.gso_type) {
        if (p->payload_len >
            ETH_MAX_IP_DGRAM_LEN - p->vec[VMXNET_TX_PKT_L3HDR_FRAG].iov_len) {
            return 0;
        }
    }

    if (p->has_virt_hdr || VIRTIO_NET_HDR_GSO_NONE == p->virt_hdr.gso_type) {
        bytes_sent = qemu_sendv_packet(vc, p->vec,
            p->payload_frags + VMXNET_TX_PKT_PL_START_FRAG);
        goto func_exit;
    }

    bytes_sent = vmxnet_tx_pkt_do_sw_fragmentation(p, vc);

func_exit:
    return bytes_sent;
}

/*=============================================================================
 *=============================================================================
 *
 *                            RX CODE
 *
 *=============================================================================
 *===========================================================================*/

/*
 * RX packet may contain up to 2 fragments - rebuilt eth header
 * in case of VLAN tag stripping
 * and payload received from QEMU - in any case
 */
#define VMXNET_MAX_RX_PACKET_FRAGMENTS (2)

typedef struct {
    struct virtio_net_hdr virt_hdr;
    uint8_t ehdr_buf[ETH_MAX_L2_HDR_LEN];
    struct iovec vec[VMXNET_MAX_RX_PACKET_FRAGMENTS];
    uint16_t vec_len;
    uint32_t tot_len;
    uint16_t tci;
    bool vlan_stripped;
    bool has_virt_hdr;
    eth_pkt_types_e packet_type;

    /* Analysis results */
    bool isip4;
    bool isip6;
    bool isudp;
    bool istcp;
} VmxnetRxPkt;

void vmxnet_rx_pkt_init(VmxnetRxPktH *pkt, bool has_virt_hdr)
{
    VmxnetRxPkt *p = g_malloc0(sizeof *p);
    p->has_virt_hdr = has_virt_hdr;
    *pkt = p;
}

void vmxnet_rx_pkt_uninit(VmxnetRxPktH pkt)
{
    if (pkt) {
        g_free(pkt);
    }
}

struct virtio_net_hdr *vmxnet_rx_pkt_get_vhdr(VmxnetRxPktH pkt)
{
    VmxnetRxPkt *p = (VmxnetRxPkt *)pkt;
    assert(p);
    return &p->virt_hdr;
}

void vmxnet_rx_pkt_attach_data(VmxnetRxPktH pkt, const void *data, size_t len,
                               bool strip_vlan)
{
    VmxnetRxPkt *p = (VmxnetRxPkt *)pkt;
    uint16_t tci = 0;
    uint16_t ploff;
    assert(p);
    p->vlan_stripped = false;

    if (strip_vlan) {
        p->vlan_stripped = eth_strip_vlan(data, p->ehdr_buf, &ploff, &tci);
    }

    if (p->vlan_stripped) {
        p->vec[0].iov_base = p->ehdr_buf;
        p->vec[0].iov_len = ploff - sizeof(struct vlan_header);
        p->vec[1].iov_base = (uint8_t *) data + ploff;
        p->vec[1].iov_len = len - ploff;
        p->vec_len = 2;
        p->tot_len = len - ploff + sizeof(struct eth_header);
    } else {
        p->vec[0].iov_base = (void *)data;
        p->vec[0].iov_len = len;
        p->vec_len = 1;
        p->tot_len = len;
    }

    p->tci = tci;

    eth_get_protocols(data, len, &p->isip4, &p->isip6, &p->isudp, &p->istcp);
}

void vmxnet_rx_pkt_dump(VmxnetRxPktH pkt)
{
#ifdef VMXNET_RX_PKT_DEBUG
    VmxnetRxPkt *p = (VmxnetRxPkt *)pkt;
    assert(p);

    printf("RX PKT: tot_len: %d, vlan_stripped: %d, vlan_tag: %d\n",
              p->tot_len, p->vlan_stripped, p->tci);
#endif
}

void vmxnet_rx_pkt_set_packet_type(VmxnetRxPktH pkt,
    eth_pkt_types_e packet_type)
{
    VmxnetRxPkt *p = (VmxnetRxPkt *)pkt;
    assert(p);

    p->packet_type = packet_type;

}

eth_pkt_types_e vmxnet_rx_pkt_get_packet_type(VmxnetRxPktH pkt)
{
    VmxnetRxPkt *p = (VmxnetRxPkt *)pkt;
    assert(p);

    return p->packet_type;
}

size_t vmxnet_rx_pkt_get_total_len(VmxnetRxPktH pkt)
{
    VmxnetRxPkt *p = (VmxnetRxPkt *)pkt;
    assert(p);

    return p->tot_len;
}

void vmxnet_rx_pkt_get_protocols(VmxnetRxPktH pkt,
                                 bool *isip4, bool *isip6,
                                 bool *isudp, bool *istcp)
{
    VmxnetRxPkt *p = (VmxnetRxPkt *)pkt;
    assert(p);

    *isip4 = p->isip4;
    *isip6 = p->isip6;
    *isudp = p->isudp;
    *istcp = p->istcp;
}

struct iovec *vmxnet_rx_pkt_get_iovec(VmxnetRxPktH pkt)
{
    VmxnetRxPkt *p = (VmxnetRxPkt *)pkt;
    assert(p);

    return p->vec;
}

void vmxnet_rx_pkt_set_vhdr(VmxnetRxPktH pkt, struct virtio_net_hdr *vhdr)
{
    VmxnetRxPkt *p = (VmxnetRxPkt *)pkt;
    assert(p);

    memcpy(&p->virt_hdr, vhdr, sizeof p->virt_hdr);
}

bool vmxnet_rx_pkt_is_vlan_stripped(VmxnetRxPktH pkt)
{
    VmxnetRxPkt *p = (VmxnetRxPkt *)pkt;
    assert(p);

    return p->vlan_stripped;
}

bool vmxnet_rx_pkt_has_virt_hdr(VmxnetRxPktH pkt)
{
    VmxnetRxPkt *p = (VmxnetRxPkt *)pkt;
    assert(p);

    return p->has_virt_hdr;
}

uint16_t vmxnet_rx_pkt_get_num_frags(VmxnetRxPktH pkt)
{
    VmxnetRxPkt *p = (VmxnetRxPkt *)pkt;
    assert(p);

    return p->vec_len;
}

uint16_t vmxnet_rx_pkt_get_vlan_tag(VmxnetRxPktH pkt)
{
    VmxnetRxPkt *p = (VmxnetRxPkt *)pkt;
    assert(p);

    return p->tci;
}
