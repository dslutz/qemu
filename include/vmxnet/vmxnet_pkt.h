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

#ifndef VMXNET_PKT_H
#define VMXNET_PKT_H

#include "stdint.h"
#include "stdbool.h"
#include "vmxnet_utils.h"

/* defines to enable packet dump functions */
/*#define VMXNET_TX_PKT_DEBUG*/
/*#define VMXNET_RX_PKT_DEBUG*/

/*=============================================================================
 *=============================================================================
 *
 *                            TX INTERFACE
 *
 *=============================================================================
 *===========================================================================*/

/* tx module context handle */
typedef void *VmxnetTxPktH;

/**
 * Init function for tx packet functionality
 *
 * @pkt:            private handle
 * @max_frags:      max tx ip fragments
 * @has_virt_hdr:   device uses virtio header.
 */
void vmxnet_tx_pkt_init(VmxnetTxPktH *pkt, uint32_t max_frags,
    bool has_virt_hdr);

/**
 * Clean all tx packet resources.
 *
 * @pkt:            private handle.
 */
void vmxnet_tx_pkt_uninit(VmxnetTxPktH pkt);

/**
 * get virtio header
 *
 * @pkt:            private handle
 * @ret:            virtio header
 */
struct virtio_net_hdr *vmxnet_tx_pkt_get_vhdr(VmxnetTxPktH pkt);

/**
 * build virtio header (will be stored in module context)
 *
 * @pkt:            private handle
 * @tso_enable:     TSO enabled
 * @csum_enable:    CSO enabled
 * @gso_size:       MSS size for TSO
 *
 */
void vmxnet_tx_pkt_build_vheader(VmxnetTxPktH pkt, bool tso_enable,
    bool csum_enable, uint32_t gso_size);

/**
 * updates vlan tag, and adds vlan header in case it is missing
 *
 * @pkt:            private handle
 * @vlan:           VLAN tag
 *
 */
void vmxnet_tx_pkt_setup_vlan_header(VmxnetTxPktH pkt, uint16_t vlan);

/**
 * populate data fragment into pkt context.
 *
 * @pkt:            private handle.
 * @pa:             physical address of fragment
 * @len:            length of fragment
 *
 */
bool vmxnet_tx_pkt_add_raw_fragment(VmxnetTxPktH pkt, hwaddr pa,
    size_t len);

/**
 * fix ip header fields and calculate checksums needed.
 *
 * @pkt:            private handle.
 *
 */
void vmxnet_tx_pkt_update_ip_checksums(VmxnetTxPktH pkt);

/**
 * get length of all populated data.
 *
 * @pkt:            private handle.
 * @ret:            total data length
 *
 */
size_t vmxnet_tx_pkt_get_total_len(VmxnetTxPktH pkt);

/**
 * get packet type
 *
 * @pkt:            private handle.
 * @ret:            packet type
 *
 */
eth_pkt_types_e vmxnet_tx_pkt_get_packet_type(VmxnetTxPktH pkt);

/**
 * prints packet data if debug is enabled
 *
 * @pkt:            private handle.
 *
 */
void vmxnet_tx_pkt_dump(VmxnetTxPktH pkt);

/**
 * reset tx packet private context (needed to be called between packets)
 *
 * @pkt:            private handle.
 *
 */
void vmxnet_tx_pkt_reset(VmxnetTxPktH pkt);

/**
 * Send packet to qemu. handles sw offloads if vhdr is not supported.
 *
 * @pkt:            private handle.
 * @vc:             NetClientState.
 * @ret: number of bytes sent.
 *
 */
size_t vmxnet_tx_pkt_send(VmxnetTxPktH pkt, NetClientState *vc);

/**
 * parse raw packet data and analyze offload requirements.
 *
 * @pkt:            private handle.
 *
 */
bool vmxnet_tx_pkt_parse(VmxnetTxPktH pkt);

/*=============================================================================
 *=============================================================================
 *
 *                            RX INTERFACE
 *
 *=============================================================================
 *===========================================================================*/

/* rx module context handle */
typedef void *VmxnetRxPktH;

/**
 * Clean all rx packet resources
 *
 * @pkt:            private handle
 *
 */
void vmxnet_rx_pkt_uninit(VmxnetRxPktH pkt);

/**
 * Init function for rx packet functionality
 *
 * @pkt:            private handle
 * @has_virt_hdr:   device uses virtio header
 *
 */
void vmxnet_rx_pkt_init(VmxnetRxPktH *pkt, bool has_virt_hdr);

/**
 * returns total length of data attached to rx context
 *
 * @pkt:            private handle
 *
 * Return:  nothing
 *
 */
size_t vmxnet_rx_pkt_get_total_len(VmxnetRxPktH pkt);

/**
 * fetches packet analysis results
 *
 * @pkt:            private handle
 * @isip4:          whether the packet given is IPv4
 * @isip6:          whether the packet given is IPv6
 * @isudp:          whether the packet given is UDP
 * @istcp:          whether the packet given is TCP
 *
 */
void vmxnet_rx_pkt_get_protocols(VmxnetRxPktH pkt,
                                 bool *isip4, bool *isip6,
                                 bool *isudp, bool *istcp);

/**
 * returns virtio header stored in rx context
 *
 * @pkt:            private handle
 * @ret:            virtio header
 *
 */
struct virtio_net_hdr *vmxnet_rx_pkt_get_vhdr(VmxnetRxPktH pkt);

/**
 * returns packet type
 *
 * @pkt:            private handle
 * @ret:            packet type
 *
 */
eth_pkt_types_e vmxnet_rx_pkt_get_packet_type(VmxnetRxPktH pkt);

/**
 * returns vlan tag
 *
 * @pkt:            private handle
 * @ret:            VLAN tag
 *
 */
uint16_t vmxnet_rx_pkt_get_vlan_tag(VmxnetRxPktH pkt);

/**
 * tells whether vlan was stripped from the packet
 *
 * @pkt:            private handle
 * @ret:            VLAN stripped sign
 *
 */
bool vmxnet_rx_pkt_is_vlan_stripped(VmxnetRxPktH pkt);

/**
 * notifies caller if the packet has virtio header
 *
 * @pkt:            private handle
 * @ret:            true if packet has virtio header, false otherwize
 *
 */
bool vmxnet_rx_pkt_has_virt_hdr(VmxnetRxPktH pkt);

/**
 * returns number of frags attached to the packet
 *
 * @pkt:            private handle
 * @ret:            number of frags
 *
 */
uint16_t vmxnet_rx_pkt_get_num_frags(VmxnetRxPktH pkt);

/**
 * attach data to rx packet
 *
 * @pkt:            private handle
 * @data:           pointer to the data buffer
 * @len:            data length
 * @strip_vlan:     should the module strip vlan from data
 *
 */
void vmxnet_rx_pkt_attach_data(VmxnetRxPktH pkt, const void *data,
    size_t len, bool strip_vlan);

/**
 * returns io vector that holds the attached data
 *
 * @pkt:            private handle
 * @ret:            pointer to IOVec
 *
 */
struct iovec *vmxnet_rx_pkt_get_iovec(VmxnetRxPktH pkt);

/**
 * prints rx packet data if debug is enabled
 *
 * @pkt:            private handle
 *
 */
void vmxnet_rx_pkt_dump(VmxnetRxPktH pkt);

/**
 * copy passed vhdr data to packet context
 *
 * @pkt:            private handle
 * @vhdr:           VHDR buffer
 *
 */
void vmxnet_rx_pkt_set_vhdr(VmxnetRxPktH pkt, struct virtio_net_hdr *vhdr);

/**
 * save packet type in packet context
 *
 * @pkt:            private handle
 * @packet_type:    the packet type
 *
 */
void vmxnet_rx_pkt_set_packet_type(VmxnetRxPktH pkt,
    eth_pkt_types_e packet_type);

#endif
