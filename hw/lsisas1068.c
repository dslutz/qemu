/*
 * QEMU LSI LOGIC LSI53C1030, SAS1068 and SAS1068e Host Bus Adapter emulation
 * Based on the QEMU Megasas emulator and the VirtualBox LsiLogic
 * LSI53c1030 SCSI controller
 *
 * Copyright (C) 2006-2009 Oracle Corporation
 * Copyright (c) 2009-2012 Hannes Reinecke, SUSE Labs
 * Copyright (C) 2012 Verizon Corporation
 *
 * This file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License Version 2 (GPLv2)
 * as published by the Free Software Foundation.

 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details. <http://www.gnu.org/licenses/>.
 */

/*
 * Technical Manual
 * http://www.lsi.com/downloads/Public/Obsolete/Obsolete%20Common%20Files/1030_tm.pdf
 *
 * LSI Fusion-MPT Architecture
 * http://www.lsi.com/downloads/Public/Obsolete/Obsolete%20Common%20Files/fusion.pdf
 *
 */

#include "hw.h"
#include "pci.h"
#include "dma.h"
#include "msi.h"
#include "msix.h"
#include "iov.h"
#include "scsi.h"
#include "scsi-defs.h"
#include "block_int.h"
#include "trace.h"

#define MPTSCSI_REQUEST_QUEUE_DEPTH_DEFAULT 128
#define MPTSCSI_REPLY_QUEUE_DEPTH_DEFAULT   128

#define MPTSCSI_MAXIMUM_CHAIN_DEPTH 0x22

#define USE_PCIE
/* #define USE_MSIX */ /* curent theory is that this chip doesn't do msi-x */

/** SPI SCSI controller (LSI53C1030) */
#define MPTSCSI_PCI_SPI_CTRLNAME             "lsi53c1030"
#define MPTSCSI_PCI_SPI_DESC \
    "LSI Logic PCI-X Fusion-MPT SCSI Host Bus Adapter"
#define MPTSCSI_PCI_SPI_REVISION_ID          (0x00)
#define MPTSCSI_PCI_SPI_CLASS_CODE           (0x01)
#define MPTSCSI_PCI_SPI_SUBSYSTEM_ID         (0x8000)
#define MPTSCSI_PCI_SPI_PORTS_MAX            1
#define MPTSCSI_PCI_SPI_BUSES_MAX            1
#define MPTSCSI_PCI_SPI_DEVICES_PER_BUS_MAX  16
#define MPTSCSI_PCI_SPI_DEVICES_MAX \
    (MPTSCSI_PCI_SPI_BUSES_MAX*MPTSCSI_PCI_SPI_DEVICES_PER_BUS_MAX)

/** SAS SCSI controller (SAS1068 PCI-X Fusion-MPT SAS) */
#define MPTSCSI_PCI_SAS_CTRLNAME             "sas1068"
#define MPTSCSI_PCI_SAS_DESC \
    "LSI Logic PCI-X Fusion-MPT SAS Host Bus Adapter"
#define MPTSCSI_PCI_SAS_REVISION_ID          (0x00)
#define MPTSCSI_PCI_SAS_CLASS_CODE           (0x00)
#define MPTSCSI_PCI_SAS_SUBSYSTEM_ID         (0x8000)
#define MPTSCSI_PCI_SAS_PORTS_MAX             256
#define MPTSCSI_PCI_SAS_PORTS_DEFAULT           8
#define MPTSCSI_PCI_SAS_DEVICES_PER_PORT_MAX    1
#define MPTSCSI_PCI_SAS_DEVICES_MAX \
    (MPTSCSI_PCI_SAS_PORTS_MAX*MPTSCSI_PCI_SAS_DEVICES_PER_PORT_MAX)

/** SAS SCSI controller (SAS1068E PCI-Express Fusion-MPT SAS) */
#define MPTSCSI_PCI_SAS_E_CTRLNAME             "sas1068e"
#define MPTSCSI_PCI_SAS_E_DESC \
    "LSI Logic PCI-Express Fusion-MPT SAS Host Bus Adapter"
#define MPTSCSI_PCI_SAS_E_SUBSYSTEM_ID         (0x8000)
#define MPTSCSI_PCI_SAS_E_PORTS_MAX             256
#define MPTSCSI_PCI_SAS_E_PORTS_DEFAULT         128
#define MPTSCSI_PCI_SAS_E_DEVICES_PER_PORT_MAX    1
#define MPTSCSI_PCI_SAS_E_DEVICES_MAX \
    (MPTSCSI_PCI_SAS_E_PORTS_MAX*MPTSCSI_PCI_SAS_E_DEVICES_PER_PORT_MAX)

/**
 * A SAS address.
 */
typedef union QEMU_PACKED SASADDRESS {
    /** 64bit view. */
    uint64_t    ll_address;
    /** 32bit view. */
    uint32_t    l_address[2];
    /** 16bit view. */
    uint16_t    s_address[4];
    /** Byte view. */
    uint8_t     b_address[8];
} SASADDRESS, *PSASADDRESS;

/**
 * Possible device types we support.
 */
typedef enum MPTCTRLTYPE {
    /** SPI SCSI controller (PCI dev id 0x0030) */
    MPTCTRLTYPE_SCSI_SPI = 0,
    /** SAS SCSI controller (PCI dev id 0x0054 & 0x0058) */
    MPTCTRLTYPE_SCSI_SAS = 1,
    /** 32bit hack */
    MPTCTRLTYPE_32BIT_HACK = 0x7fffffff
} MPTCTRLTYPE, *PMPTCTRLTYPE;

/**
 * A simple SG element for a 64bit address.
 */
typedef struct QEMU_PACKED MptSGEntrySimple64 {
    /** Length of the buffer this entry describes. */
    unsigned length:24;
    /** Flag whether this element is the end of the list. */
    unsigned end_of_list:1;
    /** Flag whether the address is 32bit or 64bits wide. */
    unsigned bit_address:1;
    /** Flag whether this buffer contains data to be transferred or
        is the destination. */
    unsigned buffer_contains_data:1;
    /** Flag whether this is a local address or a system address. */
    unsigned local_address:1;
    /** Element type. */
    unsigned element_type:2;
    /** Flag whether this is the last element of the buffer. */
    unsigned end_of_buffer:1;
    /** Flag whether this is the last element of the current segment. */
    unsigned last_element:1;
    /** Lower 32bits of the address of the data buffer. */
    uint32_t data_buf_addr_low;
    /** Upper 32bits of the address of the data buffer. */
    uint32_t data_buf_addr_high;
} MptSGEntrySimple64, *PMptSGEntrySimple64;

/**
 * A simple SG element for a 32bit address.
 */
typedef struct QEMU_PACKED MptSGEntrySimple32 {
    /** Length of the buffer this entry describes. */
    unsigned length:24;
    /** Flag whether this element is the end of the list. */
    unsigned end_of_list:1;
    /** Flag whether the address is 32bit or 64bits wide. */
    unsigned bit_address:1;
    /** Flag whether this buffer contains data to be transferred
        or is the destination. */
    unsigned buffer_contains_data:1;
    /** Flag whether this is a local address or a system address. */
    unsigned local_address:1;
    /** Element type. */
    unsigned element_type:2;
    /** Flag whether this is the last element of the buffer. */
    unsigned end_of_buffer:1;
    /** Flag whether this is the last element of the current segment. */
    unsigned last_element:1;
    /** Lower 32bits of the address of the data buffer. */
    uint32_t data_buf_addr_low;
} MptSGEntrySimple32, *PMptSGEntrySimple32;

/**
 * A chain SG element.
 */
typedef struct QEMU_PACKED MptSGEntryChain {
    /** Size of the segment. */
    uint16_t length;
    /** Offset in 32bit words of the next chain element in the segment
     *  identified by this element. */
    uint8_t next_chain_offset;
    /** Reserved. */
    unsigned reserved0:1;
    /** Flag whether the address is 32bit or 64bits wide. */
    unsigned bit_address:1;
    /** Reserved. */
    unsigned reserved1:1;
    /** Flag whether this is a local address or a system address. */
    unsigned local_address:1;
    /** Element type. */
    unsigned element_type:2;
    /** Flag whether this is the last element of the buffer. */
    unsigned reserved2:2;
    /** Lower 32bits of the address of the data buffer. */
    uint32_t segment_address_low;
    /** Upper 32bits of the address of the data buffer. */
    uint32_t segment_address_high;
} MptSGEntryChain, *PMptSGEntryChain;

typedef union MptSGEntryUnion {
    MptSGEntrySimple64 simple_64;
    MptSGEntrySimple32 simple_32;
    MptSGEntryChain    chain;
} MptSGEntryUnion, *PMptSGEntryUnion;

/**
 * MPT Fusion message header - Common for all message frames.
 * This is filled in by the guest.
 */
typedef struct QEMU_PACKED MptMessageHdr {
    /** Function dependent data. */
    uint16_t    function_dependent;
    /** Chain offset. */
    uint8_t     chain_offset;
    /** The function code. */
    uint8_t     function;
    /** Function dependent data. */
    uint8_t     function_dependent_data[3];
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context - Unique ID from the guest unmodified by the device. */
    uint32_t    message_context;
} MptMessageHdr, *PMptMessageHdr;

/** Defined function codes found in the message header. */
#define MPT_MESSAGE_HDR_FUNCTION_SCSI_IO_REQUEST        (0x00)
#define MPT_MESSAGE_HDR_FUNCTION_SCSI_TASK_MGMT         (0x01)
#define MPT_MESSAGE_HDR_FUNCTION_IOC_INIT               (0x02)
#define MPT_MESSAGE_HDR_FUNCTION_IOC_FACTS              (0x03)
#define MPT_MESSAGE_HDR_FUNCTION_CONFIG                 (0x04)
#define MPT_MESSAGE_HDR_FUNCTION_PORT_FACTS             (0x05)
#define MPT_MESSAGE_HDR_FUNCTION_PORT_ENABLE            (0x06)
#define MPT_MESSAGE_HDR_FUNCTION_EVENT_NOTIFICATION     (0x07)
#define MPT_MESSAGE_HDR_FUNCTION_EVENT_ACK              (0x08)
#define MPT_MESSAGE_HDR_FUNCTION_FW_DOWNLOAD            (0x09)
#define MPT_MESSAGE_HDR_FUNCTION_TARGET_CMD_BUFFER_POST (0x0A)
#define MPT_MESSAGE_HDR_FUNCTION_TARGET_ASSIST          (0x0B)
#define MPT_MESSAGE_HDR_FUNCTION_TARGET_STATUS_SEND     (0x0C)
#define MPT_MESSAGE_HDR_FUNCTION_TARGET_MODE_ABORT      (0x0D)
#define MPT_MESSAGE_HDR_FUNCTION_FW_UPLOAD              (0x12)

/**
 * Default reply message.
 * Send from the device to the guest upon completion of a request.
 */
typedef struct QEMU_PACKED MptDefaultReplyMessage {
    /** Function dependent data. */
    uint16_t    function_dependent;
    /** Length of the message in 32bit DWords. */
    uint8_t     message_length;
    /** Function which completed. */
    uint8_t     function;
    /** Function dependent. */
    uint8_t     function_dependent_data[3];
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context given in the request. */
    uint32_t    message_context;
    /** Function dependent status code. */
    uint16_t    function_dependentStatus;
    /** Status of the IOC. */
    uint16_t    ioc_status;
    /** Additional log info. */
    uint32_t    ioc_log_info;
} MptDefaultReplyMessage, *PMptDefaultReplyMessage;

/**
 * IO controller init request.
 */
typedef struct QEMU_PACKED MptIOCInitRequest {
    /** Which system send this init request. */
    uint8_t     who_init;
    /** Reserved */
    uint8_t     reserved;
    /** Chain offset in the SG list. */
    uint8_t     chain_offset;
    /** Function to execute. */
    uint8_t     function;
    /** Flags */
    uint8_t     flags;
    /** Maximum number of devices the driver can handle. */
    uint8_t     max_devices;
    /** Maximum number of buses the driver can handle. */
    uint8_t     max_buses;
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
    /** Reply frame size. */
    uint16_t    reply_frame_size;
    /** Reserved */
    uint16_t    reserved1;
    /** Upper 32bit part of the 64bit address the message frames are in.
     *  That means all frames must be in the same 4GB segment. */
    uint32_t    host_mfa_high_addr;
    /** Upper 32bit of the sense buffer. */
    uint32_t    sense_buffer_high_addr;
} MptIOCInitRequest, *PMptIOCInitRequest;

/**
 * IO controller init reply.
 */
typedef struct QEMU_PACKED MptIOCInitReply {
    /** Which subsystem send this init request. */
    uint8_t     who_init;
    /** Reserved */
    uint8_t     reserved;
    /** Message length */
    uint8_t     message_length;
    /** Function. */
    uint8_t     function;
    /** Flags */
    uint8_t     flags;
    /** Maximum number of devices the driver can handle. */
    uint8_t     max_devices;
    /** Maximum number of busses the driver can handle. */
    uint8_t     max_buses;
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID */
    uint32_t    message_context;
    /** Reserved */
    uint16_t    reserved1;
    /** IO controller status. */
    uint16_t    ioc_status;
    /** IO controller log information. */
    uint32_t    ioc_log_info;
} MptIOCInitReply, *PMptIOCInitReply;

/**
 * IO controller facts request.
 */
typedef struct QEMU_PACKED MptIOCFactsRequest {
    /** Reserved. */
    uint16_t    reserved;
    /** Chain offset in SG list. */
    uint8_t     chain_offset;
    /** Function number. */
    uint8_t     function;
    /** Reserved */
    uint8_t     reserved1[3];
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
} MptIOCFactsRequest, *PMptIOCFactsRequest;

/**
 * IO controller facts reply.
 */
typedef struct QEMU_PACKED MptIOCFactsReply {
    /** Message version. */
    uint16_t    message_version;
    /** Message length. */
    uint8_t     message_length;
    /** Function number. */
    uint8_t     function;
    /** Reserved */
    uint16_t    reserved1;
    /** IO controller number */
    uint8_t     ioc_number;
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
    /** IO controller exceptions */
    uint16_t    ioc_exceptions;
    /** IO controller status. */
    uint16_t    ioc_status;
    /** IO controller log information. */
    uint32_t    ioc_log_info;
    /** Maximum chain depth. */
    uint8_t     max_chain_depth;
    /** The current value of the WhoInit field. */
    uint8_t     who_init;
    /** Block size. */
    uint8_t     block_size;
    /** Flags. */
    uint8_t     flags;
    /** Depth of the reply queue. */
    uint16_t    reply_queue_depth;
    /** Size of a request frame. */
    uint16_t    request_frame_size;
    /** Reserved */
    uint16_t    reserved2;
    /** Product ID. */
    uint16_t    product_id;
    /** Current value of the high 32bit MFA address. */
    uint32_t    current_host_mfa_high_addr;
    /** Global credits - Number of entries allocated to queues */
    uint16_t    global_credits;
    /** Number of ports on the IO controller */
    uint8_t     number_of_ports;
    /** Event state. */
    uint8_t     event_state;
    /** Current value of the high 32bit sense buffer address. */
    uint32_t    current_sense_buffer_high_addr;
    /** Current reply frame size. */
    uint16_t    cur_reply_frame_size;
    /** Maximum number of devices. */
    uint8_t     max_devices;
    /** Maximum number of buses. */
    uint8_t     max_buses;
    /** Size of the firmware image. */
    uint32_t    fw_image_size;
    /** Reserved. */
    uint32_t    reserved;
    /** Firmware version */
    uint32_t    fw_version;
} MptIOCFactsReply, *PMptIOCFactsReply;

/**
 * Port facts request
 */
typedef struct QEMU_PACKED MptPortFactsRequest {
    /** Reserved */
    uint16_t    reserved1;
    /** Message length. */
    uint8_t     message_length;
    /** Function number. */
    uint8_t     function;
    /** Reserved */
    uint16_t    reserved2;
    /** Port number to get facts for. */
    uint8_t     port_number;
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
} MptPortFactsRequest, *PMptPortFactsRequest;

/**
 * Port facts reply.
 */
typedef struct QEMU_PACKED MptPortFactsReply {
    /** Reserved. */
    uint16_t    reserved1;
    /** Message length. */
    uint8_t     message_length;
    /** Function number. */
    uint8_t     function;
    /** Reserved */
    uint16_t    reserved2;
    /** Port number the facts are for. */
    uint8_t     port_number;
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
    /** Reserved. */
    uint16_t    reserved3;
    /** IO controller status. */
    uint16_t    ioc_status;
    /** IO controller log information. */
    uint32_t    ioc_log_info;
    /** Reserved */
    uint8_t     reserved;
    /** Port type */
    uint8_t     port_type;
    /** Maximum number of devices on this port. */
    uint16_t    max_devices;
    /** SCSI ID of this port on the attached bus. */
    uint16_t    port_scsi_id;
    /** Protocol flags. */
    uint16_t    protocol_flags;
    /** Maximum number of target command buffers which can be
        posted to this port at a time. */
    uint16_t    max_posted_cmd_buffers;
    /** Maximum number of target IDs that remain persistent
        between power/reset cycles. */
    uint16_t    max_persistent_ids;
    /** Maximum number of LAN buckets. */
    uint16_t    max_lan_buckets;
    /** Reserved. */
    uint16_t    reserved4;
    /** Reserved. */
    uint32_t    reserved5;
} MptPortFactsReply, *PMptPortFactsReply;

/**
 * Port Enable request.
 */
typedef struct QEMU_PACKED MptPortEnableRequest {
    /** Reserved. */
    uint16_t    reserved1;
    /** Message length. */
    uint8_t     message_length;
    /** Function number. */
    uint8_t     function;
    /** Reserved. */
    uint16_t    reserved2;
    /** Port number to enable. */
    uint8_t     port_number;
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
} MptPortEnableRequest, *PMptPortEnableRequest;

/**
 * Port enable reply.
 */
typedef struct QEMU_PACKED MptPortEnableReply {
    /** Reserved. */
    uint16_t    reserved1;
    /** Message length. */
    uint8_t     message_length;
    /** Function number. */
    uint8_t     function;
    /** Reserved */
    uint16_t    reserved2;
    /** Port number which was enabled. */
    uint8_t     port_number;
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
    /** Reserved. */
    uint16_t    reserved3;
    /** IO controller status */
    uint16_t    ioc_status;
    /** IO controller log information. */
    uint32_t    ioc_log_info;
} MptPortEnableReply, *PMptPortEnableReply;

/**
 * Event notification request.
 */
typedef struct QEMU_PACKED MptEventNotificationRequest {
    /** Switch - Turns event notification on and off. */
    uint8_t     event_switch;
    /** Reserved. */
    uint8_t     reserved1;
    /** Chain offset. */
    uint8_t     chain_offset;
    /** Function number. */
    uint8_t     function;
    /** Reserved. */
    uint8_t     reserved2[3];
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
} MptEventNotificationRequest, *PMptEventNotificationRequest;

/**
 * Event notification reply.
 */
typedef struct QEMU_PACKED MptEventNotificationReply {
    /** Event data length. */
    uint16_t    event_data_length;
    /** Message length. */
    uint8_t     message_length;
    /** Function number. */
    uint8_t     function;
    /** Reserved. */
    uint16_t    reserved1;
    /** Ack required. */
    uint8_t     ack_required;
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
    /** Reserved. */
    uint16_t    reserved2;
    /** IO controller status. */
    uint16_t    ioc_status;
    /** IO controller log information. */
    uint32_t    ioc_log_info;
    /** Notification event. */
    uint32_t    event;
    /** Event context. */
    uint32_t    event_context;
    /** Event data. */
    uint32_t    event_data;
} MptEventNotificationReply, *PMptEventNotificationReply;

#define MPT_EVENT_EVENT_CHANGE (0x0000000a)

/**
 * FW download request.
 */
typedef struct QEMU_PACKED MptFWDownloadRequest {
    /** Switch - Turns event notification on and off. */
    uint8_t     image_type;
    /** Reserved. */
    uint8_t     reserved1;
    /** Chain offset. */
    uint8_t     chain_offset;
    /** Function number. */
    uint8_t     function;
    /** Reserved. */
    uint8_t     reserved2[3];
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
} MptFWDownloadRequest, *PMptFWDownloadRequest;

#define MPT_FW_DOWNLOAD_REQUEST_IMAGE_TYPE_RESERVED 0
#define MPT_FW_DOWNLOAD_REQUEST_IMAGE_TYPE_FIRMWARE 1
#define MPT_FW_DOWNLOAD_REQUEST_IMAGE_TYPE_MPI_BIOS 2
#define MPT_FW_DOWNLOAD_REQUEST_IMAGE_TYPE_NVDATA   3

/**
 * FW download reply.
 */
typedef struct QEMU_PACKED MptFWDownloadReply {
    /** Reserved. */
    uint16_t    reserved1;
    /** Message length. */
    uint8_t     message_length;
    /** Function number. */
    uint8_t     function;
    /** Reserved. */
    uint8_t     reserved2[3];
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
    /** Reserved. */
    uint16_t    reserved3;
    /** IO controller status. */
    uint16_t    ioc_status;
    /** IO controller log information. */
    uint32_t    ioc_log_info;
} MptFWDownloadReply, *PMptFWDownloadReply;

typedef struct QEMU_PACKED MptFwHeader {
    uint32_t    arm_branch_instruction_0;   /* 00h */
    uint32_t    signature_0;                /* 04h */
    uint32_t    signature_1;                /* 08h */
    uint32_t    signature_2;                /* 0Ch */
    uint32_t    arm_branch_instruction_1;   /* 10h */
    uint32_t    arm_branch_instruction_2;   /* 14h */
    uint32_t    reserved;                   /* 18h */
    uint32_t    checksum;                   /* 1Ch */
    uint16_t    vendor_id;                  /* 20h */
    uint16_t    product_id;                 /* 22h */
    uint32_t    fw_version;                 /* 24h */
    uint32_t    seq_code_version;           /* 28h */
    uint32_t    image_size;                 /* 2Ch */
    uint32_t    next_image_header_offset;   /* 30h */
    uint32_t    load_start_address;         /* 34h */
    uint32_t    iop_reset_vector_value;     /* 38h */
    uint32_t    iop_reset_reg_addr;         /* 3Ch */
    uint32_t    version_name_what;          /* 40h */
    uint8_t     version_name[32];           /* 44h */
    uint32_t    vendor_name_what;           /* 64h */
    uint8_t     vendor_name[32];            /* 68h */
} MptFwHeader_t, *pMptFwHeader_t;

typedef struct QEMU_PACKED MptFWUploadTCSGE {
    uint8_t      reserved;                  /* 00h */
    uint8_t      context_size;              /* 01h */
    uint8_t      details_length;            /* 02h */
    uint8_t      flags;                     /* 03h */
    uint32_t     reserved1;                 /* 04h */
    uint32_t     image_offset;              /* 08h */
    uint32_t     image_size;                /* 0Ch */
} MptFWUploadTCSGE_t, *pMptFWUploadTCSGE_t;

#define MPI_FW_UPLOAD_ITYPE_FW_IOC_MEM          (0x00)
#define MPI_FW_UPLOAD_ITYPE_FW_FLASH            (0x01)
#define MPI_FW_UPLOAD_ITYPE_BIOS_FLASH          (0x02)
#define MPI_FW_UPLOAD_ITYPE_NVDATA              (0x03)
#define MPI_FW_UPLOAD_ITYPE_BOOTLOADER          (0x04)
#define MPI_FW_UPLOAD_ITYPE_FW_BACKUP           (0x05)
#define MPI_FW_UPLOAD_ITYPE_MANUFACTURING       (0x06)
#define MPI_FW_UPLOAD_ITYPE_CONFIG_1            (0x07)
#define MPI_FW_UPLOAD_ITYPE_CONFIG_2            (0x08)
#define MPI_FW_UPLOAD_ITYPE_MEGARAID            (0x09)
#define MPI_FW_UPLOAD_ITYPE_COMPLETE            (0x0A)
#define MPI_FW_UPLOAD_ITYPE_COMMON_BOOT_BLOCK   (0x0B)

/**
 * FW upload request.
 */
typedef struct QEMU_PACKED MptFWUploadRequest {
    /** Requested image type. */
    uint8_t     image_type;
    /** Reserved. */
    uint8_t     reserved1;
    /** Chain offset. */
    uint8_t     chain_offset;
    /** Function number. */
    uint8_t     function;
    /** Reserved. */
    uint8_t     reserved2[3];
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
    MptFWUploadTCSGE_t tc_sge;
    MptSGEntrySimple32 sge;
} MptFWUploadRequest, *PMptFWUploadRequest;

/**
 * FW upload reply.
 */
typedef struct QEMU_PACKED MptFWUploadReply {
    /** Image type. */
    uint8_t     image_type;
    /** Reserved. */
    uint8_t     reserved1;
    /** Message length. */
    uint8_t     message_length;
    /** Function number. */
    uint8_t     function;
    /** Reserved. */
    uint8_t     reserved2[3];
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
    /** Reserved. */
    uint16_t    reserved3;
    /** IO controller status. */
    uint16_t    ioc_status;
    /** IO controller log information. */
    uint32_t    ioc_log_info;
    /** Uploaded image size. */
    uint32_t    actual_image_size;
} MptFWUploadReply, *PMptFWUploadReply;

/**
 * SCSI IO Request
 */
typedef struct QEMU_PACKED MptSCSIIORequest {
    /** Target ID */
    uint8_t     target_id;
    /** Bus number */
    uint8_t     bus;
    /** Chain offset */
    uint8_t     chain_offset;
    /** Function number. */
    uint8_t     function;
    /** CDB length. */
    uint8_t     cdb_length;
    /** Sense buffer length. */
    uint8_t     sense_buffer_length;
    /** Reserved */
    uint8_t     reserved;
    /** Message flags. */
    uint8_t     message_flags;
    /** Message context ID. */
    uint32_t    message_context;
    /** LUN */
    uint8_t     lun[8];
    /** Control values. */
    uint32_t    control;
    /** The CDB. */
    uint8_t     cdb[16];
    /** Data length. */
    uint32_t    data_length;
    /** Sense buffer low 32bit address. */
    uint32_t    sense_buffer_low_address;
} MptSCSIIORequest, *PMptSCSIIORequest;

#define MPT_SCSIIO_REQUEST_CONTROL_TXDIR_GET(x) (((x) & 0x3000000) >> 24)
#define MPT_SCSIIO_REQUEST_CONTROL_TXDIR_NONE  (0x0)
#define MPT_SCSIIO_REQUEST_CONTROL_TXDIR_WRITE (0x1)
#define MPT_SCSIIO_REQUEST_CONTROL_TXDIR_READ  (0x2)

/**
 * SCSI IO error reply.
 */
typedef struct QEMU_PACKED MptSCSIIOErrorReply {
    /** Target ID */
    uint8_t     target_id;
    /** Bus number */
    uint8_t     bus;
    /** Message length. */
    uint8_t     message_length;
    /** Function number. */
    uint8_t     function;
    /** CDB length */
    uint8_t     cdb_length;
    /** Sense buffer length */
    uint8_t     sense_buffer_length;
    /** Reserved */
    uint8_t     reserved;
    /** Message flags */
    uint8_t     message_flags;
    /** Message context ID */
    uint32_t    message_context;
    /** SCSI status. */
    uint8_t     scsi_status;
    /** SCSI state */
    uint8_t     scsi_state;
    /** IO controller status */
    uint16_t    ioc_status;
    /** IO controller log information */
    uint32_t    ioc_log_info;
    /** Transfer count */
    uint32_t    transfer_count;
    /** Sense count */
    uint32_t    sense_count;
    /** Response information */
    uint32_t    response_info;
} MptSCSIIOErrorReply, *PMptSCSIIOErrorReply;

#define MPT_SCSI_IO_ERROR_SCSI_STATE_AUTOSENSE_VALID (0x01)
#define MPT_SCSI_IO_ERROR_SCSI_STATE_TERMINATED      (0x08)

/**
 * IOC status codes specific to the SCSI I/O error reply.
 */
#define MPT_SCSI_IO_ERROR_IOCSTATUS_INVALID_BUS      (0x0041)
#define MPT_SCSI_IO_ERROR_IOCSTATUS_INVALID_TARGETID (0x0042)
#define MPT_SCSI_IO_ERROR_IOCSTATUS_DEVICE_NOT_THERE (0x0043)

/**
 * SCSI task management request.
 */
typedef struct QEMU_PACKED MptSCSITaskManagementRequest {
    /** Target ID */
    uint8_t     target_id;
    /** Bus number */
    uint8_t     bus;
    /** Chain offset */
    uint8_t     chain_offset;
    /** Function number */
    uint8_t     function;
    /** Reserved */
    uint8_t     reserved1;
    /** Task type */
    uint8_t     task_type;
    /** Reserved */
    uint8_t     reserved2;
    /** Message flags */
    uint8_t     message_flags;
    /** Message context ID */
    uint32_t    message_context;
    /** LUN */
    uint8_t     lun[8];
    /** Reserved */
    uint8_t     aureserved[28];
    /** Task message context ID. */
    uint32_t    task_message_context;
} MptSCSITaskManagementRequest, *PMptSCSITaskManagementRequest;

/**
 * SCSI task management reply.
 */
typedef struct QEMU_PACKED MptSCSITaskManagementReply {
    /** Target ID */
    uint8_t     target_id;
    /** Bus number */
    uint8_t     bus;
    /** Message length */
    uint8_t     message_length;
    /** Function number */
    uint8_t     function;
    /** Reserved */
    uint8_t     reserved1;
    /** Task type */
    uint8_t     task_type;
    /** Reserved */
    uint8_t     reserved2;
    /** Message flags */
    uint8_t     message_flags;
    /** Message context ID */
    uint32_t    message_context;
    /** Reserved */
    uint16_t    reserved;
    /** IO controller status */
    uint16_t    ioc_status;
    /** IO controller log information */
    uint32_t    ioc_log_info;
    /** Termination count */
    uint32_t    termination_count;
} MptSCSITaskManagementReply, *PMptSCSITaskManagementReply;

/**
 * Page address for SAS expander page types.
 */
typedef union QEMU_PACKED MptConfigurationPageAddressSASExpander {
    struct {
        uint16_t    handle;
        uint16_t    reserved;
    } form0_and2;
    struct {
        uint16_t    handle;
        uint8_t     phy_num;
        uint8_t     reserved;
    } form1;
} MptConfigurationPageAddressSASExpander,
    *PMptConfigurationPageAddressSASExpander;

/**
 * Page address for SAS device page types.
 */
typedef union QEMU_PACKED MptConfigurationPageAddressSASDevice {
    struct {
        uint16_t    handle;
        uint16_t    reserved;
    } form0_and2;
    struct {
        uint8_t     target_id;
        uint8_t     bus;
        uint8_t     reserved;
    } form1;
} MptConfigurationPageAddressSASDevice, *PMptConfigurationPageAddressSASDevice;

/**
 * Page address for SAS PHY page types.
 */
typedef union QEMU_PACKED MptConfigurationPageAddressSASPHY {
    struct {
        uint8_t     phy_number;
        uint8_t     reserved[3];
    } Form0;
    struct {
        uint16_t    index;
        uint16_t    reserved;
    } form1;
} MptConfigurationPageAddressSASPHY, *PMptConfigurationPageAddressSASPHY;

/**
 * Page address for SAS Enclosure page types.
 */
typedef struct QEMU_PACKED MptConfigurationPageAddressSASEnclosure {
    uint16_t    handle;
    uint16_t    reserved;
} MptConfigurationPageAddressSASEnclosure,
    *PMptConfigurationPageAddressSASEnclosure;

/**
 * Union of all possible address types.
 */
typedef union QEMU_PACKED MptConfigurationPageAddress {
    /** 32bit view. */
    uint32_t page_address;
    struct {
        /** Port number to get the configuration page for. */
        uint8_t port_number;
        /** Reserved. */
        uint8_t reserved[3];
    } mpi_port_number;
    struct {
        /** Target ID to get the configuration page for. */
        uint8_t target_id;
        /** Bus number to get the configuration page for. */
        uint8_t bus;
        /** Reserved. */
        uint8_t reserved[2];
    } bus_and_target_id;
    MptConfigurationPageAddressSASExpander  sas_expander;
    MptConfigurationPageAddressSASDevice    sas_device;
    MptConfigurationPageAddressSASPHY       sas_phy;
    MptConfigurationPageAddressSASEnclosure sas_enclosure;
} MptConfigurationPageAddress, *PMptConfigurationPageAddress;

#define MPT_CONFIGURATION_PAGE_ADDRESS_GET_SAS_FORM(x)  \
    (((x).page_address >> 28) & 0x0f)

/**
 * Configuration request
 */
typedef struct QEMU_PACKED MptConfigurationRequest {
    /** Action code. */
    uint8_t    action;
    /** Reserved. */
    uint8_t    reserved1;
    /** Chain offset. */
    uint8_t    chain_offset;
    /** Function number. */
    uint8_t    function;
    /** Extended page length. */
    uint16_t   ext_page_len;
    /** Extended page type */
    uint8_t    ext_page_type;
    /** Message flags. */
    uint8_t    message_flags;
    /** Message context ID. */
    uint32_t   message_context;
    /** Reserved. */
    uint8_t    reserved2[8];
    /** Version number of the page. */
    uint8_t    page_version;
    /** Length of the page in 32bit Dwords. */
    uint8_t    page_length;
    /** Page number to access. */
    uint8_t    page_number;
    /** Type of the page being accessed. */
    uint8_t    page_type;
    /** Page type dependent address. */
    MptConfigurationPageAddress page_address;
    /** Simple SG element describing the buffer. */
    MptSGEntrySimple64          simple_sge;
    uint32_t    reserved[4];
} MptConfigurationRequest, *PMptConfigurationRequest;

/** Possible action codes. */
#define MPT_CONFIGURATION_REQUEST_ACTION_HEADER        (0x00)
#define MPT_CONFIGURATION_REQUEST_ACTION_READ_CURRENT  (0x01)
#define MPT_CONFIGURATION_REQUEST_ACTION_WRITE_CURRENT (0x02)
#define MPT_CONFIGURATION_REQUEST_ACTION_DEFAULT       (0x03)
#define MPT_CONFIGURATION_REQUEST_ACTION_WRITE_NVRAM   (0x04)
#define MPT_CONFIGURATION_REQUEST_ACTION_READ_DEFAULT  (0x05)
#define MPT_CONFIGURATION_REQUEST_ACTION_READ_NVRAM    (0x06)

/** Page type codes. */
#define MPT_CONFIGURATION_REQUEST_PAGE_TYPE_IO_UNIT    (0x00)
#define MPT_CONFIGURATION_REQUEST_PAGE_TYPE_IOC        (0x01)
#define MPT_CONFIGURATION_REQUEST_PAGE_TYPE_BIOS       (0x02)
#define MPT_CONFIGURATION_REQUEST_PAGE_TYPE_SCSI_PORT  (0x03)
#define MPT_CONFIGURATION_REQUEST_PAGE_TYPE_EXTENDED   (0x0F)

/**
 * Configuration reply.
 */
typedef struct QEMU_PACKED MptConfigurationReply {
    /** Action code. */
    uint8_t    action;
    /** Reserved. */
    uint8_t    reserved;
    /** Message length. */
    uint8_t    message_length;
    /** Function number. */
    uint8_t    function;
    /** Extended page length. */
    uint16_t   ext_page_len;
    /** Extended page type */
    uint8_t    ext_page_type;
    /** Message flags. */
    uint8_t    message_flags;
    /** Message context ID. */
    uint32_t   message_context;
    /** Reserved. */
    uint16_t   reserved1;
    /** I/O controller status. */
    uint16_t   ioc_status;
    /** I/O controller log information. */
    uint32_t   ioc_log_info;
    /** Version number of the page. */
    uint8_t    page_version;
    /** Length of the page in 32bit Dwords. */
    uint8_t    page_length;
    /** Page number to access. */
    uint8_t    page_number;
    /** Type of the page being accessed. */
    uint8_t    page_type;
} MptConfigurationReply, *PMptConfigurationReply;

/** Additional I/O controller status codes for the configuration reply. */
#define MPT_IOCSTATUS_CONFIG_INVALID_ACTION (0x0020)
#define MPT_IOCSTATUS_CONFIG_INVALID_TYPE   (0x0021)
#define MPT_IOCSTATUS_CONFIG_INVALID_PAGE   (0x0022)
#define MPT_IOCSTATUS_CONFIG_INVALID_DATA   (0x0023)
#define MPT_IOCSTATUS_CONFIG_NO_DEFAULTS    (0x0024)
#define MPT_IOCSTATUS_CONFIG_CANT_COMMIT    (0x0025)

/**
 * Union of all possible request messages.
 */
typedef union MptRequestUnion {
    MptMessageHdr                header;
    MptIOCInitRequest            ioc_init;
    MptIOCFactsRequest           ioc_facts;
    MptPortFactsRequest          port_facts;
    MptPortEnableRequest         port_enable;
    MptEventNotificationRequest  event_notification;
    MptSCSIIORequest             scsi_io;
    MptSCSITaskManagementRequest scsi_task_management;
    MptConfigurationRequest      configuration;
    MptFWDownloadRequest         fw_download;
    MptFWUploadRequest           fw_upload;
} MptRequestUnion, *PMptRequestUnion;

/**
 * Union of all possible reply messages.
 */
typedef union MptReplyUnion {
    /** 16bit view. */
    uint16_t                   areply[30];
    MptDefaultReplyMessage     header;
    MptIOCInitReply            ioc_init;
    MptIOCFactsReply           ioc_facts;
    MptPortFactsReply          port_facts;
    MptPortEnableReply         port_enable;
    MptEventNotificationReply  event_notification;
    MptSCSIIOErrorReply        scsi_io_error;
    MptSCSITaskManagementReply scsi_task_management;
    MptConfigurationReply      configuration;
    MptFWDownloadReply         fw_download;
    MptFWUploadReply           fw_upload;
} MptReplyUnion, *PMptReplyUnion;


/**
 * Configuration Page attributes.
 */
#define MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY            (0x00)
#define MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE          (0x10)
#define MPT_CONFIGURATION_PAGE_ATTRIBUTE_PERSISTENT          (0x20)
#define MPT_CONFIGURATION_PAGE_ATTRIBUTE_PERSISTENT_READONLY (0x30)

#define MPT_CONFIGURATION_PAGE_ATTRIBUTE_GET(page_type) ((page_type) & 0xf0)

/**
 * Configuration Page types.
 */
#define MPT_CONFIGURATION_PAGE_TYPE_IO_UNIT                  (0x00)
#define MPT_CONFIGURATION_PAGE_TYPE_IOC                      (0x01)
#define MPT_CONFIGURATION_PAGE_TYPE_BIOS                     (0x02)
#define MPT_CONFIGURATION_PAGE_TYPE_SCSI_SPI_PORT            (0x03)
#define MPT_CONFIGURATION_PAGE_TYPE_SCSI_SPI_DEVICE          (0x04)
#define MPT_CONFIGURATION_PAGE_TYPE_MANUFACTURING            (0x09)
#define MPT_CONFIGURATION_PAGE_TYPE_EXTENDED                 (0x0F)

#define MPT_CONFIGURATION_PAGE_TYPE_GET(page_type) ((page_type) & 0x0f)

/**
 * Extented page types.
 */
#define MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASIOUNIT       (0x10)
#define MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASEXPANDER     (0x11)
#define MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASDEVICE       (0x12)
#define MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASPHYS         (0x13)
#define MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_LOG             (0x14)
#define MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_ENCLOSURE       (0x15)

/**
 * Configuration Page header - Common to all pages.
 */
typedef struct QEMU_PACKED MptConfigurationPageHeader {
    /** Version of the page. */
    uint8_t     page_version;
    /** The length of the page in 32bit D-Words. */
    uint8_t     page_length;
    /** Number of the page. */
    uint8_t     page_number;
    /** Type of the page. */
    uint8_t     page_type;
} MptConfigurationPageHeader, *PMptConfigurationPageHeader;

/**
 * Extended configuration page header - Common to all extended pages.
 */
typedef struct QEMU_PACKED MptExtendedConfigurationPageHeader {
    /** Version of the page. */
    uint8_t     page_version;
    /** Reserved. */
    uint8_t     reserved1;
    /** Number of the page. */
    uint8_t     page_number;
    /** Type of the page. */
    uint8_t     page_type;
    /** Extended page length. */
    uint16_t    ext_page_len;
    /** Extended page type. */
    uint8_t     ext_page_type;
    /** Reserved */
    uint8_t     reserved2;
} MptExtendedConfigurationPageHeader, *PMptExtendedConfigurationPageHeader;

/**
 * Manufacturing page 0. - Readonly.
 */
typedef struct QEMU_PACKED MptConfigurationPageManufacturing0 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[76];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Name of the chip. */
            uint8_t               chip_name[16];
            /** Chip revision. */
            uint8_t               chip_revision[8];
            /** Board name. */
            uint8_t               board_name[16];
            /** Board assembly. */
            uint8_t               board_assembly[16];
            /** Board tracer number. */
            uint8_t               board_tracer_number[16];
        } fields;
    } u;
} MptConfigurationPageManufacturing0, *PMptConfigurationPageManufacturing0;

/**
 * Manufacturing page 1. - Readonly Persistent.
 */
typedef struct QEMU_PACKED MptConfigurationPageManufacturing1 {
    /** Union */
    union {
        /** Byte view */
        uint8_t                           page_data[260];
        /** Field view */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** VPD info - don't know what belongs here so all zero. */
            uint8_t                       vpd_info[256];
        } fields;
    } u;
} MptConfigurationPageManufacturing1, *PMptConfigurationPageManufacturing1;

/**
 * Manufacturing page 2. - Readonly.
 */
typedef struct QEMU_PACKED MptConfigurationPageManufacturing2 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                        page_data[8];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader header;
            /** PCI Device ID. */
            uint16_t                   pci_device_id;
            /** PCI Revision ID. */
            uint8_t                    pci_revision_id;
            /** Reserved. */
            uint8_t                    reserved;
            /** Hardware specific settings... */
        } fields;
    } u;
} MptConfigurationPageManufacturing2, *PMptConfigurationPageManufacturing2;

/**
 * Manufacturing page 3. - Readonly.
 */
typedef struct QEMU_PACKED MptConfigurationPageManufacturing3 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[8];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** PCI Device ID. */
            uint16_t              pci_device_id;
            /** PCI Revision ID. */
            uint8_t               pci_revision_id;
            /** Reserved. */
            uint8_t               reserved;
            /** Chip specific settings... */
        } fields;
    } u;
} MptConfigurationPageManufacturing3, *PMptConfigurationPageManufacturing3;

/**
 * Manufacturing page 4. - Readonly.
 */
typedef struct QEMU_PACKED MptConfigurationPageManufacturing4 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[84];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Reserved. */
            uint32_t              reserved;
            /** InfoOffset0. */
            uint8_t               info_offset_0;
            /** Info size. */
            uint8_t               info_size_0;
            /** InfoOffset1. */
            uint8_t               info_offset_1;
            /** Info size. */
            uint8_t               info_size_1;
            /** Size of the inquiry data. */
            uint8_t               inquiry_size;
            /** Reserved. */
            uint8_t               reserved1[3];
            /** Inquiry data. */
            uint8_t               inquiry_data[56];
            /** IS volume settings. */
            uint32_t              is_volume_settings;
            /** IME volume settings. */
            uint32_t              ime_volume_settings;
            /** IM volume settings. */
            uint32_t              im_volume_settings;
        } fields;
    } u;
} MptConfigurationPageManufacturing4, *PMptConfigurationPageManufacturing4;

/**
 * Manufacturing page 5 - Readonly.
 */
typedef struct QEMU_PACKED MptConfigurationPageManufacturing5 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                           page_data[88];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Base WWID. */
            uint64_t                      base_wwid;
            /** Flags */
            uint8_t                       flags;
            /** Number of ForceWWID fields in this page. */
            uint8_t                       num_force_wwid;
            /** Reserved */
            uint16_t                      reserved;
            /** Reserved */
            uint32_t                      reserved1[2];
            /** ForceWWID entries  Maximum of 8 because the SAS
                controller doesn't has more */
            uint64_t                      force_wwid[8];
        } fields;
    } u;
} MptConfigurationPageManufacturing5, *PMptConfigurationPageManufacturing5;

/**
 * Manufacturing page 6 - Readonly.
 */
typedef struct QEMU_PACKED MptConfigurationPageManufacturing6 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                           page_data[4];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Product specific data - 0 for now */
        } fields;
    } u;
} MptConfigurationPageManufacturing6, *PMptConfigurationPageManufacturing6;

/**
 * Manufacutring page 7 - PHY element.
 */
typedef struct QEMU_PACKED MptConfigurationPageManufacturing7PHY {
    /** Pinout */
    uint32_t                  pinout;
    /** Connector name */
    uint8_t                   sz_connector[16];
    /** Location */
    uint8_t                   location;
    /** Reserved */
    uint8_t                   reserved;
    /** Slot */
    uint16_t                  slot;
} MptConfigurationPageManufacturing7PHY,
    *PMptConfigurationPageManufacturing7PHY;

/**
 * Manufacturing page 7 - Readonly.
 */
typedef struct QEMU_PACKED MptConfigurationPageManufacturing7 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                           page_data[1];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Reserved */
            uint32_t                      reserved[2];
            /** Flags */
            uint32_t                      flags;
            /** Enclosure name */
            uint8_t                       sz_enclosure_name[16];
            /** Number of PHYs */
            uint8_t                       num_phys;
            /** Reserved */
            uint8_t                       reserved1[3];
            /** PHY list for the SAS controller -
                variable depending on the number of ports */
            MptConfigurationPageManufacturing7PHY phy[1];
        } fields;
    } u;
} MptConfigurationPageManufacturing7, *PMptConfigurationPageManufacturing7;

#define MPTSCSI_MANUFACTURING7_GET_SIZE(ports)                          \
    (sizeof(MptConfigurationPageManufacturing7) + ((ports) - 1) *       \
     sizeof(MptConfigurationPageManufacturing7PHY))

/** Flags for the flags field */
#define MPTSCSI_MANUFACTURING7_FLAGS_USE_PROVIDED_INFORMATION (1<<0)

/** Flags for the pinout field */
#define MPTSCSI_MANUFACTURING7_PINOUT_UNKNOWN                 (1<<0)
#define MPTSCSI_MANUFACTURING7_PINOUT_SFF8482                 (1<<1)
#define MPTSCSI_MANUFACTURING7_PINOUT_SFF8470_LANE1           (1<<8)
#define MPTSCSI_MANUFACTURING7_PINOUT_SFF8470_LANE2           (1<<9)
#define MPTSCSI_MANUFACTURING7_PINOUT_SFF8470_LANE3           (1<<10)
#define MPTSCSI_MANUFACTURING7_PINOUT_SFF8470_LANE4           (1<<11)
#define MPTSCSI_MANUFACTURING7_PINOUT_SFF8484_LANE1           (1<<16)
#define MPTSCSI_MANUFACTURING7_PINOUT_SFF8484_LANE2           (1<<17)
#define MPTSCSI_MANUFACTURING7_PINOUT_SFF8484_LANE3           (1<<18)
#define MPTSCSI_MANUFACTURING7_PINOUT_SFF8484_LANE4           (1<<19)

/** Flags for the location field */
#define MPTSCSI_MANUFACTURING7_LOCATION_UNKNOWN               0x01
#define MPTSCSI_MANUFACTURING7_LOCATION_INTERNAL              0x02
#define MPTSCSI_MANUFACTURING7_LOCATION_EXTERNAL              0x04
#define MPTSCSI_MANUFACTURING7_LOCATION_SWITCHABLE            0x08
#define MPTSCSI_MANUFACTURING7_LOCATION_AUTO                  0x10
#define MPTSCSI_MANUFACTURING7_LOCATION_NOT_PRESENT           0x20
#define MPTSCSI_MANUFACTURING7_LOCATION_NOT_CONNECTED         0x80

/**
 * Manufacturing page 8 - Readonly.
 */
typedef struct QEMU_PACKED MptConfigurationPageManufacturing8 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                           page_data[4];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Product specific information */
        } fields;
    } u;
} MptConfigurationPageManufacturing8, *PMptConfigurationPageManufacturing8;

/**
 * Manufacturing page 9 - Readonly.
 */
typedef struct QEMU_PACKED MptConfigurationPageManufacturing9 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                           page_data[4];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Product specific information */
        } fields;
    } u;
} MptConfigurationPageManufacturing9, *PMptConfigurationPageManufacturing9;

/**
 * Manufacturing page 10 - Readonly.
 */
typedef struct QEMU_PACKED MptConfigurationPageManufacturing10 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                           page_data[4];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Product specific information */
        } fields;
    } u;
} MptConfigurationPageManufacturing10, *PMptConfigurationPageManufacturing10;

/**
 * IO Unit page 0. - Readonly.
 */
typedef struct QEMU_PACKED MptConfigurationPageIOUnit0 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[12];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** A unique identifier. */
            uint64_t              unique_identifier;
        } fields;
    } u;
} MptConfigurationPageIOUnit0, *PMptConfigurationPageIOUnit0;

/**
 * IO Unit page 1. - Read/Write.
 */
typedef struct QEMU_PACKED MptConfigurationPageIOUnit1 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[8];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Flag whether this is a single function PCI device. */
            unsigned              single_function:1;
            /** Flag whether all possible paths to a device are mapped. */
            unsigned              all_paths_mapped:1;
            /** Reserved. */
            unsigned              reserved:4;
            /** Flag whether all RAID functionality is disabled. */
            unsigned              integrated_raid_disabled:1;
            /** Flag whether 32bit PCI accesses are forced. */
            unsigned              f32bit_access_forced:1;
            /** Reserved. */
            unsigned              reserved1:24;
        } fields;
    } u;
} MptConfigurationPageIOUnit1, *PMptConfigurationPageIOUnit1;

/**
 * Adapter Ordering.
 */
typedef struct QEMU_PACKED MptConfigurationPageIOUnit2AdapterOrdering {
    /** PCI bus number. */
    uint8_t     pci_bus_number;
    /** PCI device and function number. */
    uint8_t     pci_dev_fn;
    /** Flag whether the adapter is embedded. */
    unsigned    adapter_embedded:1;
    /** Flag whether the adapter is enabled. */
    unsigned    adapter_enabled:1;
    /** Reserved. */
    unsigned    reserved:6;
    /** Reserved. */
    uint8_t     reserved1;
} MptConfigurationPageIOUnit2AdapterOrdering,
    *PMptConfigurationPageIOUnit2AdapterOrdering;

/**
 * IO Unit page 2. - Read/Write.
 */
typedef struct QEMU_PACKED MptConfigurationPageIOUnit2 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[28];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Reserved. */
            unsigned              reserved:1;
            /** Flag whether Pause on error is enabled. */
            unsigned              pause_on_error:1;
            /** Flag whether verbose mode is enabled. */
            unsigned              verbose_mode_enabled:1;
            /** Set to disable color video. */
            unsigned              disable_color_video:1;
            /** Flag whether int 40h is hooked. */
            unsigned              not_hook_int_40h:1;
            /** Reserved. */
            unsigned              reserved1:3;
            /** Reserved. */
            unsigned              reserved2:24;
            /** BIOS version. */
            uint32_t              bios_version;
            /** Adapter ordering. */
            MptConfigurationPageIOUnit2AdapterOrdering adapter_order[4];
        } fields;
    } u;
} MptConfigurationPageIOUnit2, *PMptConfigurationPageIOUnit2;

/*
 * IO Unit page 3. - Read/Write.
 */
typedef struct QEMU_PACKED MptConfigurationPageIOUnit3 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[8];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Number of GPIO values. */
            uint8_t               gpio_count;
            /** Reserved. */
            uint8_t               reserved[3];
        } fields;
    } u;
} MptConfigurationPageIOUnit3, *PMptConfigurationPageIOUnit3;

/*
 * IO Unit page 4. - Readonly for everyone except the BIOS.
 */
typedef struct QEMU_PACKED MptConfigurationPageIOUnit4 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[20];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Reserved */
            uint32_t                      reserved;
            /** SG entry describing the Firmware location. */
            MptSGEntrySimple64            fw_image_sge;
        } fields;
    } u;
} MptConfigurationPageIOUnit4, *PMptConfigurationPageIOUnit4;

/**
 * IOC page 0. - Readonly
 */
typedef struct QEMU_PACKED MptConfigurationPageIOC0 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[28];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Total amount of NV memory in bytes. */
            uint32_t              total_nv_Store;
            /** Number of free bytes in the NV store. */
            uint32_t              free_nv_store;
            /** PCI vendor ID. */
            uint16_t              vendor_id;
            /** PCI device ID. */
            uint16_t              device_id;
            /** PCI revision ID. */
            uint8_t               revision_id;
            /** Reserved. */
            uint8_t               reserved[3];
            /** PCI class code. */
            uint32_t              class_code;
            /** Subsystem vendor Id. */
            uint16_t              subsystem_vendor_id;
            /** Subsystem Id. */
            uint16_t              subsystem_id;
        } fields;
    } u;
} MptConfigurationPageIOC0, *PMptConfigurationPageIOC0;

/**
 * IOC page 1. - Read/Write
 */
typedef struct QEMU_PACKED MptConfigurationPageIOC1 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[16];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Flag whether reply coalescing is enabled. */
            unsigned              reply_coalescing_enabled:1;
            /** Reserved. */
            unsigned              reserved:31;
            /** Coalescing Timeout in microseconds. */
            uint32_t              coalescing_timeout;
            /** Coalescing depth. */
            uint8_t               coalescing_depth;
            /** Reserved. */
            uint8_t               reserved1;
            uint8_t               reserved2;
            uint8_t               reserved3;
        } fields;
    } u;
} MptConfigurationPageIOC1, *PMptConfigurationPageIOC1;

/**
 * IOC page 2. - Readonly
 */
typedef struct QEMU_PACKED MptConfigurationPageIOC2 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[12];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Flag whether striping is supported. */
            unsigned              striping_supported:1;
            /** Flag whether enhanced mirroring is supported. */
            unsigned              enhanced_mirroring_supported:1;
            /** Flag whether mirroring is supported. */
            unsigned              mirroring_supported:1;
            /** Reserved. */
            unsigned              reserved:26;
            /** Flag whether SES is supported. */
            unsigned              ses_supported:1;
            /** Flag whether SAF-TE is supported. */
            unsigned              saf_te_supported:1;
            /** Flag whether cross channel volumes are supported. */
            unsigned              cross_channel_volumes_supported:1;
            /** Number of active integrated RAID volumes. */
            uint8_t               num_active_volumes;
            /** Maximum number of integrated RAID volumes supported. */
            uint8_t               max_volumes;
            /** Number of active integrated RAID physical disks. */
            uint8_t               num_active_phys_disks;
            /** Maximum number of integrated RAID physical disks supported. */
            uint8_t               max_phys_disks;
            /** RAID volumes... - not supported. */
        } fields;
    } u;
} MptConfigurationPageIOC2, *PMptConfigurationPageIOC2;

/**
 * IOC page 3. - Readonly
 */
typedef struct QEMU_PACKED MptConfigurationPageIOC3 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[8];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Number of active integrated RAID physical disks. */
            uint8_t               num_phys_disks;
            /** Reserved. */
            uint8_t               reserved[3];
        } fields;
    } u;
} MptConfigurationPageIOC3, *PMptConfigurationPageIOC3;

/**
 * IOC page 4. - Read/Write
 */
typedef struct QEMU_PACKED MptConfigurationPageIOC4 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[8];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Number of SEP entries in this page. */
            uint8_t               active_sep;
            /** Maximum number of SEp entries supported. */
            uint8_t               max_sep;
            /** Reserved. */
            uint16_t              reserved;
            /** SEP entries... - not supported. */
        } fields;
    } u;
} MptConfigurationPageIOC4, *PMptConfigurationPageIOC4;

/**
 * IOC page 6. - Read/Write
 */
typedef struct QEMU_PACKED MptConfigurationPageIOC6 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[60];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            uint32_t                      capabilities_flags;
            uint8_t                       max_drives_is;
            uint8_t                       max_drives_im;
            uint8_t                       max_drives_ime;
            uint8_t                       reserved1;
            uint8_t                       min_drives_is;
            uint8_t                       min_drives_im;
            uint8_t                       min_drives_ime;
            uint8_t                       reserved2;
            uint8_t                       max_global_hot_spares;
            uint8_t                       reserved3;
            uint16_t                      reserved4;
            uint32_t                      reserved5;
            uint32_t                      supported_stripe_size_map_is;
            uint32_t                      supported_stripe_size_map_ime;
            uint32_t                      reserved6;
            uint8_t                       metadata_size;
            uint8_t                       reserved7;
            uint16_t                      reserved8;
            uint16_t                      max_bad_block_table_entries;
            uint16_t                      reserved9;
            uint16_t                      ir_nvsram_usage;
            uint16_t                      reserved10;
            uint32_t                      ir_nvsram_version;
            uint32_t                      reserved11;
        } fields;
    } u;
} MptConfigurationPageIOC6, *PMptConfigurationPageIOC6;

/**
 * BIOS page 1 - Read/write.
 */
typedef struct QEMU_PACKED MptConfigurationPageBIOS1 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[48];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** BIOS options */
            uint32_t                      bios_options;
            /** IOC settings */
            uint32_t                      ioc_settings;
            /** Reserved */
            uint32_t                      reserved;
            /** Device settings */
            uint32_t                      device_settings;
            /** Number of devices */
            uint16_t                      number_of_devices;
            /** Expander spinup */
            uint8_t                       expander_spinup;
            /** Reserved */
            uint8_t                       reserved1;
            /** I/O timeout of block devices without removable media */
            uint16_t                      io_timeout_block_devices_non_rm;
            /** I/O timeout sequential */
            uint16_t                      io_timeout_sequential;
            /** I/O timeout other */
            uint16_t                      io_timeout_other;
            /** I/O timeout of block devices with removable media */
            uint16_t                      io_timeout_block_devices_rm;
        } fields;
    } u;
} MptConfigurationPageBIOS1, *PMptConfigurationPageBIOS1;

#define MPTSCSI_BIOS1_BIOSOPTIONS_BIOS_DISABLE              (1<<0)
#define MPTSCSI_BIOS1_BIOSOPTIONS_SCAN_FROM_HIGH_TO_LOW     (1<<1)
#define MPTSCSI_BIOS1_BIOSOPTIONS_BIOS_EXTENDED_SAS_SUPPORT (1<<8)
#define MPTSCSI_BIOS1_BIOSOPTIONS_BIOS_EXTENDED_FC_SUPPORT  (1<<9)
#define MPTSCSI_BIOS1_BIOSOPTIONS_BIOS_EXTENDED_SPI_SUPPORT (1<<10)

#define MPTSCSI_BIOS1_IOCSETTINGS_ALTERNATE_CHS             (1<<3)

#define MPTSCSI_BIOS1_IOCSETTINGS_ADAPTER_SUPPORT_SET(x)    ((x) << 4)
#define MPTSCSI_BIOS1_IOCSETTINGS_ADAPTER_SUPPORT_DISABLED  0x00
#define MPTSCSI_BIOS1_IOCSETTINGS_ADAPTER_SUPPORT_BIOS_ONLY 0x01
#define MPTSCSI_BIOS1_IOCSETTINGS_ADAPTER_SUPPORT_OS_ONLY   0x02
#define MPTSCSI_BIOS1_IOCSETTINGS_ADAPTER_SUPPORT_BOT       0x03

#define MPTSCSI_BIOS1_IOCSETTINGS_REMOVABLE_MEDIA_SET(x)    ((x) << 6)
#define MPTSCSI_BIOS1_IOCSETTINGS_REMOVABLE_MEDIA_NO_INT13H 0x00
#define MPTSCSI_BIOS1_IOCSETTINGS_REMOVABLE_BOOT_MEDIA_INT13H 0x01
#define MPTSCSI_BIOS1_IOCSETTINGS_REMOVABLE_MEDIA_INT13H      0x02

#define MPTSCSI_BIOS1_IOCSETTINGS_SPINUP_DELAY_SET(x) ((x & 0xF) << 8)
#define MPTSCSI_BIOS1_IOCSETTINGS_SPINUP_DELAY_GET(x) ((x >> 8) & 0x0F)
#define MPTSCSI_BIOS1_IOCSETTINGS_MAX_TARGET_SPINUP_SET(x) ((x & 0xF) << 12)
#define MPTSCSI_BIOS1_IOCSETTINGS_MAX_TARGET_SPINUP_GET(x) ((x >> 12) & 0x0F)

#define MPTSCSI_BIOS1_IOCSETTINGS_BOOT_PREFERENCE_SET(x)        \
    (((x) & 0x3) << 16)
#define MPTSCSI_BIOS1_IOCSETTINGS_BOOT_PREFERENCE_ENCLOSURE   0x0
#define MPTSCSI_BIOS1_IOCSETTINGS_BOOT_PREFERENCE_SAS_ADDRESS 0x1

#define MPTSCSI_BIOS1_IOCSETTINGS_DIRECT_ATTACH_SPINUP_MODE_ALL (1<<18)
#define MPTSCSI_BIOS1_IOCSETTINGS_AUTO_PORT_ENABLE              (1<<19)

#define MPTSCSI_BIOS1_IOCSETTINGS_PORT_ENABLE_REPLY_DELAY_SET(x)        \
    (((x) & 0xF) << 20)
#define MPTSCSI_BIOS1_IOCSETTINGS_PORT_ENABLE_REPLY_DELAY_GET(x)        \
    ((x >> 20) & 0x0F)

#define MPTSCSI_BIOS1_IOCSETTINGS_PORT_ENABLE_SPINUP_DELAY_SET(x)       \
    (((x) & 0xF) << 24)
#define MPTSCSI_BIOS1_IOCSETTINGS_PORT_ENABLE_SPINUP_DELAY_GET(x)       \
    ((x >> 24) & 0x0F)

#define MPTSCSI_BIOS1_DEVSETTINGS_DISABLE_LUN_SCANS      (1<<0)
#define MPTSCSI_BIOS1_DEVSETTINGS_DISABLE_LUN_SCANS_NON_REMOVABLE_DEVS (1<<1)
#define MPTSCSI_BIOS1_DEVSETTINGS_DISABLE_LUN_SCANS_REMOVABLE_DEVS (1<<2)
#define MPTSCSI_BIOS1_DEVSETTINGS_DISABLE_LUN_SCANS2     (1<<3)
#define MPTSCSI_BIOS1_DEVSETTINGS_DISABLE_SMART_POLLING  (1<<4)

#define MPTSCSI_BIOS1_EXPANDERSPINUP_SPINUP_DELAY_SET(x) ((x) & 0x0F)
#define MPTSCSI_BIOS1_EXPANDERSPINUP_SPINUP_DELAY_GET(x) ((x) & 0x0F)
#define MPTSCSI_BIOS1_EXPANDERSPINUP_MAX_SPINUP_DELAY_SET(x)    \
    (((x) & 0x0F) << 4)
#define MPTSCSI_BIOS1_EXPANDERSPINUP_MAX_SPINUP_DELAY_GET(x) ((x >> 4) & 0x0F)

/**
 * BIOS page 2 - Read/write.
 */
typedef struct QEMU_PACKED MptConfigurationPageBIOS2 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[384];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Reserved */
            uint32_t                      reserved[6];
            /** Format of the boot device field. */
            uint8_t                       boot_device_form;
            /** Previous format of the boot device field. */
            uint8_t                       prev_boot_device_form;
            /** Reserved */
            uint16_t                      reserved1;
            /** Boot device fields - dependent on the format */
            union {
                /** Device for AdapterNumber:Bus:Target:LUN */
                struct {
                    /** Target ID */
                    uint8_t               target_id;
                    /** Bus */
                    uint8_t               bus;
                    /** Adapter Number */
                    uint8_t               adapter_number;
                    /** Reserved */
                    uint8_t               reserved;
                    /** Reserved */
                    uint32_t              reserved1[3];
                    /** LUN */
                    uint32_t              lun[5];
                    /** Reserved */
                    uint32_t              reserved2[56];
                } AdapterNumberBusTargetLUN;
                /** Device for PCIAddress:Bus:Target:LUN */
                struct {
                    /** Target ID */
                    uint8_t               target_id;
                    /** Bus */
                    uint8_t               bus;
                    /** Adapter Number */
                    uint16_t              pci_address;
                    /** Reserved */
                    uint32_t              reserved[3];
                    /** LUN */
                    uint32_t              lun[5];
                    /** Reserved */
                    uint32_t              reserved2[56];
                } PCIAddressBusTargetLUN;
                /** Device for PCISlotNo:Bus:Target:LUN */
                struct {
                    /** Target ID */
                    uint8_t               target_id;
                    /** Bus */
                    uint8_t               bus;
                    /** PCI Slot Number */
                    uint8_t               pci_slot_no;
                    /** Reserved */
                    uint32_t              reserved[3];
                    /** LUN */
                    uint32_t              lun[5];
                    /** Reserved */
                    uint32_t              reserved2[56];
                } PCIAddressBusSlotLUN;
                /** Device for FC channel world wide name */
                struct {
                    /** World wide port name low */
                    uint32_t              world_wide_port_name_low;
                    /** World wide port name high */
                    uint32_t              world_wide_port_name_high;
                    /** Reserved */
                    uint32_t              reserved[3];
                    /** LUN */
                    uint32_t              lun[5];
                    /** Reserved */
                    uint32_t              reserved2[56];
                } FCWorldWideName;
                /** Device for FC channel world wide name */
                struct {
                    /** SAS address */
                    SASADDRESS            sas_address;
                    /** Reserved */
                    uint32_t              reserved[3];
                    /** LUN */
                    uint32_t              lun[5];
                    /** Reserved */
                    uint32_t              reserved2[56];
                } SASWorldWideName;
                /** Device for Enclosure/Slot */
                struct {
                    /** Enclosure logical ID */
                    uint64_t              enclosure_logical_id;
                    /** Reserved */
                    uint32_t              reserved[3];
                    /** LUN */
                    uint32_t              lun[5];
                    /** Reserved */
                    uint32_t              reserved2[56];
                } EnclosureSlot;
            } BootDevice;
        } fields;
    } u;
} MptConfigurationPageBIOS2, *PMptConfigurationPageBIOS2;

#define MPTSCSI_BIOS2_BOOT_DEVICE_FORM_SET(x)                 ((x) & 0x0F)
#define MPTSCSI_BIOS2_BOOT_DEVICE_FORM_FIRST                  0x0
#define MPTSCSI_BIOS2_BOOT_DEVICE_FORM_ADAPTER_BUS_TARGET_LUN 0x1
#define MPTSCSI_BIOS2_BOOT_DEVICE_FORM_PCIADDR_BUS_TARGET_LUN 0x2
#define MPTSCSI_BIOS2_BOOT_DEVICE_FORM_PCISLOT_BUS_TARGET_LUN 0x3
#define MPTSCSI_BIOS2_BOOT_DEVICE_FORM_FC_WWN                 0x4
#define MPTSCSI_BIOS2_BOOT_DEVICE_FORM_SAS_WWN                0x5
#define MPTSCSI_BIOS2_BOOT_DEVICE_FORM_ENCLOSURE_SLOT         0x6

/**
 * BIOS page 4 - Read/Write (Where is 3? - not defined in the spec)
 */
typedef struct QEMU_PACKED MptConfigurationPageBIOS4 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[12];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Reassignment Base WWID */
            uint64_t                      reassignment_base_wwid;
        } fields;
    } u;
} MptConfigurationPageBIOS4, *PMptConfigurationPageBIOS4;

/**
 * SCSI-SPI port page 0. - Readonly
 */
typedef struct QEMU_PACKED MptConfigurationPageSCSISPIPort0 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[12];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /* Flag whether this port is information unit transfers capable. */
            unsigned              information_unit_transfers_capable:1;
            /* Flag whether the port is DT (Dual Transfer) capable. */
            unsigned              dt_capable:1;
            /* Flag whether the port is QAS  capable. */
            unsigned              qas_capable:1;
            /* reserved. */
            unsigned              reserved:5;
            /* Minimum Synchronous transfer period. */
            uint8_t               minimum_synchronous_transfer_period;
            /* Maximum synchronous offset. */
            uint8_t               maximum_synchronous_offset;
            /** Reserved. */
            unsigned              reserved1:5;
            /* Flag whether indicating the width of the bus -
               0 narrow and 1 for wide. */
            unsigned              wide:1;
            /* reserved */
            unsigned              reserved2:1;
            /* Flag whether the port is AIP capable. */
            unsigned              aip_capable:1;
            /* Signaling Type. */
            unsigned              signaling_type:2;
            /* reserved. */
            unsigned              reserved3:30;
        } fields;
    } u;
} MptConfigurationPageSCSISPIPort0, *PMptConfigurationPageSCSISPIPort0;

/**
 * SCSI-SPI port page 1. - Read/Write
 */
typedef struct QEMU_PACKED MptConfigurationPageSCSISPIPort1 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[12];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** The SCSI ID of the port. */
            uint8_t               scsi_id;
            /** Reserved. */
            uint8_t               reserved;
            /** Port response IDs Bit mask field. */
            uint16_t              port_response_i_ds_bitmask;
            /** Value for the on BUS timer. */
            uint32_t              on_bus_timer_value;
        } fields;
    } u;
} MptConfigurationPageSCSISPIPort1, *PMptConfigurationPageSCSISPIPort1;

/**
 * Device settings for one device.
 */
typedef struct QEMU_PACKED MptDeviceSettings {
    /** Timeout for I/O in seconds. */
    uint8_t     timeout;
    /** Minimum synchronous factor. */
    uint8_t     sync_factor;
    /** Flag whether disconnect is enabled. */
    unsigned    disconnect_enable:1;
    /** Flag whether Scan ID is enabled. */
    unsigned    scan_i_d_enable:1;
    /** Flag whether Scan LUNs is enabled. */
    unsigned    scan_lun_enable:1;
    /** Flag whether tagged queuing is enabled. */
    unsigned    tagged_queuing_enabled:1;
    /** Flag whether wide is enabled. */
    unsigned    wide_disable:1;
    /** Flag whether this device is bootable. */
    unsigned    boot_choice:1;
    /** Reserved. */
    unsigned    reserved:10;
} MptDeviceSettings, *PMptDeviceSettings;

/**
 * SCSI-SPI port page 2. - Read/Write for the BIOS
 */
typedef struct QEMU_PACKED MptConfigurationPageSCSISPIPort2 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[76];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Flag indicating the bus scan order. */
            unsigned              bus_scan_order_high_to_low:1;
            /** Reserved. */
            unsigned              reserved:1;
            /** Flag whether SCSI Bus resets are avoided. */
            unsigned              avoid_scsi_bus_resets:1;
            /** Flag whether alternate CHS is used. */
            unsigned              alternate_chs:1;
            /** Flag whether termination is disabled. */
            unsigned              termination_disabled:1;
            /** Reserved. */
            unsigned              reserved1:27;
            /** Host SCSI ID. */
            unsigned              host_scsi_id:4;
            /** Initialize HBA. */
            unsigned              initialize_hba:2;
            /** Removeable media setting. */
            unsigned              removable_media_setting:2;
            /** Spinup delay. */
            unsigned              spinup_delay:4;
            /** Negotiating settings. */
            unsigned              negotitating_settings:2;
            /** Reserved. */
            unsigned              reserved2:18;
            /** Device Settings. */
            MptDeviceSettings     device_settings[16];
        } fields;
    } u;
} MptConfigurationPageSCSISPIPort2, *PMptConfigurationPageSCSISPIPort2;

/**
 * SCSI-SPI device page 0. - Readonly
 */
typedef struct QEMU_PACKED MptConfigurationPageSCSISPIDevice0 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[12];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Negotiated Parameters. */
            /** Information Units enabled. */
            unsigned              information_units_enabled:1;
            /** Dual Transfers Enabled. */
            unsigned              dt_enabled:1;
            /** QAS enabled. */
            unsigned              qas_enabled:1;
            /** Reserved. */
            unsigned              reserved:5;
            /** Synchronous Transfer period. */
            uint8_t               negotiated_synchronous_transfer_period;
            /** Synchronous offset. */
            uint8_t               negotiated_synchronous_offset;
            /** Reserved. */
            unsigned              reserved1:5;
            /** Width - 0 for narrow and 1 for wide. */
            unsigned              wide:1;
            /** Reserved. */
            unsigned              reserved2:1;
            /** AIP enabled. */
            unsigned              aip_enabled:1;
            /** Flag whether negotiation occurred. */
            unsigned              negotation_occured:1;
            /** Flag whether a SDTR message was rejected. */
            unsigned              sdtr_rejected:1;
            /** Flag whether a WDTR message was rejected. */
            unsigned              wdtr_rejected:1;
            /** Flag whether a PPR message was rejected. */
            unsigned              ppr_rejected:1;
            /** Reserved. */
            unsigned              reserved3:28;
        } fields;
    } u;
} MptConfigurationPageSCSISPIDevice0, *PMptConfigurationPageSCSISPIDevice0;

/**
 * SCSI-SPI device page 1. - Read/Write
 */
typedef struct QEMU_PACKED MptConfigurationPageSCSISPIDevice1 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[16];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Requested Parameters. */
            /** Information Units enable. */
            bool                  information_units_enable:1;
            /** Dual Transfers Enable. */
            bool                  dt_enable:1;
            /** QAS enable. */
            bool                  qas_enable:1;
            /** Reserved. */
            unsigned              reserved:5;
            /** Synchronous Transfer period. */
            uint8_t               negotiated_synchronous_transfer_period;
            /** Synchronous offset. */
            uint8_t               negotiated_synchronous_offset;
            /** Reserved. */
            unsigned              reserved1:5;
            /** Width - 0 for narrow and 1 for wide. */
            bool                  wide:1;
            /** Reserved. */
            bool                  reserved2:1;
            /** AIP enable. */
            bool                  aip_enable:1;
            /** Reserved. */
            bool                  reserved3:1;
            /** WDTR disallowed. */
            bool                  wdtr_disallowed:1;
            /** SDTR disallowed. */
            bool                  sdtr_disallowed:1;
            /** Reserved. */
            unsigned              reserved4:29;
        } fields;
    } u;
} MptConfigurationPageSCSISPIDevice1, *PMptConfigurationPageSCSISPIDevice1;

/**
 * SCSI-SPI device page 2. - Read/Write
 */
typedef struct QEMU_PACKED MptConfigurationPageSCSISPIDevice2 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[16];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Reserved. */
            unsigned              reserved:4;
            /** ISI enable. */
            unsigned              isi_enable:1;
            /** Secondary driver enable. */
            unsigned              secondary_driver_enable:1;
            /** Reserved. */
            unsigned              reserved1:1;
            /** Slew create controller. */
            unsigned              slew_rate_controler:3;
            /** Primary drive strength controller. */
            unsigned              primary_drive_strength_control:3;
            /** Secondary drive strength controller. */
            unsigned              secondary_drive_strength_control:3;
            /** Reserved. */
            unsigned              reserved2:12;
            /** XCLKH_ST. */
            unsigned              xclkh_st:1;
            /** XCLKS_ST. */
            unsigned              xclks_st:1;
            /** XCLKH_DT. */
            unsigned              xclkh_dt:1;
            /** XCLKS_DT. */
            unsigned              xclks_dt:1;
            /** Parity pipe select. */
            unsigned              parity_pipe_select:2;
            /** Reserved. */
            unsigned              reserved3:30;
            /** Data bit pipeline select. */
            uint32_t              data_pipeline_select;
        } fields;
    } u;
} MptConfigurationPageSCSISPIDevice2, *PMptConfigurationPageSCSISPIDevice2;

/**
 * SCSI-SPI device page 3 (Revision G). - Readonly
 */
typedef struct QEMU_PACKED MptConfigurationPageSCSISPIDevice3 {
    /** Union. */
    union {
        /** Byte view. */
        uint8_t                   page_data[1];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptConfigurationPageHeader    header;
            /** Number of times the IOC rejected a message because
                it doesn't support the operation. */
            uint16_t                      msg_reject_count;
            /** Number of times the SCSI bus entered an invalid
                operation state. */
            uint16_t                      phase_error_count;
            /** Number of parity errors. */
            uint16_t                      parity_count;
            /** Reserved. */
            uint16_t                      reserved;
        } fields;
    } u;
} MptConfigurationPageSCSISPIDevice3, *PMptConfigurationPageSCSISPIDevice3;

/**
 * PHY entry for the SAS I/O unit page 0
 */
typedef struct QEMU_PACKED MptConfigurationPageSASIOUnit0PHY {
    /** Port number */
    uint8_t                           port;
    /** Port flags */
    uint8_t                           port_flags;
    /** Phy flags */
    uint8_t                           phy_flags;
    /** negotiated link rate */
    uint8_t                           negotiated_link_rate;
    /** Controller phy device info */
    uint32_t                          controller_phy_device_info;
    /** Attached device handle */
    uint16_t                          attached_dev_handle;
    /** Controller device handle */
    uint16_t                          controller_dev_handle;
    /** Discovery status */
    uint32_t                          discovery_status;
} MptConfigurationPageSASIOUnit0PHY, *PMptConfigurationPageSASIOUnit0PHY;

/**
 * SAS I/O  Unit page 0 - Readonly
 */
typedef struct QEMU_PACKED MptConfigurationPageSASIOUnit0 {
    /** Union. */
    union {
        /** Byte view - variable. */
        uint8_t                                   page_data[1];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptExtendedConfigurationPageHeader    ext_hdr;
            /** Nvdata version default */
            uint16_t                              nvdata_version_default;
            /** Nvdata version persistent */
            uint16_t                              nvdata_version_persistent;
            /** Number of physical ports */
            uint8_t                               num_phys;
            /** Reserved */
            uint8_t                               reserved[3];
            /** Content for each physical port -
                variable depending on the amount of ports. */
            MptConfigurationPageSASIOUnit0PHY     phy[1];
        } fields;
    } u;
} MptConfigurationPageSASIOUnit0, *PMptConfigurationPageSASIOUnit0;

#define MPTSCSI_SASIOUNIT0_GET_SIZE(ports)                      \
    (sizeof(MptConfigurationPageSASIOUnit0) + ((ports) - 1) *   \
     sizeof(MptConfigurationPageSASIOUnit0PHY))

#define MPTSCSI_SASIOUNIT0_PORT_CONFIGURATION_AUTO  (1<<0)
#define MPTSCSI_SASIOUNIT0_PORT_TARGET_IOC          (1<<2)
#define MPTSCSI_SASIOUNIT0_PORT_DISCOVERY_IN_STATUS (1<<3)

#define MPTSCSI_SASIOUNIT0_PHY_RX_INVERTED          (1<<0)
#define MPTSCSI_SASIOUNIT0_PHY_TX_INVERTED          (1<<1)
#define MPTSCSI_SASIOUNIT0_PHY_DISABLED             (1<<2)

#define MPTSCSI_SASIOUNIT0_NEGOTIATED_RATE_SET(x)   ((x) & 0x0F)
#define MPTSCSI_SASIOUNIT0_NEGOTIATED_RATE_GET(x)   ((x) & 0x0F)
#define MPTSCSI_SASIOUNIT0_NEGOTIATED_RATE_UNKNOWN  0x00
#define MPTSCSI_SASIOUNIT0_NEGOTIATED_RATE_DISABLED 0x01
#define MPTSCSI_SASIOUNIT0_NEGOTIATED_RATE_FAILED   0x02
#define MPTSCSI_SASIOUNIT0_NEGOTIATED_RATE_SATA_OOB 0x03
#define MPTSCSI_SASIOUNIT0_NEGOTIATED_RATE_15GB     0x08
#define MPTSCSI_SASIOUNIT0_NEGOTIATED_RATE_30GB     0x09

#define MPTSCSI_SASIOUNIT0_DEVICE_TYPE_SET(x)          ((x) & 0x3)
#define MPTSCSI_SASIOUNIT0_DEVICE_TYPE_NO              0x0
#define MPTSCSI_SASIOUNIT0_DEVICE_TYPE_END             0x1
#define MPTSCSI_SASIOUNIT0_DEVICE_TYPE_EDGE_EXPANDER   0x2
#define MPTSCSI_SASIOUNIT0_DEVICE_TYPE_FANOUT_EXPANDER 0x3

#define MPTSCSI_SASIOUNIT0_DEVICE_SATA_HOST            (1<<3)
#define MPTSCSI_SASIOUNIT0_DEVICE_SMP_INITIATOR        (1<<4)
#define MPTSCSI_SASIOUNIT0_DEVICE_STP_INITIATOR        (1<<5)
#define MPTSCSI_SASIOUNIT0_DEVICE_SSP_INITIATOR        (1<<6)
#define MPTSCSI_SASIOUNIT0_DEVICE_SATA                 (1<<7)
#define MPTSCSI_SASIOUNIT0_DEVICE_SMP_TARGET           (1<<8)
#define MPTSCSI_SASIOUNIT0_DEVICE_STP_TARGET           (1<<9)
#define MPTSCSI_SASIOUNIT0_DEVICE_SSP_TARGET           (1<<10)
#define MPTSCSI_SASIOUNIT0_DEVICE_DIRECT_ATTACHED      (1<<11)
#define MPTSCSI_SASIOUNIT0_DEVICE_LSI                  (1<<12)
#define MPTSCSI_SASIOUNIT0_DEVICE_ATAPI_DEVICE         (1<<13)
#define MPTSCSI_SASIOUNIT0_DEVICE_SEP_DEVICE           (1<<14)

#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_LOOP            (1<<0)
#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_UNADDRESSABLE   (1<<1)
#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_SAME_SAS_ADDR   (1<<2)
#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_EXPANDER_ERROR  (1<<3)
#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_SMP_TIMEOUT     (1<<4)
#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_EXP_ROUTE_OOE   (1<<5)
#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_EXP_ROUTE_IDX   (1<<6)
#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_SMP_FUNC_FAILED (1<<7)
#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_SMP_CRC_ERROR   (1<<8)
#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_SUBTRSCTIVE_LNK (1<<9)
#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_TBL_LNK         (1<<10)
#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_UNSUPPORTED_DEV (1<<11)
#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_MAX_SATA_TGTS   (1<<12)
#define MPTSCSI_SASIOUNIT0_DISCOVERY_STATUS_MULT_CTRLS      (1<<13)

/**
 * PHY entry for the SAS I/O unit page 1
 */
typedef struct QEMU_PACKED MptConfigurationPageSASIOUnit1PHY {
    /** Port number */
    uint8_t                           port;
    /** Port flags */
    uint8_t                           port_flags;
    /** Phy flags */
    uint8_t                           phy_flags;
    /** Max link rate */
    uint8_t                           max_min_link_rate;
    /** Controller phy device info */
    uint32_t                          controller_phy_device_info;
    /** Maximum target port connect time */
    uint16_t                          max_target_port_connect_time;
    /** Reserved */
    uint16_t                          reserved;
} MptConfigurationPageSASIOUnit1PHY, *PMptConfigurationPageSASIOUnit1PHY;

/**
 * SAS I/O  Unit page 1 - Read/Write
 */
typedef struct QEMU_PACKED MptConfigurationPageSASIOUnit1 {
    /** Union. */
    union {
        /** Byte view - variable. */
        uint8_t                                   page_data[1];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptExtendedConfigurationPageHeader    ext_hdr;
            /** Control flags */
            uint16_t                              control_flags;
            /** maximum number of SATA targets */
            uint16_t                              max_num_sata_targets;
            /** additional control flags */
            uint16_t                              additional_control_flags;
            /** Reserved */
            uint16_t                              reserved;
            /** Number of PHYs */
            uint8_t                               num_phys;
            /** maximum SATA queue depth */
            uint8_t                               sata_max_q_depth;
            /** Delay for reporting missing devices. */
            uint8_t                               report_device_missing_delay;
            /** I/O device missing delay */
            uint8_t                               i_o_device_missing_delay;
            /** Content for each physical port -
                variable depending on the number of ports */
            MptConfigurationPageSASIOUnit1PHY     phy[1];
        } fields;
    } u;
} MptConfigurationPageSASIOUnit1, *PMptConfigurationPageSASIOUnit1;

#define MPTSCSI_SASIOUNIT1_GET_SIZE(ports)                      \
    (sizeof(MptConfigurationPageSASIOUnit1) + ((ports) - 1) *   \
     sizeof(MptConfigurationPageSASIOUnit1PHY))

#define MPTSCSI_SASIOUNIT1_CONTROL_CLEAR_SATA_AFFILIATION     (1<<0)
#define MPTSCSI_SASIOUNIT1_CONTROL_FIRST_LEVEL_DISCOVERY_ONLY (1<<1)
#define MPTSCSI_SASIOUNIT1_CONTROL_SUBTRACTIVE_LNK_ILLEGAL    (1<<2)
#define MPTSCSI_SASIOUNIT1_CONTROL_IOC_ENABLE_HIGH_PHY        (1<<3)
#define MPTSCSI_SASIOUNIT1_CONTROL_SATA_FUA_REQUIRED          (1<<4)
#define MPTSCSI_SASIOUNIT1_CONTROL_SATA_NCQ_REQUIRED          (1<<5)
#define MPTSCSI_SASIOUNIT1_CONTROL_SATA_SMART_REQUIRED        (1<<6)
#define MPTSCSI_SASIOUNIT1_CONTROL_SATA_LBA48_REQUIRED        (1<<7)
#define MPTSCSI_SASIOUNIT1_CONTROL_SATA_INIT_POSTPONED        (1<<8)

#define MPTSCSI_SASIOUNIT1_CONTROL_DEVICE_SUPPORT_SET(x)        \
    (((x) & 0x3) << 9)
#define MPTSCSI_SASIOUNIT1_CONTROL_DEVICE_SUPPORT_GET(x)        \
    (((x) >> 9) & 0x3)
#define MPTSCSI_SASIOUNIT1_CONTROL_DEVICE_SUPPORT_SAS_AND_SATA 0x00
#define MPTSCSI_SASIOUNIT1_CONTROL_DEVICE_SUPPORT_SAS          0x01
#define MPTSCSI_SASIOUNIT1_CONTROL_DEVICE_SUPPORT_SATA         0x02

#define MPTSCSI_SASIOUNIT1_CONTROL_SATA_EXP_ADDR                  (1<<11)
#define MPTSCSI_SASIOUNIT1_CONTROL_SATA_SETTINGS_PRESERV_REQUIRED (1<<12)
#define MPTSCSI_SASIOUNIT1_CONTROL_SATA_LIMIT_RATE_15GB           (1<<13)
#define MPTSCSI_SASIOUNIT1_CONTROL_SATA_LIMIT_RATE_30GB           (1<<14)
#define MPTSCSI_SASIOUNIT1_CONTROL_SAS_SELF_TEST_ENABLED          (1<<15)

#define MPTSCSI_SASIOUNIT1_ADDITIONAL_CONTROL_TBL_LNKS_ALLOW        (1<<0)
#define MPTSCSI_SASIOUNIT1_ADDITIONAL_CONTROL_SATA_RST_NO_AFFIL     (1<<1)
#define MPTSCSI_SASIOUNIT1_ADDITIONAL_CONTROL_SATA_RST_SELF_AFFIL   (1<<2)
#define MPTSCSI_SASIOUNIT1_ADDITIONAL_CONTROL_SATA_RST_OTHER_AFFIL  (1<<3)
#define MPTSCSI_SASIOUNIT1_ADDITIONAL_CONTROL_SATA_RST_PORT_EN_ONLY (1<<4)
#define MPTSCSI_SASIOUNIT1_ADDITIONAL_CONTROL_HIDE_NON_ZERO_PHYS    (1<<5)
#define MPTSCSI_SASIOUNIT1_ADDITIONAL_CONTROL_SATA_ASYNC_NOTIF      (1<<6)
#define MPTSCSI_SASIOUNIT1_ADDITIONAL_CONTROL_MULT_PORTS_ILL_SAME_DOMAIN (1<<7)

#define MPTSCSI_SASIOUNIT1_MISSING_DEVICE_DELAY_UNITS_16_SEC     (1<<7)
#define MPTSCSI_SASIOUNIT1_MISSING_DEVICE_DELAY_SET(x)   ((x) & 0x7F)
#define MPTSCSI_SASIOUNIT1_MISSING_DEVICE_DELAY_GET(x)   ((x) & 0x7F)

#define MPTSCSI_SASIOUNIT1_PORT_CONFIGURATION_AUTO       (1<<0)
#define MPTSCSI_SASIOUNIT1_PORT_CONFIGURATION_IOC1       (1<<2)

#define MPTSCSI_SASIOUNIT1_PHY_RX_INVERT                 (1<<0)
#define MPTSCSI_SASIOUNIT1_PHY_TX_INVERT                 (1<<1)
#define MPTSCSI_SASIOUNIT1_PHY_DISABLE                   (1<<2)

#define MPTSCSI_SASIOUNIT1_LINK_RATE_MIN_SET(x)          ((x) & 0xF)
#define MPTSCSI_SASIOUNIT1_LINK_RATE_MIN_GET(x)          ((x) & 0xF)
#define MPTSCSI_SASIOUNIT1_LINK_RATE_MAX_SET(x)          (((x) & 0xF)<<4)
#define MPTSCSI_SASIOUNIT1_LINK_RATE_MAX_GET(x)          ((x >> 4) & 0xF)
#define MPTSCSI_SASIOUNIT1_LINK_RATE_15GB                0x8
#define MPTSCSI_SASIOUNIT1_LINK_RATE_30GB                0x9

#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_TYPE_SET(x)    ((x) & 0x3)
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_TYPE_GET(x)    ((x) & 0x3)
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_TYPE_NO                0x0
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_TYPE_END               0x1
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_TYPE_EDGE_EXPANDER     0x2
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_TYPE_FANOUT_EXPANDER   0x3
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_SMP_INITIATOR  (1<<4)
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_STP_INITIATOR  (1<<5)
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_SSP_INITIATOR  (1<<6)
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_SMP_TARGET     (1<<8)
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_STP_TARGET     (1<<9)
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_SSP_TARGET     (1<<10)
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_DIRECT_ATTACHED    (1<<11)
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_LSI            (1<<12)
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_ATAPI          (1<<13)
#define MPTSCSI_SASIOUNIT1_CTL_PHY_DEVICE_SEP            (1<<14)

/**
 * SAS I/O unit page 2 - Read/Write
 */
typedef struct QEMU_PACKED MptConfigurationPageSASIOUnit2 {
    /** Union. */
    union {
        /** Byte view - variable. */
        uint8_t                                   page_data[1];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptExtendedConfigurationPageHeader    ext_hdr;
            /** Device numbers per enclosure */
            uint8_t                               num_devs_per_enclosure;
            /** Boot device wait time */
            uint8_t                               boot_device_wait_time;
            /** Reserved */
            uint16_t                              reserved;
            /** Maximum number of persistent Bus and target ID mappings */
            uint16_t                              max_persistent_ids;
            /** Number of persistent IDs used */
            uint16_t                              num_persistent_i_ds_used;
            /** Status */
            uint8_t                               status;
            /** Flags */
            uint8_t                               flags;
            /** Maximum number of physical mapped IDs */
            uint16_t                              max_num_physical_mapped_i_ds;
        } fields;
    } u;
} MptConfigurationPageSASIOUnit2, *PMptConfigurationPageSASIOUnit2;

#define MPTSCSI_SASIOUNIT2_STATUS_PERSISTENT_MAP_TBL_FULL       (1<<0)
#define MPTSCSI_SASIOUNIT2_STATUS_PERSISTENT_MAP_DISABLED       (1<<1)
#define MPTSCSI_SASIOUNIT2_STATUS_PERSISTENT_ENC_DEV_UNMAPPED   (1<<2)
#define MPTSCSI_SASIOUNIT2_STATUS_PERSISTENT_DEV_LIMIT_EXCEEDED (1<<3)

#define MPTSCSI_SASIOUNIT2_FLAGS_PERSISTENT_MAP_DISABLE          (1<<0)
#define MPTSCSI_SASIOUNIT2_FLAGS_PERSISTENT_PHYS_MAP_MODE_SET(x)        \
    ((x & 0x7) << 1)
#define MPTSCSI_SASIOUNIT2_FLAGS_PERSISTENT_PHYS_MAP_MODE_GET(x)        \
    ((x >> 1) & 0x7)
#define MPTSCSI_SASIOUNIT2_FLAGS_PERSISTENT_PHYS_MAP_MODE_NO     0x0
#define MPTSCSI_SASIOUNIT2_FLAGS_PERSISTENT_PHYS_MAP_MODE_DIRECT_ATTACHED 0x1
#define MPTSCSI_SASIOUNIT2_FLAGS_PERSISTENT_PHYS_MAP_MODE_ENC    0x2
#define MPTSCSI_SASIOUNIT2_FLAGS_PERSISTENT_PHYS_MAP_MODE_HOST   0x7
#define MPTSCSI_SASIOUNIT2_FLAGS_RESERVE_TARGET_ID_ZERO          (1<<4)
#define MPTSCSI_SASIOUNIT2_FLAGS_START_SLOT_NUMBER_ONE           (1<<5)

/**
 * SAS I/O unit page 3 - Read/Write
 */
typedef struct QEMU_PACKED MptConfigurationPageSASIOUnit3 {
    /** Union. */
    union {
        /** Byte view - variable. */
        uint8_t                                   page_data[1];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptExtendedConfigurationPageHeader    ext_hdr;
            /** Reserved */
            uint32_t                          reserved;
            uint32_t                          max_invalid_dword_count;
            uint32_t                          invalid_dword_count_time;
            uint32_t                          max_running_disparity_error_count;
            uint32_t                          running_disparity_error_time;
            uint32_t                          max_loss_dword_synch_count;
            uint32_t                          loss_dword_synch_count_time;
            uint32_t                          max_phys_reset_problem_count;
            uint32_t                          phy_reset_problem_time;
        } fields;
    } u;
} MptConfigurationPageSASIOUnit3, *PMptConfigurationPageSASIOUnit3;

/**
 * SAS PHY page 0 - Readonly
 */
typedef struct QEMU_PACKED MptConfigurationPageSASPHY0 {
    /** Union. */
    union {
        /** Byte view - variable. */
        uint8_t                                   page_data[1];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptExtendedConfigurationPageHeader    ext_hdr;
            /** Owner dev handle. */
            uint16_t                              owner_dev_handle;
            /** Reserved */
            uint16_t                              reserved0;
            /** SAS address */
            SASADDRESS                            sas_address;
            /** Attached device handle */
            uint16_t                              attached_dev_handle;
            /** Attached phy identifier */
            uint8_t                               attached_phy_identifier;
            /** Reserved */
            uint8_t                               reserved1;
            /** Attached device information */
            uint32_t                              attached_device_info;
            /** Programmed link rate */
            uint8_t                               programmed_link_rate;
            /** Hardware link rate */
            uint8_t                               hw_link_rate;
            /** Change count */
            uint8_t                               change_count;
            /** Flags */
            uint8_t                               flags;
            /** Phy information */
            uint32_t                              phy_info;
        } fields;
    } u;
} MptConfigurationPageSASPHY0, *PMptConfigurationPageSASPHY0;

#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_TYPE_SET(x)          ((x) & 0x3)
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_TYPE_GET(x)          ((x) & 0x3)
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_TYPE_NO              0x0
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_TYPE_END             0x1
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_TYPE_EDGE_EXPANDER   0x2
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_TYPE_FANOUT_EXPANDER 0x3
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_SMP_INITIATOR        (1<<4)
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_STP_INITIATOR        (1<<5)
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_SSP_INITIATOR        (1<<6)
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_SMP_TARGET           (1<<8)
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_STP_TARGET           (1<<9)
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_SSP_TARGET           (1<<10)
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_DIRECT_ATTACHED      (1<<11)
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_LSI                  (1<<12)
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_ATAPI                (1<<13)
#define MPTSCSI_SASPHY0_DEV_INFO_DEVICE_SEP                  (1<<14)

/**
 * SAS PHY page 1 - Readonly
 */
typedef struct QEMU_PACKED MptConfigurationPageSASPHY1 {
    /** Union. */
    union {
        /** Byte view - variable. */
        uint8_t                                   page_data[1];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptExtendedConfigurationPageHeader    ext_hdr;
            /** Reserved */
            uint32_t                              reserved0;
            uint32_t                              invalid_dword_cound;
            uint32_t                              running_disparity_error_count;
            uint32_t                              loss_dword_synch_count;
            uint32_t                              phy_reset_problem_count;
        } fields;
    } u;
} MptConfigurationPageSASPHY1, *PMptConfigurationPageSASPHY1;

/**
 * SAS Device page 0 - Readonly
 */
typedef struct QEMU_PACKED MptConfigurationPageSASDevice0 {
    /** Union. */
    union {
        /** Byte view - variable. */
        uint8_t                                   page_data[1];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptExtendedConfigurationPageHeader    ext_hdr;
            /** Slot number */
            uint16_t                              slot;
            /** Enclosure handle. */
            uint16_t                              enclosure_handle;
            /** SAS address */
            SASADDRESS                            sas_address;
            /** Parent device handle */
            uint16_t                              parent_dev_handle;
            /** Phy number */
            uint8_t                               phy_num;
            /** Access status */
            uint8_t                               access_status;
            /** Device handle */
            uint16_t                              dev_handle;
            /** Target ID */
            uint8_t                               target_id;
            /** Bus */
            uint8_t                               bus;
            /** Device info */
            uint32_t                              device_info;
            /** Flags */
            uint16_t                              flags;
            /** Physical port */
            uint8_t                               physical_port;
            /** Reserved */
            uint8_t                               reserved0;
        } fields;
    } u;
} MptConfigurationPageSASDevice0, *PMptConfigurationPageSASDevice0;

#define MPTSCSI_SASDEVICE0_STATUS_NO_ERRORS                 (0x00)

#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_TYPE_SET(x)      ((x) & 0x3)
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_TYPE_GET(x)      ((x) & 0x3)
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_TYPE_NO              0x0
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_TYPE_END             0x1
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_TYPE_EDGE_EXPANDER   0x2
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_TYPE_FANOUT_EXPANDER 0x3
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_SMP_INITIATOR        (1<<4)
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_STP_INITIATOR        (1<<5)
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_SSP_INITIATOR        (1<<6)
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_SMP_TARGET           (1<<8)
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_STP_TARGET           (1<<9)
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_SSP_TARGET           (1<<10)
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_DIRECT_ATTACHED      (1<<11)
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_LSI                  (1<<12)
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_ATAPI                (1<<13)
#define MPTSCSI_SASDEVICE0_DEV_INFO_DEVICE_SEP                  (1<<14)

#define MPTSCSI_SASDEVICE0_FLAGS_DEVICE_PRESENT                 (1<<0)
#define MPTSCSI_SASDEVICE0_FLAGS_DEVICE_MAPPED_TO_BUS_AND_TARGET_ID (1<<(1))
#define MPTSCSI_SASDEVICE0_FLAGS_DEVICE_MAPPING_PERSISTENT (1<<(2))

/**
 * SAS Device page 1 - Readonly
 */
typedef struct QEMU_PACKED MptConfigurationPageSASDevice1 {
    /** Union. */
    union {
        /** Byte view - variable. */
        uint8_t                                   page_data[1];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptExtendedConfigurationPageHeader    ext_hdr;
            /** Reserved */
            uint32_t                              reserved0;
            /** SAS address */
            SASADDRESS                            sas_address;
            /** Reserved */
            uint32_t                              reserved;
            /** Device handle */
            uint16_t                              dev_handle;
            /** Target ID */
            uint8_t                               target_id;
            /** Bus */
            uint8_t                               bus;
            /** Initial REgister device FIS */
            uint32_t                              ainitial_reg_device_f_i_s[5];
        } fields;
    } u;
} MptConfigurationPageSASDevice1, *PMptConfigurationPageSASDevice1;

/**
 * SAS Device page 2 - Read/Write persistent
 */
typedef struct QEMU_PACKED MptConfigurationPageSASDevice2 {
    /** Union. */
    union {
        /** Byte view - variable. */
        uint8_t                                   page_data[1];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptExtendedConfigurationPageHeader    ext_hdr;
            /** Physical identifier */
            SASADDRESS                            sas_address;
            /** Enclosure mapping */
            uint32_t                              enclosure_mapping;
        } fields;
    } u;
} MptConfigurationPageSASDevice2, *PMptConfigurationPageSASDevice2;

/**
 * A device entitiy containing all pages.
 */
typedef struct QEMU_PACKED MptSASDevice {
    /** Pointer to the next device if any. */
    struct MptSASDevice            *p_next;
    /** Pointer to the previous device if any. */
    struct MptSASDevice            *p_prev;

    MptConfigurationPageSASDevice0  sas_dev_page0;
    MptConfigurationPageSASDevice1  sas_dev_page1;
    MptConfigurationPageSASDevice2  sas_dev_page2;
} MptSASDevice, *PMptSASDevice;

/**
 * SAS Expander page 0 - Readonly
 */
typedef struct QEMU_PACKED MptConfigurationPageSASExpander0 {
    /** Union. */
    union {
        /** Byte view - variable. */
        uint8_t                                   page_data[1];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptExtendedConfigurationPageHeader    ext_hdr;
            /** Physical port */
            uint8_t                               physical_port;
            /** Reserved */
            uint8_t                               reserved0;
            /** Enclosure handle */
            uint16_t                              enclosure_handle;
            /** SAS address */
            SASADDRESS                            sas_address;
            /** Discovery status */
            uint32_t                              discovery_status;
            /** Device handle. */
            uint16_t                              dev_handle;
            /** Parent device handle */
            uint16_t                              parent_dev_handle;
            /** Expander change count */
            uint16_t                              expander_change_count;
            /** Expander route indexes */
            uint16_t                              expander_route_indexes;
            /** Number of PHys in this expander */
            uint8_t                               num_phys;
            /** SAS level */
            uint8_t                               sas_level;
            /** Flags */
            uint8_t                               flags;
            /** Reserved */
            uint8_t                               reserved1;
        } fields;
    } u;
} MptConfigurationPageSASExpander0, *PMptConfigurationPageSASExpander0;

/**
 * SAS Expander page 1 - Readonly
 */
typedef struct QEMU_PACKED MptConfigurationPageSASExpander1 {
    /** Union. */
    union {
        /** Byte view - variable. */
        uint8_t                                   page_data[1];
        /** Field view. */
        struct {
            /** The omnipresent header. */
            MptExtendedConfigurationPageHeader    ext_hdr;
            /** Physical port */
            uint8_t                               physical_port;
            /** Reserved */
            uint8_t                               reserved0[3];
            /** Number of PHYs */
            uint8_t                               num_phys;
            /** Number of the Phy the information in this page is for. */
            uint8_t                               phy;
            /** Number of routing table entries */
            uint16_t                              num_table_entries_programmed;
            /** Programmed link rate */
            uint8_t                               programmed_link_rate;
            /** Hardware link rate */
            uint8_t                               hw_link_rate;
            /** Attached device handle */
            uint16_t                              attached_dev_handle;
            /** Phy information */
            uint32_t                              phy_info;
            /** Attached device information */
            uint32_t                              attached_device_info;
            /** Owner device handle. */
            uint16_t                              owner_dev_handle;
            /** Change count */
            uint8_t                               change_count;
            /** Negotiated link rate */
            uint8_t                               negotiated_link_rate;
            /** Phy identifier */
            uint8_t                               phy_identifier;
            /** Attached phy identifier */
            uint8_t                               attached_phy_identifier;
            /** Reserved */
            uint8_t                               reserved1;
            /** Discovery information */
            uint8_t                               discovery_info;
            /** Reserved */
            uint32_t                              reserved;
        } fields;
    } u;
} MptConfigurationPageSASExpander1, *PMptConfigurationPageSASExpander1;

/**
 * Structure of all supported pages for the SCSI SPI controller.
 * Used to load the device state from older versions.
 */
typedef struct MptConfigurationPagesSupported_SSM_V2 {
    MptConfigurationPageManufacturing0 manufacturing_page_0;
    MptConfigurationPageManufacturing1 manufacturing_page_1;
    MptConfigurationPageManufacturing2 manufacturing_page_2;
    MptConfigurationPageManufacturing3 manufacturing_page_3;
    MptConfigurationPageManufacturing4 manufacturing_page_4;
    MptConfigurationPageIOUnit0        io_unit_page_0;
    MptConfigurationPageIOUnit1        io_unit_page_1;
    MptConfigurationPageIOUnit2        io_unit_page_2;
    MptConfigurationPageIOUnit3        io_unit_page_3;
    MptConfigurationPageIOC0           ioc_page_0;
    MptConfigurationPageIOC1           ioc_page_1;
    MptConfigurationPageIOC2           ioc_page_2;
    MptConfigurationPageIOC3           ioc_page_3;
    MptConfigurationPageIOC4           ioc_page_4;
    MptConfigurationPageIOC6           ioc_page_6;
    struct {
        MptConfigurationPageSCSISPIPort0   scsi_spi_port_page_0;
        MptConfigurationPageSCSISPIPort1   scsi_spi_port_page_1;
        MptConfigurationPageSCSISPIPort2   scsi_spi_port_page_2;
    } port_pages[1]; /* Currently only one port supported. */
    struct {
        struct {
            MptConfigurationPageSCSISPIDevice0 scsi_spi_dev_page0;
            MptConfigurationPageSCSISPIDevice1 scsi_spi_dev_page1;
            MptConfigurationPageSCSISPIDevice2 scsi_spi_dev_page2;
            MptConfigurationPageSCSISPIDevice3 scsi_spi_dev_page3;
        } dev_pages[MPTSCSI_PCI_SPI_DEVICES_MAX];
    } buses[1]; /* Only one bus at the moment. */
} MptConfigurationPagesSupported_SSM_V2,
    *PMptConfigurationPagesSupported_SSM_V2;

typedef struct MptConfigurationPagesSpi {
    struct {
        MptConfigurationPageSCSISPIPort0   scsi_spi_port_page_0;
        MptConfigurationPageSCSISPIPort1   scsi_spi_port_page_1;
        MptConfigurationPageSCSISPIPort2   scsi_spi_port_page_2;
    } port_pages[1]; /* Currently only one port supported. */
    struct {
        struct {
            MptConfigurationPageSCSISPIDevice0 scsi_spi_dev_page0;
            MptConfigurationPageSCSISPIDevice1 scsi_spi_dev_page1;
            MptConfigurationPageSCSISPIDevice2 scsi_spi_dev_page2;
            MptConfigurationPageSCSISPIDevice3 scsi_spi_dev_page3;
        } dev_pages[MPTSCSI_PCI_SPI_DEVICES_MAX];
    } buses[1]; /* Only one bus at the moment. */
} MptConfigurationPagesSpi, *PMptConfigurationPagesSpi;

typedef struct MptPHY {
    MptConfigurationPageSASPHY0     sas_phy_page_0;
    MptConfigurationPageSASPHY1     sas_phy_page_1;
} MptPHY, *PMptPHY;

typedef struct QEMU_PACKED MptConfigurationPagesSas {
    /** Size of the manufacturing page 7 */
    uint32_t                            cb_manufacturing_page_7;
    /** Pointer to the manufacturing page 7 */
    PMptConfigurationPageManufacturing7 p_manufacturing_page_7;
    /** Size of the I/O unit page 0 */
    uint32_t                            cb_sas_io_unit_page_0;
    /** Pointer to the I/O unit page 0 */
    PMptConfigurationPageSASIOUnit0     p_sas_io_unit_page_0;
    /** Size of the I/O unit page 1 */
    uint32_t                            cb_sas_io_unit_page_1;
    /** Pointer to the I/O unit page 1 */
    PMptConfigurationPageSASIOUnit1     p_sas_io_unit_page_1;
    /** I/O unit page 2 */
    MptConfigurationPageSASIOUnit2      sas_io_unit_page_2;
    /** I/O unit page 3 */
    MptConfigurationPageSASIOUnit3      sas_io_unit_page_3;

    /** Number of PHYs in the array. */
    uint32_t                            c_phy_s;
    /** Pointer to an array of per PHYS pages. */
    PMptPHY                             pa_phy_s;

    /** Number of devices detected. */
    uint32_t                            c_devices;
    /** Pointer to the first SAS device. */
    PMptSASDevice                       p_sas_device_head;
    /** Pointer to the last SAS device. */
    PMptSASDevice                       p_sas_device_tail;
} MptConfigurationPagesSas, *PMptConfigurationPagesSas;

/**
 * Structure of all supported pages for both controllers.
 */
typedef struct MptConfigurationPagesSupported {
    MptConfigurationPageManufacturing0  manufacturing_page_0;
    MptConfigurationPageManufacturing1  manufacturing_page_1;
    MptConfigurationPageManufacturing2  manufacturing_page_2;
    MptConfigurationPageManufacturing3  manufacturing_page_3;
    MptConfigurationPageManufacturing4  manufacturing_page_4;
    MptConfigurationPageManufacturing5  manufacturing_page_5;
    MptConfigurationPageManufacturing6  manufacturing_page_6;
    MptConfigurationPageManufacturing8  manufacturing_page_8;
    MptConfigurationPageManufacturing9  manufacturing_page_9;
    MptConfigurationPageManufacturing10 manufacturing_page_10;
    MptConfigurationPageIOUnit0         io_unit_page_0;
    MptConfigurationPageIOUnit1         io_unit_page_1;
    MptConfigurationPageIOUnit2         io_unit_page_2;
    MptConfigurationPageIOUnit3         io_unit_page_3;
    MptConfigurationPageIOUnit4         io_unit_page_4;
    MptConfigurationPageIOC0            ioc_page_0;
    MptConfigurationPageIOC1            ioc_page_1;
    MptConfigurationPageIOC2            ioc_page_2;
    MptConfigurationPageIOC3            ioc_page_3;
    MptConfigurationPageIOC4            ioc_page_4;
    MptConfigurationPageIOC6            ioc_page_6;
    /* BIOS page 0 is not described */
    MptConfigurationPageBIOS1           bios_page_1;
    MptConfigurationPageBIOS2           bios_page_2;
    /* BIOS page 3 is not described */
    MptConfigurationPageBIOS4           bios_page_4;

    /** Controller dependent data. */
    union {
        MptConfigurationPagesSpi        spi_pages;
        MptConfigurationPagesSas        sas_pages;
    } u;
} MptConfigurationPagesSupported, *PMptConfigurationPagesSupported;

/**
 * Initializes a page header.
 */
#define MPT_CONFIG_PAGE_HEADER_INIT(pg, type, nr, flags)                \
    (pg)->u.fields.header.page_type = flags;                            \
    (pg)->u.fields.header.page_number = nr;                             \
    (pg)->u.fields.header.page_length = sizeof(type) / 4

#define MPT_CONFIG_PAGE_HEADER_INIT_MANUFACTURING(pg, type, nr, flags)  \
    MPT_CONFIG_PAGE_HEADER_INIT(pg, type, nr, flags |                   \
                                MPT_CONFIGURATION_PAGE_TYPE_MANUFACTURING)

#define MPT_CONFIG_PAGE_HEADER_INIT_IO_UNIT(pg, type, nr, flags)        \
    MPT_CONFIG_PAGE_HEADER_INIT(pg, type, nr, flags |                   \
                                MPT_CONFIGURATION_PAGE_TYPE_IO_UNIT)

#define MPT_CONFIG_PAGE_HEADER_INIT_IOC(pg, type, nr, flags)            \
    MPT_CONFIG_PAGE_HEADER_INIT(pg, type, nr, flags |                   \
                                MPT_CONFIGURATION_PAGE_TYPE_IOC)

#define MPT_CONFIG_PAGE_HEADER_INIT_BIOS(pg, type, nr, flags)           \
    MPT_CONFIG_PAGE_HEADER_INIT(pg, type, nr, flags |                   \
                                MPT_CONFIGURATION_PAGE_TYPE_BIOS)

/**
 * Initializes a extended page header.
 */
#define MPT_CONFIG_EXTENDED_PAGE_HEADER_INIT(pg, cb, nr, flags, exttype) \
    (pg)->u.fields.ext_hdr.page_type = flags |                           \
        MPT_CONFIGURATION_PAGE_TYPE_EXTENDED;                            \
    (pg)->u.fields.ext_hdr.page_number = nr;                             \
    (pg)->u.fields.ext_hdr.ext_page_type = exttype;                      \
    (pg)->u.fields.ext_hdr.ext_page_len = cb / 4

/**
 * Possible SG element types.
 */
enum MPTSGENTRYTYPE {
    MPTSGENTRYTYPE_TRANSACTION_CONTEXT = 0x00,
    MPTSGENTRYTYPE_SIMPLE = 0x01,
    MPTSGENTRYTYPE_CHAIN = 0x03
};

/**
 * Register interface.
 */

/**
 * Defined states that the SCSI controller can have.
 */
typedef enum MPTSTATE {
    /** Reset state. */
    MPTSTATE_RESET = 0x00,
    /** Ready state. */
    MPTSTATE_READY = 0x01,
    /** Operational state. */
    MPTSTATE_OPERATIONAL = 0x02,
    /** Fault state. */
    MPTSTATE_FAULT = 0x04,
    /** 32bit size hack */
    MPTSTATE_32BIT_HACK = 0x7fffffff
} MPTSTATE;

/**
 * Which entity needs to initialize the controller
 * to get into the operational state.
 */
typedef enum MPTWHOINIT {
    /** Not initialized. */
    MPTWHOINIT_NOT_INITIALIZED = 0x00,
    /** System BIOS. */
    MPTWHOINIT_SYSTEM_BIOS = 0x01,
    /** ROM Bios. */
    MPTWHOINIT_ROM_BIOS = 0x02,
    /** PCI Peer. */
    MPTWHOINIT_PCI_PEER = 0x03,
    /** Host driver. */
    MPTWHOINIT_HOST_DRIVER = 0x04,
    /** Manufacturing. */
    MPTWHOINIT_MANUFACTURING = 0x05,
    /** 32bit size hack. */
    MPTWHOINIT_32BIT_HACK = 0x7fffffff
} MPTWHOINIT;


/**
 * IOC status codes.
 */
#define MPT_IOCSTATUS_SUCCESS                0x0000
#define MPT_IOCSTATUS_INVALID_FUNCTION       0x0001
#define MPT_IOCSTATUS_BUSY                   0x0002
#define MPT_IOCSTATUS_INVALID_SGL            0x0003
#define MPT_IOCSTATUS_INTERNAL_ERROR         0x0004
#define MPT_IOCSTATUS_RESERVED               0x0005
#define MPT_IOCSTATUS_INSUFFICIENT_RESOURCES 0x0006
#define MPT_IOCSTATUS_INVALID_FIELD          0x0007
#define MPT_IOCSTATUS_INVALID_STATE          0x0008
#define MPT_IOCSTATUS_OP_STATE_NOT_SUPPOTED  0x0009

/**
 * Doorbell register - Used to get the status of the controller and
 * initialise it.
 */
#define MPT_REG_DOORBELL 0x00
#define MPT_REG_DOORBELL_SET_STATE(State) (((State) & 0x0f) << 28)
#define MPT_REG_DOORBELL_SET_USED(fUsed) (((fUsed) ? 1 : 0) << 27)
#define MPT_REG_DOORBELL_SET_WHOINIT(Who)(((Who) & 0x07) << 24)
#define MPT_REG_DOORBELL_SET_FAULT_CODE(Code) (Code)
#define MPT_REG_DOORBELL_GET_FUNCTION(x) (((x) & 0xff000000) >> 24)
#define MPT_REG_DOORBELL_GET_SIZE(x)     (((x) & 0x00ff0000) >> 16)

/**
 * Functions which can be passed through the system doorbell.
 */
#define MPT_DOORBELL_FUNCTION_IOC_MSG_UNIT_RESET  0x40
#define MPT_DOORBELL_FUNCTION_IO_UNIT_RESET       0x41
#define MPT_DOORBELL_FUNCTION_HANDSHAKE           0x42
#define MPT_DOORBELL_FUNCTION_REPLY_FRAME_REMOVAL 0x43

/**
 * Write sequence register for the diagnostic register.
 */
#define MPT_REG_WRITE_SEQUENCE    0x04

/**
 * Diagnostic register - used to reset the controller.
 */
#define MPT_REG_HOST_DIAGNOSTIC   0x08
#define MPT_REG_HOST_DIAGNOSTIC_DIAG_MEM_ENABLE     (1<<(0))
#define MPT_REG_HOST_DIAGNOSTIC_DISABLE_ARM         (1<<(1))
#define MPT_REG_HOST_DIAGNOSTIC_RESET_ADAPTER       (1<<(2))
#define MPT_REG_HOST_DIAGNOSTIC_DIAG_RW_ENABLE      (1<<(4))
#define MPT_REG_HOST_DIAGNOSTIC_RESET_HISTORY       (1<<(5))
#define MPT_REG_HOST_DIAGNOSTIC_FLASH_BAD_SIG       (1<<(6))
#define MPT_REG_HOST_DIAGNOSTIC_DRWE                (1<<(7))
#define MPT_REG_HOST_DIAGNOSTIC_PREVENT_IOC_BOOT    (1<<(9))
#define MPT_REG_HOST_DIAGNOSTIC_CLEAR_FLASH_BAD_SIG (1<<(10))

#define MPT_REG_TEST_BASE_ADDRESS 0x0c
#define MPT_REG_DIAG_RW_DATA      0x10
#define MPT_REG_DIAG_RW_ADDRESS   0x14

/**
 * Interrupt status register.
 */
#define MPT_REG_HOST_INTR_STATUS  0x30
#define MPT_REG_HOST_INTR_STATUS_W_MASK          (1<<(3))
#define MPT_REG_HOST_INTR_STATUS_DOORBELL_STS    (1<<(31))
#define MPT_REG_HOST_INTR_STATUS_REPLY_INTR      (1<<(3))
#define MPT_REG_HOST_INTR_STATUS_SYSTEM_DOORBELL (1<<(0))

/**
 * Interrupt mask register.
 */
#define MPT_REG_HOST_INTR_MASK    0x34
#define MPT_REG_HOST_INTR_MASK_W_MASK (1<<(0) | 1<<(3) | 1<<(8) | 1<<(9))
#define MPT_REG_HOST_INTR_MASK_IRQ_ROUTING (1<<(8) | 1<<(9))
#define MPT_REG_HOST_INTR_MASK_DOORBELL (1<<(0))
#define MPT_REG_HOST_INTR_MASK_REPLY    (1<<(3))

/**
 * Queue registers.
 */
#define MPT_REG_REQUEST_QUEUE     0x40
#define MPT_REG_REPLY_QUEUE       0x44


#define MPT_MAX_CMDS 2048     /* Firmware limit at 65535 */

#define NAA_LOCALLY_ASSIGNED_ID 0x3ULL
#define IEEE_COMPANY_LOCALLY_ASSIGNED 0x525400

#define MPT_FLAG_USE_MSIX      0
#define MPT_MASK_USE_MSIX      (1 << MPT_FLAG_USE_MSIX)
#define MPT_FLAG_USE_MSI       1
#define MPT_MASK_USE_MSI       (1 << MPT_FLAG_USE_MSI)

typedef struct MptCmd {
    uint32_t index;
    uint16_t flags;
    uint16_t count;
    uint64_t context;

    hwaddr host_msg_frame_pa;
    MptRequestUnion request;
    MptReplyUnion reply;
    SCSIRequest *req;
    QEMUSGList qsg;
    uint32_t sge_cnt;
    void *iov_buf;
    size_t iov_size;
    size_t iov_offset;
    struct MptState *state;
} MptCmd;

typedef struct MptState {
    PCIDevice dev;
    MemoryRegion mmio_io;
    MemoryRegion port_io;
    MemoryRegion diag_io;

    MptConfigurationPagesSupported *config_pages;

    MPTCTRLTYPE ctrl_type;
    MPTSTATE state;
    MPTWHOINIT who_init;
    uint16_t next_handle;
    uint32_t ports;
    uint32_t flags;
    uint32_t intr_mask;
    uint32_t intr_status;
    uint32_t doorbell;
    uint32_t busy;
    bool     msi_used;
    bool     event_notification_enabled;
    bool     diagnostic_enabled;
    uint32_t diagnostic_access_idx;
    /** Maximum number of devices the driver reported he can handle. */
    uint16_t max_devices;
    /** Maximum number of buses the driver reported he can handle. */
    uint16_t max_buses;

    uint64_t sas_addr;

    /* Buffer for messages which are passed through the doorbell
     * using the handshake method.
     */
    uint32_t drbl_message[(sizeof(MptRequestUnion)+sizeof(uint32_t)-1)/
                          sizeof(uint32_t)];
    uint16_t drbl_message_index;
    uint16_t drbl_message_size; /** Size of the message in dwords. */

    MptReplyUnion reply_buffer;
    uint16_t next_reply_entry_read;
    uint16_t reply_size;        /* in 16bit words. */

    uint16_t ioc_fault_code;    /* if we are in the fault state. */
    /** Current size of reply message frames in the guest. */
    uint16_t reply_frame_size;
    /** Upper 32 bits of the message frame address to
        locate requests in guest memory. */
    uint32_t host_mfa_high_addr;
    /** Upper 32 bits of the sense buffer address. */
    uint32_t sense_buffer_high_addr;

    uint32_t reply_queue_entries;
    uint32_t request_queue_entries;

    uint32_t *reply_post_queue;
    uint32_t *reply_free_queue;
    uint32_t *request_queue;
    uint32_t reply_free_queue_next_entry_free_write;
    uint32_t reply_free_queue_next_address_read;

    uint32_t reply_post_queue_next_entry_free_write;
    uint32_t reply_post_queue_next_address_read;

    uint32_t request_queue_next_entry_free_write;
    uint32_t request_queue_next_address_read;

    uint32_t next_cmd;
    MptCmd * cmds[MPT_MAX_CMDS];

    SCSIBus bus;
} MptState;

static bool mpt_use_msi(MptState *s)
{
    return s->flags & MPT_MASK_USE_MSI;
}

static bool mpt_use_msix(MptState *s)
{
    return s->flags & MPT_MASK_USE_MSIX;
}

static bool mpt_is_sas(MptState *s)
{
    return s->ctrl_type == MPTCTRLTYPE_SCSI_SAS;
}

static uint16_t mpt_get_handle(MptState *s)
{
    uint16_t handle = s->next_handle++;
    return handle;
}

static void mpt_soft_reset(MptState *s);

static void mpt_update_interrupt(MptState *s)
{
    uint32_t int_sts;

    int_sts = (s->intr_status & ~MPT_REG_HOST_INTR_STATUS_DOORBELL_STS);
    int_sts &= ~(s->intr_mask & ~MPT_REG_HOST_INTR_MASK_IRQ_ROUTING);

    if (int_sts) {
        if (msix_enabled(&s->dev)) {
            trace_mpt_msix_raise(0);
            msix_notify(&s->dev, 0);
        } else {
            trace_mpt_irq_raise();
            qemu_irq_raise(s->dev.irq[0]);
        }
    } else if (!msix_enabled(&s->dev)) {
        trace_mpt_irq_lower();
        qemu_irq_lower(s->dev.irq[0]);
    }
}

static void mpt_finish_address_reply(MptState *s,
                                     MptReplyUnion *reply,
                                     bool force_reply_fifo)
{
    /*
     * If we are in a doorbell function we set the reply size now and
     * set the system doorbell status interrupt to notify the guest that
     * we are ready to send the reply.
     */
    if (s->doorbell && !force_reply_fifo) {
        /* Set size of the reply in 16bit words.
         * The size in the reply is in 32bit dwords. */
        s->reply_size = reply->header.message_length * 2;
        s->next_reply_entry_read = 0;
        s->intr_status |= MPT_REG_HOST_INTR_STATUS_SYSTEM_DOORBELL;
        mpt_update_interrupt(s);
    } else {
        /* Grab a free reply message from the queue. */

        /* Check for a free reply frame and room on the post queue. */
        if ((s->reply_free_queue_next_address_read ==
             s->reply_free_queue_next_entry_free_write)) {
            s->ioc_fault_code = MPT_IOCSTATUS_INSUFFICIENT_RESOURCES;
            s->state = MPTSTATE_FAULT;
            return;
        }
        uint32_t reply_frame_address_low =
            s->reply_free_queue[s->reply_free_queue_next_address_read];

        uint32_t next_addr =
            (s->reply_free_queue_next_address_read + 1) %
            s->reply_queue_entries;
        if (next_addr != s->reply_free_queue_next_entry_free_write) {
            s->reply_free_queue_next_address_read = next_addr;
        }

        uint64_t reply_message_pa = ((uint64_t)s->host_mfa_high_addr << 32) |
            reply_frame_address_low;
        int reply_copied = (s->reply_frame_size < sizeof(MptReplyUnion)) ?
            s->reply_frame_size : sizeof(MptReplyUnion);

        cpu_physical_memory_write(reply_message_pa,
                                  (uint8_t *)reply, reply_copied);

        /* Write low 32bits of reply frame into post reply queue. */

        /* We have a address reply. Set the 31th bit to indicate that. */
        s->reply_post_queue[s->reply_post_queue_next_entry_free_write++] =
            (1<<31) | (reply_frame_address_low >> 1);
        s->reply_post_queue_next_entry_free_write %= s->reply_queue_entries;

        if (force_reply_fifo) {
            s->doorbell = false;
            s->intr_status |= MPT_REG_HOST_INTR_STATUS_SYSTEM_DOORBELL;
        }

        /* Set interrupt. */
        s->intr_status |= MPT_REG_HOST_INTR_STATUS_REPLY_INTR;
        mpt_update_interrupt(s);
    }
}

static void mpt_abort_command(MptCmd *cmd)
{
    if (cmd->req) {
        cmd->req = NULL;
    }
}


static QEMUSGList *mpt_get_sg_list(SCSIRequest *req)
{
    MptCmd *cmd = req->hba_private;

    if (cmd->sge_cnt == 0) {
        return NULL;
    } else {
        return &cmd->qsg;
    }
}

static void mpt_xfer_complete(SCSIRequest *req, uint32_t len)
{
    MptCmd *cmd = req->hba_private;

    trace_mpt_io_complete(cmd->index, len);
    if (cmd->sge_cnt != 0) {
        scsi_req_continue(req);
        return;
    }
}

static void mpt_finish_context_reply(MptState *s,
                                     uint32_t message_context)
{
    assert(!s->doorbell);

    /* Write message context ID into reply post queue. */
    s->reply_post_queue[s->reply_post_queue_next_entry_free_write++] =
        message_context;
    s->reply_post_queue_next_entry_free_write %= s->reply_queue_entries;

    s->intr_status |= MPT_REG_HOST_INTR_STATUS_REPLY_INTR;
    mpt_update_interrupt(s);
}

static void mpt_command_complete(SCSIRequest *req,
                                 uint32_t status, size_t resid)
{
    MptCmd *cmd = req->hba_private;
    uint8_t sense_buf[SCSI_SENSE_BUF_SIZE];
    uint8_t sense_len;

    hwaddr sense_buffer_pa =
        cmd->request.scsi_io.sense_buffer_low_address |
        ((uint64_t)cmd->state->sense_buffer_high_addr << 32);

    trace_mpt_command_complete(cmd->index, status, resid);

    if (cmd->sge_cnt) {
        qemu_sglist_destroy(&cmd->qsg);
    }

    sense_len = scsi_req_get_sense(cmd->req, sense_buf,
                                   SCSI_SENSE_BUF_SIZE);
    req->status = status;
    trace_mpt_scsi_complete(cmd->index, req->status,
                            cmd->iov_size, req->cmd.xfer);

    if (sense_len > 0) {
        cpu_physical_memory_write(
            sense_buffer_pa, sense_buf,
            MIN(cmd->request.scsi_io.sense_buffer_length, sense_len));
    }

    if (req->status != GOOD) {
        /* The SCSI target encountered an error during processing.
         * Post a reply. */
        memset(&cmd->reply, 0, sizeof(MptReplyUnion));
        cmd->reply.scsi_io_error.target_id =
            cmd->request.scsi_io.target_id;
        cmd->reply.scsi_io_error.bus =
            cmd->request.scsi_io.bus;
        cmd->reply.scsi_io_error.message_length = 8;
        cmd->reply.scsi_io_error.function =
            cmd->request.scsi_io.function;
        cmd->reply.scsi_io_error.cdb_length =
            cmd->request.scsi_io.cdb_length;
        cmd->reply.scsi_io_error.sense_buffer_length =
            cmd->request.scsi_io.sense_buffer_length;
        cmd->reply.scsi_io_error.message_flags =
            cmd->request.scsi_io.message_flags;
        cmd->reply.scsi_io_error.message_context =
            cmd->request.scsi_io.message_context;
        cmd->reply.scsi_io_error.scsi_status = req->status;
        cmd->reply.scsi_io_error.scsi_state =
            MPT_SCSI_IO_ERROR_SCSI_STATE_AUTOSENSE_VALID;
        cmd->reply.scsi_io_error.ioc_status = 0;
        cmd->reply.scsi_io_error.ioc_log_info = 0;
        cmd->reply.scsi_io_error.transfer_count = 0;
        cmd->reply.scsi_io_error.sense_count = sense_len;
        cmd->reply.scsi_io_error.response_info = 0;

        mpt_finish_address_reply(cmd->state, &cmd->reply, true);
    } else {
        mpt_finish_context_reply(cmd->state,
                                 cmd->request.scsi_io.message_context);
    }

    scsi_req_unref(cmd->req);
    cmd->state->cmds[cmd->index] = 0;
    cmd->req = NULL;
    g_free(cmd);
}

static void mpt_command_cancel(SCSIRequest *req)
{
    MptCmd *cmd = req->hba_private;

    if (cmd && cmd->req) {
        scsi_req_unref(req);
        cmd->req = NULL;
    }
}

static void mpt_map_sgl(MptState *s, MptCmd *cmd,
                        hwaddr sgl_pa, uint32_t chain_offset)
{
    uint32_t iov_count = 0;
    bool do_mapping = false;
    uint32_t pass;

    for (pass = 0; pass < 2; pass++) {
        bool end_of_list = false;
        hwaddr next_sge_pa = sgl_pa;
        hwaddr seg_start_pa = sgl_pa;
        uint32_t next_chain_offset = chain_offset;

        if (do_mapping) {
            cmd->sge_cnt = iov_count;
	    //            qemu_sglist_init(&cmd->qsg, iov_count, pci_dma_context(&s->dev));
            qemu_sglist_init(&cmd->qsg, iov_count, &dma_context_memory);
        }
        while (end_of_list == false) {
            bool end_of_seg = false;

            while (end_of_seg == false) {
                MptSGEntryUnion sge;
                cpu_physical_memory_read(next_sge_pa, &sge,
                                         sizeof(MptSGEntryUnion));
                assert(sge.simple_32.element_type == MPTSGENTRYTYPE_SIMPLE);
                if (sge.simple_32.length == 0 && sge.simple_32.end_of_list &&
                    sge.simple_32.end_of_buffer) {
                    cmd->sge_cnt = 0;
                    return;
                }
                if (sge.simple_32.bit_address) {
                    next_sge_pa += sizeof(MptSGEntrySimple64);
                } else {
                    next_sge_pa += sizeof(MptSGEntrySimple32);
                }
                if (do_mapping) {
                    dma_addr_t iov_pa = sge.simple_32.data_buf_addr_low;
                    dma_addr_t iov_size = sge.simple_32.length;

                    if (sge.simple_32.bit_address) {
                        iov_pa |=
                            ((uint64_t)sge.simple_64.data_buf_addr_high) << 32;
                    }

                    qemu_sglist_add(&cmd->qsg, iov_pa, iov_size);
                }
                iov_count++;
                if (sge.simple_32.end_of_list) {
                    end_of_seg = true;
                    end_of_list = true;
                } else if (sge.simple_32.last_element) {
                    end_of_seg = true;
                }
            }
            if (next_chain_offset) {
                MptSGEntryChain sgec;
                cpu_physical_memory_read(seg_start_pa + next_chain_offset,
                                         &sgec, sizeof(MptSGEntryChain));
                assert(sgec.element_type == MPTSGENTRYTYPE_CHAIN);
                next_sge_pa = sgec.segment_address_low;
                if (sgec.bit_address) {
                    next_sge_pa |=
                        ((uint64_t)sgec.segment_address_high) << 32;
                }
                seg_start_pa = next_sge_pa;
                next_chain_offset = sgec.next_chain_offset * sizeof(uint32_t);
            }
        }
        do_mapping = true;
    }
}

static int mpt_process_scsi_io_Request(MptState *s, MptCmd *cmd)
{
    struct SCSIDevice *sdev = NULL;

    if (cmd->request.scsi_io.target_id < s->max_devices &&
        cmd->request.scsi_io.bus == 0) {
        sdev = scsi_device_find(&s->bus, 0, cmd->request.scsi_io.target_id,
                                cmd->request.scsi_io.lun[1]);
        cmd->iov_size = le32_to_cpu(cmd->request.scsi_io.data_length);
        trace_mpt_handle_scsi("SCSI IO", 0,
                              cmd->request.scsi_io.target_id,
                              cmd->request.scsi_io.lun[1], sdev, cmd->iov_size);
        if (sdev) {
            uint32_t chain_offset = cmd->request.scsi_io.chain_offset;
            int32_t len;
            bool is_write;

            if (chain_offset) {
                chain_offset = chain_offset * sizeof(uint32_t) -
                    sizeof(MptSCSIIORequest);
            }

            mpt_map_sgl(s, cmd, cmd->host_msg_frame_pa +
                        sizeof(MptSCSIIORequest), chain_offset);
            is_write = MPT_SCSIIO_REQUEST_CONTROL_TXDIR_GET(
                cmd->request.scsi_io.control) ==
                MPT_SCSIIO_REQUEST_CONTROL_TXDIR_WRITE ?
                true : false;
            uint32_t i;
            for (i = 0; i < MPT_MAX_CMDS; i++) {
                if (s->cmds[i] == 0) {
                    s->cmds[i] = cmd;
                    cmd->index = i;
                    break;
                }
            }
            assert(i < MPT_MAX_CMDS);
            cmd->state = s;
            cmd->req = scsi_req_new(sdev, cmd->index,
                                    cmd->request.scsi_io.lun[1],
                                    cmd->request.scsi_io.cdb, cmd);
            len = scsi_req_enqueue(cmd->req);
            if (len < 0) {
                len = -len;
            }
            if (len > 0) {
                if (len > cmd->iov_size) {
                    if (is_write) {
                        trace_mpt_iov_write_overflow(cmd->index, len,
                                                     cmd->iov_size);
                    } else {
                        trace_mpt_iov_read_overflow(cmd->index, len,
                                                    cmd->iov_size);
                    }
                }
                if (len < cmd->iov_size) {
                    if (is_write) {
                        trace_mpt_iov_write_underflow(cmd->index, len,
                                                      cmd->iov_size);
                    } else {
                        trace_mpt_iov_read_underflow(cmd->index, len,
                                                     cmd->iov_size);
                    }
                    cmd->iov_size = len;
                }
                if (is_write) {
                    trace_mpt_scsi_write_start(cmd->index, len);
                } else {
                    trace_mpt_scsi_read_start(cmd->index, len);
                }
                scsi_req_continue(cmd->req);
            } else {
                trace_mpt_scsi_nodata(cmd->index);
            }
            return 0;
        } else {
            cmd->reply.scsi_io_error.ioc_status =
                MPT_SCSI_IO_ERROR_IOCSTATUS_DEVICE_NOT_THERE;
        }
    } else {
        if (cmd->request.scsi_io.bus != 0) {
            cmd->reply.scsi_io_error.ioc_status =
                MPT_SCSI_IO_ERROR_IOCSTATUS_INVALID_BUS;
        } else {
            cmd->reply.scsi_io_error.ioc_status =
                MPT_SCSI_IO_ERROR_IOCSTATUS_INVALID_TARGETID;
        }
    }
    cmd->reply.scsi_io_error.target_id = cmd->request.scsi_io.target_id;
    cmd->reply.scsi_io_error.bus = cmd->request.scsi_io.bus;
    cmd->reply.scsi_io_error.message_length = sizeof(MptSCSIIOErrorReply) / 4;
    cmd->reply.scsi_io_error.function = cmd->request.scsi_io.function;
    cmd->reply.scsi_io_error.cdb_length = cmd->request.scsi_io.cdb_length;
    cmd->reply.scsi_io_error.sense_buffer_length =
        cmd->request.scsi_io.sense_buffer_length;
    cmd->reply.scsi_io_error.message_context =
        cmd->request.scsi_io.message_context;
    cmd->reply.scsi_io_error.scsi_status = GOOD;
    cmd->reply.scsi_io_error.scsi_state =
        MPT_SCSI_IO_ERROR_SCSI_STATE_TERMINATED;
    cmd->reply.scsi_io_error.ioc_log_info = 0;
    cmd->reply.scsi_io_error.transfer_count = 0;
    cmd->reply.scsi_io_error.sense_count = 0;
    cmd->reply.scsi_io_error.response_info = 0;

    mpt_finish_address_reply(s, &cmd->reply, false);
    g_free(cmd);

    return 0;
}

static void mpt_process_message(MptState *s, MptMessageHdr *msg,
                                MptReplyUnion *reply);

static bool mpt_queue_consumer(MptState *s)
{
    /* Only process request which arrived before we
       received the notification. */
    uint32_t request_queue_next_entry_write =
        s->request_queue_next_entry_free_write;

    /* Go through the messages now and process them. */
    while ((s->state == MPTSTATE_OPERATIONAL)
           && (s->request_queue_next_address_read !=
               request_queue_next_entry_write)) {
        uint32_t request_message_frame_desc =
            s->request_queue[s->request_queue_next_address_read];
        MptRequestUnion request;
        hwaddr host_msg_frame_pa;

        host_msg_frame_pa = ((uint64_t)s->host_mfa_high_addr) << 32 |
            (request_message_frame_desc & ~0x03);

        /* Read the message header from the guest first. */
        cpu_physical_memory_read(host_msg_frame_pa, &request.header,
                                 sizeof(MptMessageHdr));

        /* Determine the size of the request. */
        uint32_t cb_request = 0;

        switch (request.header.function) {
        case MPT_MESSAGE_HDR_FUNCTION_SCSI_IO_REQUEST:
            cb_request = sizeof(MptSCSIIORequest);
            break;
        case MPT_MESSAGE_HDR_FUNCTION_SCSI_TASK_MGMT:
            cb_request = sizeof(MptSCSITaskManagementRequest);
            break;
        case MPT_MESSAGE_HDR_FUNCTION_IOC_INIT:
            cb_request = sizeof(MptIOCInitRequest);
            break;
        case MPT_MESSAGE_HDR_FUNCTION_IOC_FACTS:
            cb_request = sizeof(MptIOCFactsRequest);
            break;
        case MPT_MESSAGE_HDR_FUNCTION_CONFIG:
            cb_request = sizeof(MptConfigurationRequest);
            break;
        case MPT_MESSAGE_HDR_FUNCTION_PORT_FACTS:
            cb_request = sizeof(MptPortFactsRequest);
            break;
        case MPT_MESSAGE_HDR_FUNCTION_PORT_ENABLE:
            cb_request = sizeof(MptPortEnableRequest);
            break;
        case MPT_MESSAGE_HDR_FUNCTION_EVENT_NOTIFICATION:
            cb_request = sizeof(MptEventNotificationRequest);
            break;
        case MPT_MESSAGE_HDR_FUNCTION_FW_DOWNLOAD:
            cb_request = sizeof(MptFWDownloadRequest);
            break;
        case MPT_MESSAGE_HDR_FUNCTION_FW_UPLOAD:
            cb_request = sizeof(MptFWUploadRequest);
            break;
        case MPT_MESSAGE_HDR_FUNCTION_EVENT_ACK:
        default:
            if (s->state != MPTSTATE_FAULT) {
                s->ioc_fault_code = MPT_IOCSTATUS_INVALID_FUNCTION;
                s->state = MPTSTATE_FAULT;
            }
        }

        if (cb_request != 0) {
            /* Handle SCSI I/O requests seperately. */
            if (request.header.function ==
                MPT_MESSAGE_HDR_FUNCTION_SCSI_IO_REQUEST) {
                MptCmd *cmd = g_malloc0(sizeof(MptCmd));
                cpu_physical_memory_read(host_msg_frame_pa,
                                         &cmd->request.header, cb_request);
                cmd->host_msg_frame_pa = host_msg_frame_pa;
                mpt_process_scsi_io_Request(s, cmd);
            } else {
                MptReplyUnion Reply;
                cpu_physical_memory_read(host_msg_frame_pa, &request.header,
                                         cb_request);
                mpt_process_message(s, &request.header, &Reply);
            }
        }
        s->request_queue_next_address_read++;
        s->request_queue_next_address_read %= s->request_queue_entries;
    }

    return true;
}


static int mpt_hard_reset(MptState *s);

static int mpt_config_unit_page(MptState *p_lsi_logic,
                                PMptConfigurationPagesSupported p_pages,
                                uint8_t page_number,
                                PMptConfigurationPageHeader *pp_page_header,
                                uint8_t **pp_page_data, size_t *p_cb_page)
{
    int rc = 0;

    switch (page_number) {
    case 0:
        *pp_page_header = &p_pages->io_unit_page_0.u.fields.header;
        *pp_page_data = p_pages->io_unit_page_0.u.page_data;
        *p_cb_page = sizeof(p_pages->io_unit_page_0);
        break;
    case 1:
        *pp_page_header = &p_pages->io_unit_page_1.u.fields.header;
        *pp_page_data = p_pages->io_unit_page_1.u.page_data;
        *p_cb_page = sizeof(p_pages->io_unit_page_1);
        break;
    case 2:
        *pp_page_header = &p_pages->io_unit_page_2.u.fields.header;
        *pp_page_data = p_pages->io_unit_page_2.u.page_data;
        *p_cb_page = sizeof(p_pages->io_unit_page_2);
        break;
    case 3:
        *pp_page_header = &p_pages->io_unit_page_3.u.fields.header;
        *pp_page_data = p_pages->io_unit_page_3.u.page_data;
        *p_cb_page = sizeof(p_pages->io_unit_page_3);
        break;
    case 4:
        *pp_page_header = &p_pages->io_unit_page_4.u.fields.header;
        *pp_page_data = p_pages->io_unit_page_4.u.page_data;
        *p_cb_page = sizeof(p_pages->io_unit_page_4);
        break;
    default:
        rc = -1;
    }

    return rc;
}

static int mpt_config_ioc_page(MptState *p_lsi_logic,
                               PMptConfigurationPagesSupported p_pages,
                               uint8_t page_number,
                               PMptConfigurationPageHeader *pp_page_header,
                               uint8_t **pp_page_data, size_t *p_cb_page)
{
    int rc = 0;

    switch (page_number) {
    case 0:
        *pp_page_header = &p_pages->ioc_page_0.u.fields.header;
        *pp_page_data = p_pages->ioc_page_0.u.page_data;
        *p_cb_page = sizeof(p_pages->ioc_page_0);
        break;
    case 1:
        *pp_page_header = &p_pages->ioc_page_1.u.fields.header;
        *pp_page_data = p_pages->ioc_page_1.u.page_data;
        *p_cb_page = sizeof(p_pages->ioc_page_1);
        break;
    case 2:
        *pp_page_header = &p_pages->ioc_page_2.u.fields.header;
        *pp_page_data = p_pages->ioc_page_2.u.page_data;
        *p_cb_page = sizeof(p_pages->ioc_page_2);
        break;
    case 3:
        *pp_page_header = &p_pages->ioc_page_3.u.fields.header;
        *pp_page_data = p_pages->ioc_page_3.u.page_data;
        *p_cb_page = sizeof(p_pages->ioc_page_3);
        break;
    case 4:
        *pp_page_header = &p_pages->ioc_page_4.u.fields.header;
        *pp_page_data = p_pages->ioc_page_4.u.page_data;
        *p_cb_page = sizeof(p_pages->ioc_page_4);
        break;
    case 6:
        *pp_page_header = &p_pages->ioc_page_6.u.fields.header;
        *pp_page_data = p_pages->ioc_page_6.u.page_data;
        *p_cb_page = sizeof(p_pages->ioc_page_6);
        break;
    default:
        rc = -1;
    }

    return rc;
}

static int mpt_config_manufacturing_page(
    MptState *p_lsi_logic,
    PMptConfigurationPagesSupported p_pages,
    uint8_t page_number,
    PMptConfigurationPageHeader *pp_page_header,
    uint8_t **pp_page_data, size_t *p_cb_page)
{
    int rc = 0;

    switch (page_number) {
    case 0:
        *pp_page_header = &p_pages->manufacturing_page_0.u.fields.header;
        *pp_page_data = p_pages->manufacturing_page_0.u.page_data;
        *p_cb_page = sizeof(p_pages->manufacturing_page_0);
        break;
    case 1:
        *pp_page_header = &p_pages->manufacturing_page_1.u.fields.header;
        *pp_page_data = p_pages->manufacturing_page_1.u.page_data;
        *p_cb_page = sizeof(p_pages->manufacturing_page_1);
        break;
    case 2:
        *pp_page_header = &p_pages->manufacturing_page_2.u.fields.header;
        *pp_page_data = p_pages->manufacturing_page_2.u.page_data;
        *p_cb_page = sizeof(p_pages->manufacturing_page_2);
        break;
    case 3:
        *pp_page_header = &p_pages->manufacturing_page_3.u.fields.header;
        *pp_page_data = p_pages->manufacturing_page_3.u.page_data;
        *p_cb_page = sizeof(p_pages->manufacturing_page_3);
        break;
    case 4:
        *pp_page_header = &p_pages->manufacturing_page_4.u.fields.header;
        *pp_page_data = p_pages->manufacturing_page_4.u.page_data;
        *p_cb_page = sizeof(p_pages->manufacturing_page_4);
        break;
    case 5:
        *pp_page_header = &p_pages->manufacturing_page_5.u.fields.header;
        *pp_page_data = p_pages->manufacturing_page_5.u.page_data;
        *p_cb_page = sizeof(p_pages->manufacturing_page_5);
        break;
    case 6:
        *pp_page_header = &p_pages->manufacturing_page_6.u.fields.header;
        *pp_page_data = p_pages->manufacturing_page_6.u.page_data;
        *p_cb_page = sizeof(p_pages->manufacturing_page_6);
        break;
    case 7:
        if (p_lsi_logic->ctrl_type == MPTCTRLTYPE_SCSI_SAS) {
            *pp_page_header = &p_pages->u.sas_pages.p_manufacturing_page_7->
                u.fields.header;
            *pp_page_data = p_pages->u.sas_pages.p_manufacturing_page_7->
                u.page_data;
            *p_cb_page = p_pages->u.sas_pages.cb_manufacturing_page_7;
        } else {
            rc = -1;
        }
        break;
    case 8:
        *pp_page_header = &p_pages->manufacturing_page_8.u.fields.header;
        *pp_page_data = p_pages->manufacturing_page_8.u.page_data;
        *p_cb_page = sizeof(p_pages->manufacturing_page_8);
        break;
    case 9:
        *pp_page_header = &p_pages->manufacturing_page_9.u.fields.header;
        *pp_page_data = p_pages->manufacturing_page_9.u.page_data;
        *p_cb_page = sizeof(p_pages->manufacturing_page_9);
        break;
    case 10:
        *pp_page_header = &p_pages->manufacturing_page_10.u.fields.header;
        *pp_page_data = p_pages->manufacturing_page_10.u.page_data;
        *p_cb_page = sizeof(p_pages->manufacturing_page_10);
        break;
    default:
        rc = -1;
    }

    return rc;
}

static int mpt_config_bios_page(MptState *p_lsi_logic,
                                PMptConfigurationPagesSupported p_pages,
                                uint8_t page_number,
                                PMptConfigurationPageHeader *pp_page_header,
                                uint8_t **pp_page_data, size_t *p_cb_page)
{
    int rc = 0;

    switch (page_number) {
    case 1:
        *pp_page_header = &p_pages->bios_page_1.u.fields.header;
        *pp_page_data = p_pages->bios_page_1.u.page_data;
        *p_cb_page = sizeof(p_pages->bios_page_1);
        break;
    case 2:
        *pp_page_header = &p_pages->bios_page_2.u.fields.header;
        *pp_page_data = p_pages->bios_page_2.u.page_data;
        *p_cb_page = sizeof(p_pages->bios_page_2);
        break;
    case 4:
        *pp_page_header = &p_pages->bios_page_4.u.fields.header;
        *pp_page_data = p_pages->bios_page_4.u.page_data;
        *p_cb_page = sizeof(p_pages->bios_page_4);
        break;
    default:
        rc = -1;
    }

    return rc;
}

static int mpt_config_scsi_spi_port_page(
    MptState *p_lsi_logic,
    PMptConfigurationPagesSupported p_pages,
    uint8_t port,
    uint8_t page_number,
    PMptConfigurationPageHeader *pp_page_header,
    uint8_t **pp_page_data, size_t *p_cb_page)
{
    int rc = 0;
    MptConfigurationPageSCSISPIPort0 *p_page_0;
    MptConfigurationPageSCSISPIPort1 *p_page_1;
    MptConfigurationPageSCSISPIPort2 *p_page_2;

    if (port >= ARRAY_SIZE(p_pages->u.spi_pages.port_pages)) {
        return -1;
    }

    p_page_0 = &p_pages->u.spi_pages.port_pages[port].scsi_spi_port_page_0;
    p_page_1 = &p_pages->u.spi_pages.port_pages[port].scsi_spi_port_page_1;
    p_page_2 = &p_pages->u.spi_pages.port_pages[port].scsi_spi_port_page_2;

    switch (page_number) {
    case 0:
        *pp_page_header = &p_page_0->u.fields.header;
        *pp_page_data = p_page_0->u.page_data;
        *p_cb_page = sizeof(*p_page_0);
        break;
    case 1:
        *pp_page_header = &p_page_1->u.fields.header;
        *pp_page_data = p_page_1->u.page_data;
        *p_cb_page = sizeof(*p_page_1);
        break;
    case 2:
        *pp_page_header = &p_page_2->u.fields.header;
        *pp_page_data = p_page_2->u.page_data;
        *p_cb_page = sizeof(*p_page_2);
        break;
    default:
        rc = -1;
    }

    return rc;
}

static int mpt_config_scsi_spi_dev_page(
    MptState *p_lsi_logic,
    PMptConfigurationPagesSupported p_pages,
    uint8_t bus,
    uint8_t tgt_id, uint8_t page_number,
    PMptConfigurationPageHeader *pp_page_header,
    uint8_t **pp_page_data, size_t *p_cb_page)
{
    int rc = 0;
    MptConfigurationPageSCSISPIDevice0 *p_page_0;
    MptConfigurationPageSCSISPIDevice1 *p_page_1;
    MptConfigurationPageSCSISPIDevice2 *p_page_2;
    MptConfigurationPageSCSISPIDevice3 *p_page_3;

    if (bus >= ARRAY_SIZE(p_pages->u.spi_pages.buses)) {
        return -1;
    }

    if (tgt_id >= ARRAY_SIZE(p_pages->u.spi_pages.buses[bus].dev_pages)) {
        return -1;
    }

    p_page_0 =
        &p_pages->u.spi_pages.buses[bus].dev_pages[tgt_id].scsi_spi_dev_page0;
    p_page_1 =
        &p_pages->u.spi_pages.buses[bus].dev_pages[tgt_id].scsi_spi_dev_page1;
    p_page_2 =
        &p_pages->u.spi_pages.buses[bus].dev_pages[tgt_id].scsi_spi_dev_page2;
    p_page_3 =
        &p_pages->u.spi_pages.buses[bus].dev_pages[tgt_id].scsi_spi_dev_page3;

    switch (page_number) {
    case 0:
        *pp_page_header = &p_page_0->u.fields.header;
        *pp_page_data = p_page_0->u.page_data;
        *p_cb_page = sizeof(*p_page_0);
        break;
    case 1:
        *pp_page_header = &p_page_1->u.fields.header;
        *pp_page_data = p_page_1->u.page_data;
        *p_cb_page = sizeof(*p_page_1);
        break;
    case 2:
        *pp_page_header = &p_page_2->u.fields.header;
        *pp_page_data = p_page_2->u.page_data;
        *p_cb_page = sizeof(*p_page_2);
        break;
    case 3:
        *pp_page_header = &p_page_3->u.fields.header;
        *pp_page_data = p_page_3->u.page_data;
        *p_cb_page = sizeof(*p_page_3);
        break;
    default:
        rc = -1;
    }

    return rc;
}

static int mpt_config_sas_unit(
    MptState *p_lsi_logic,
    PMptConfigurationPagesSupported p_pages,
    uint8_t page_number,
    PMptExtendedConfigurationPageHeader *pp_page_header,
    uint8_t **pp_page_data, size_t *p_cb_page)
{
    int rc = 0;
    PMptConfigurationPageSASIOUnit0 p_page_0 =
        p_pages->u.sas_pages.p_sas_io_unit_page_0;
    PMptConfigurationPageSASIOUnit1 p_page_1 =
        p_pages->u.sas_pages.p_sas_io_unit_page_1;
    MptConfigurationPageSASIOUnit2 *p_page_2 =
        &p_pages->u.sas_pages.sas_io_unit_page_2;
    MptConfigurationPageSASIOUnit3 *p_page_3 =
        &p_pages->u.sas_pages.sas_io_unit_page_3;

    switch (page_number) {
    case 0:
        *pp_page_header = &p_page_0->u.fields.ext_hdr;
        *pp_page_data = p_page_0->u.page_data;
        *p_cb_page = p_pages->u.sas_pages.cb_sas_io_unit_page_0;
        break;
    case 1:
        *pp_page_header = &p_page_1->u.fields.ext_hdr;
        *pp_page_data = p_page_1->u.page_data;
        *p_cb_page = p_pages->u.sas_pages.cb_sas_io_unit_page_1;
        break;
    case 2:
        *pp_page_header = &p_page_2->u.fields.ext_hdr;
        *pp_page_data = p_page_2->u.page_data;
        *p_cb_page = sizeof(*p_page_2);
        break;
    case 3:
        *pp_page_header = &p_page_3->u.fields.ext_hdr;
        *pp_page_data = p_page_3->u.page_data;
        *p_cb_page = sizeof(*p_page_3);
        break;
    default:
        rc = -1;
    }

    return rc;
}

static int mpt_config_sas_phy(
    MptState *p_lsi_logic,
    PMptConfigurationPagesSupported p_pages,
    uint8_t page_number,
    MptConfigurationPageAddress page_address,
    PMptExtendedConfigurationPageHeader *pp_page_header,
    uint8_t **pp_page_data, size_t *p_cb_page)
{
    int rc = 0;
    uint8_t uAddressForm =
        MPT_CONFIGURATION_PAGE_ADDRESS_GET_SAS_FORM(page_address);
    PMptConfigurationPagesSas p_pagesSas = &p_pages->u.sas_pages;
    PMptPHY p_phy_pages = NULL;


    if (uAddressForm == 0) { /* PHY number */
        uint8_t phy_number = page_address.sas_phy.Form0.phy_number;

        if (phy_number >= p_pagesSas->c_phy_s) {
            return -1;
        }

        p_phy_pages = &p_pagesSas->pa_phy_s[phy_number];
    } else if (uAddressForm == 1) { /* Index form */
        uint16_t index = page_address.sas_phy.form1.index;

        if (index >= p_pagesSas->c_phy_s) {
            return -1;
        }

        p_phy_pages = &p_pagesSas->pa_phy_s[index];
    } else {
        rc = -1; /* Correct? */
    }

    if (p_phy_pages) {
        switch (page_number) {
        case 0:
            *pp_page_header = &p_phy_pages->sas_phy_page_0.u.fields.ext_hdr;
            *pp_page_data = p_phy_pages->sas_phy_page_0.u.page_data;
            *p_cb_page = sizeof(p_phy_pages->sas_phy_page_0);
            break;
        case 1:
            *pp_page_header = &p_phy_pages->sas_phy_page_1.u.fields.ext_hdr;
            *pp_page_data = p_phy_pages->sas_phy_page_1.u.page_data;
            *p_cb_page = sizeof(p_phy_pages->sas_phy_page_1);
            break;
        default:
            rc = -1;
        }
    } else {
        rc = -1;
    }

    return rc;
}

static int mpt_config_sas_device(
    MptState *p_lsi_logic,
    PMptConfigurationPagesSupported p_pages,
    uint8_t page_number,
    MptConfigurationPageAddress page_address,
    PMptExtendedConfigurationPageHeader *pp_page_header,
    uint8_t **pp_page_data, size_t *p_cb_page)
{
    int rc = 0;
    uint8_t address_form =
        MPT_CONFIGURATION_PAGE_ADDRESS_GET_SAS_FORM(page_address);
    PMptConfigurationPagesSas p_pagesSas = &p_pages->u.sas_pages;
    PMptSASDevice p_sas_device = NULL;

    if (address_form == 0) {
        uint16_t handle = page_address.sas_device.form0_and2.handle;

        p_sas_device = p_pagesSas->p_sas_device_head;

        /* Get the first device? */
        if (handle != 0xffff) {
            /* No, search for the right one. */

            while (p_sas_device
                   && p_sas_device->sas_dev_page0.u.fields.dev_handle !=
                   handle) {
                p_sas_device = p_sas_device->p_next;
            }

            if (p_sas_device) {
                p_sas_device = p_sas_device->p_next;
            }
        }
    } else if (address_form == 1) {
        uint8_t tgt_id = page_address.sas_device.form1.target_id;
        uint8_t bus = page_address.sas_device.form1.bus;

        p_sas_device = p_pagesSas->p_sas_device_head;

        while (p_sas_device
               && (p_sas_device->sas_dev_page0.u.fields.target_id != tgt_id
                   || p_sas_device->sas_dev_page0.u.fields.bus != bus))
            p_sas_device = p_sas_device->p_next;
    } else if (address_form == 2) {
        uint16_t handle = page_address.sas_device.form0_and2.handle;

        p_sas_device = p_pagesSas->p_sas_device_head;

        while (p_sas_device
               && p_sas_device->sas_dev_page0.u.fields.dev_handle != handle) {
            p_sas_device = p_sas_device->p_next;
        }
    }

    if (p_sas_device) {
        switch (page_number) {
        case 0:
            *pp_page_header = &p_sas_device->sas_dev_page0.u.fields.ext_hdr;
            *pp_page_data = p_sas_device->sas_dev_page0.u.page_data;
            *p_cb_page = sizeof(p_sas_device->sas_dev_page0);
            break;
        case 1:
            *pp_page_header = &p_sas_device->sas_dev_page1.u.fields.ext_hdr;
            *pp_page_data = p_sas_device->sas_dev_page1.u.page_data;
            *p_cb_page = sizeof(p_sas_device->sas_dev_page1);
            break;
        case 2:
            *pp_page_header = &p_sas_device->sas_dev_page2.u.fields.ext_hdr;
            *pp_page_data = p_sas_device->sas_dev_page2.u.page_data;
            *p_cb_page = sizeof(p_sas_device->sas_dev_page2);
            break;
        default:
            rc = -1;
        }
    } else {
        rc = -1;
    }

    return rc;
}

static int mpt_config_page_get_extended(
    MptState *p_lsi_logic,
    PMptConfigurationRequest pConfigurationReq,
    PMptExtendedConfigurationPageHeader *pp_page_header,
    uint8_t **pp_page_data, size_t *p_cb_page)
{
    int rc = 0;

    switch (pConfigurationReq->ext_page_type) {
    case MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASIOUNIT:
    {
        rc = mpt_config_sas_unit(p_lsi_logic,
                                 p_lsi_logic->config_pages,
                                 pConfigurationReq->page_number,
                                 pp_page_header, pp_page_data, p_cb_page);
        break;
    }
    case MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASPHYS:
    {
        rc = mpt_config_sas_phy(p_lsi_logic,
                                p_lsi_logic->config_pages,
                                pConfigurationReq->page_number,
                                pConfigurationReq->page_address,
                                pp_page_header, pp_page_data, p_cb_page);
        break;
    }
    case MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASDEVICE:
    {
        rc = mpt_config_sas_device(p_lsi_logic,
                                   p_lsi_logic->config_pages,
                                   pConfigurationReq->page_number,
                                   pConfigurationReq->page_address,
                                   pp_page_header, pp_page_data, p_cb_page);
        break;
    }
    case MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASEXPANDER:
        /* No expanders supported */
    case MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_LOG:
        /* No log supported */
    case MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_ENCLOSURE:
        /* No enclosures supported */
    default:
        rc = -1;
    }

    return rc;
}


static int mpt_process_config_req(MptState *s,
                                  MptConfigurationRequest *config_req,
                                  MptConfigurationReply *reply)
{
    int rc = 0;
    uint8_t                            *pbPageData = NULL;
    PMptConfigurationPageHeader         pPageHeader = NULL;
    PMptExtendedConfigurationPageHeader pExtPageHeader = NULL;
    size_t                              cbPage = 0;


    /* Copy common bits from the request into the reply. */
    reply->message_length = 6; /* 6 32bit D-Words. */
    reply->action = config_req->action;
    reply->function = config_req->function;
    reply->message_context = config_req->message_context;

    switch (MPT_CONFIGURATION_PAGE_TYPE_GET(config_req->page_type)) {
    case MPT_CONFIGURATION_PAGE_TYPE_IO_UNIT:
    {
        rc = mpt_config_unit_page(s, s->config_pages,
                                  config_req->page_number,
                                  &pPageHeader, &pbPageData, &cbPage);
        break;
    }
    case MPT_CONFIGURATION_PAGE_TYPE_IOC:
    {
        /* Get the page data. */
        rc = mpt_config_ioc_page(s, s->config_pages,
                                 config_req->page_number,
                                 &pPageHeader, &pbPageData, &cbPage);
        break;
    }
    case MPT_CONFIGURATION_PAGE_TYPE_MANUFACTURING:
    {
        rc = mpt_config_manufacturing_page(s, s->config_pages,
                                           config_req->page_number,
                                           &pPageHeader, &pbPageData,
                                           &cbPage);
        break;
    }
    case MPT_CONFIGURATION_PAGE_TYPE_SCSI_SPI_PORT:
    {
        rc = mpt_config_scsi_spi_port_page(
            s, s->config_pages,
            config_req->page_address.mpi_port_number.port_number,
            config_req->page_number,
            &pPageHeader, &pbPageData, &cbPage);
        break;
    }
    case MPT_CONFIGURATION_PAGE_TYPE_SCSI_SPI_DEVICE:
    {
        rc = mpt_config_scsi_spi_dev_page(
            s, s->config_pages,
            config_req->page_address.bus_and_target_id.bus,
            config_req->page_address.bus_and_target_id.target_id,
            config_req->page_number,
            &pPageHeader, &pbPageData, &cbPage);
        break;
    }
    case MPT_CONFIGURATION_PAGE_TYPE_BIOS:
    {
        rc = mpt_config_bios_page(s, s->config_pages,
                                  config_req->page_number,
                                  &pPageHeader, &pbPageData, &cbPage);
        break;
    }
    case MPT_CONFIGURATION_PAGE_TYPE_EXTENDED:
    {
        rc = mpt_config_page_get_extended(s, config_req, &pExtPageHeader,
                                          &pbPageData, &cbPage);
        break;
    }
    default:
        rc = -1;
    }

    if (rc == -1) {
        reply->page_type = config_req->page_type;
        reply->page_number = config_req->page_number;
        reply->page_length = config_req->page_length;
        reply->page_version = config_req->page_version;
        reply->ioc_status = MPT_IOCSTATUS_CONFIG_INVALID_PAGE;
        return 0;
    }

    if (MPT_CONFIGURATION_PAGE_TYPE_GET(config_req->page_type) ==
        MPT_CONFIGURATION_PAGE_TYPE_EXTENDED) {
        reply->page_type = pExtPageHeader->page_type;
        reply->page_number = pExtPageHeader->page_number;
        reply->page_version = pExtPageHeader->page_version;
        reply->ext_page_type = pExtPageHeader->ext_page_type;
        reply->ext_page_len = pExtPageHeader->ext_page_len;
    } else {
        reply->page_type = pPageHeader->page_type;
        reply->page_number = pPageHeader->page_number;
        reply->page_length = pPageHeader->page_length;
        reply->page_version = pPageHeader->page_version;
    }

    /*
     * Don't use the scatter gather handling code as the configuration
     * request always have only one simple element.
     */
    switch (config_req->action) {
    case MPT_CONFIGURATION_REQUEST_ACTION_DEFAULT:
        /* Nothing to do. We are always using the defaults. */
    case MPT_CONFIGURATION_REQUEST_ACTION_HEADER:
    {
        /* Already copied above nothing to do. */
        break;
    }
    case MPT_CONFIGURATION_REQUEST_ACTION_READ_NVRAM:
    case MPT_CONFIGURATION_REQUEST_ACTION_READ_CURRENT:
    case MPT_CONFIGURATION_REQUEST_ACTION_READ_DEFAULT:
    {
        uint32_t cbBuffer = config_req->simple_sge.length;
        if (cbBuffer != 0) {
            uint64_t page_buffer_pa = config_req->simple_sge.data_buf_addr_low;
            if (config_req->simple_sge.bit_address) {
                page_buffer_pa |=
                    (uint64_t)config_req->simple_sge.data_buf_addr_high << 32;
            }

            cpu_physical_memory_write(page_buffer_pa, pbPageData,
                                      MIN(cbBuffer, cbPage));
        }
        break;
    }
    case MPT_CONFIGURATION_REQUEST_ACTION_WRITE_CURRENT:
    case MPT_CONFIGURATION_REQUEST_ACTION_WRITE_NVRAM:
    {
        uint32_t cbBuffer = config_req->simple_sge.length;
        if (cbBuffer != 0) {
            uint64_t page_buffer_pa = config_req->simple_sge.data_buf_addr_low;
            if (config_req->simple_sge.bit_address) {
                page_buffer_pa |=
                    (uint64_t)config_req->simple_sge.data_buf_addr_high << 32;
            }
            cpu_physical_memory_read(page_buffer_pa, pbPageData,
                                     MIN(cbBuffer, cbPage));
        }
        break;
    }
    default:
        break;
    }

    return 0;
}

static const char *mpt_msg_desc[] = {
    "SCSI_IO_REQUEST",
    "SCSI_TASK_MGMT",
    "IOC_INIT",
    "IOC_FACTS",
    "CONFIG",
    "PORT_FACTS",
    "PORT_ENABLE",
    "EVENT_NOTIFICATION",
    "EVENT_ACK",
    "FW_DOWNLOAD",
    "TARGET_CMD_BUFFER_POST",
    "TARGET_ASSIST",
    "TARGET_STATUS_SEND",
    "TARGET_MODE_ABORT",
    "UNDEFINED",
    "UNDEFINED",
    "UNDEFINED",
    "UNDEFINED",
    "FW_UPLOAD"
};

static void mpt_process_message(MptState *s, MptMessageHdr *msg,
                                MptReplyUnion *reply)
{
    bool fForceReplyPostFifo = false;

    memset(reply, 0, sizeof(MptReplyUnion));

    trace_mpt_process_message(mpt_msg_desc[msg->function]);
    switch (msg->function) {
    case MPT_MESSAGE_HDR_FUNCTION_SCSI_TASK_MGMT:
    {
        PMptSCSITaskManagementRequest p_task_mgmt_req =
            (PMptSCSITaskManagementRequest)msg;

        reply->scsi_task_management.message_length = 6;
        reply->scsi_task_management.task_type =
            p_task_mgmt_req->task_type;
        reply->scsi_task_management.termination_count = 0;
        fForceReplyPostFifo = true;
        break;
    }

    case MPT_MESSAGE_HDR_FUNCTION_IOC_INIT:
    {
        /* This request sets the I/O contr to the operational state. */
        PMptIOCInitRequest p_ioc_init_req = (PMptIOCInitRequest)msg;

        /* Update configuration values. */
        s->who_init = (MPTWHOINIT)p_ioc_init_req->who_init;
        s->reply_frame_size = p_ioc_init_req->reply_frame_size;
        s->max_buses = p_ioc_init_req->max_buses;
        s->max_devices = p_ioc_init_req->max_devices;
        s->host_mfa_high_addr = p_ioc_init_req->host_mfa_high_addr;
        s->sense_buffer_high_addr = p_ioc_init_req->sense_buffer_high_addr;

        if (s->state == MPTSTATE_READY) {
            s->state = MPTSTATE_OPERATIONAL;
        }

        /* Return reply. */
        reply->ioc_init.message_length = 5;
        reply->ioc_init.who_init = s->who_init;
        reply->ioc_init.max_devices = s->max_devices;
        reply->ioc_init.max_buses = s->max_buses;
        break;
    }
    case MPT_MESSAGE_HDR_FUNCTION_IOC_FACTS:
    {
        reply->ioc_facts.message_length = 15; /* 15 32bit dwords. */

        if (s->ctrl_type == MPTCTRLTYPE_SCSI_SPI) {
            /* Version from the specification. */
            reply->ioc_facts.message_version = 0x0102;
        } else if (s->ctrl_type == MPTCTRLTYPE_SCSI_SAS) {
            /* Version from the specification. */
            reply->ioc_facts.message_version = 0x0105;
        }

        reply->ioc_facts.number_of_ports = s->ports;
        /* PCI function number. */
        reply->ioc_facts.ioc_number = 0;
        reply->ioc_facts.ioc_exceptions = 0;
        reply->ioc_facts.max_chain_depth = MPTSCSI_MAXIMUM_CHAIN_DEPTH;
        reply->ioc_facts.who_init = s->who_init;
        /* Block size in 32bit dwords. This is the largest request
           we can get (SCSI I/O). */
        reply->ioc_facts.block_size = 12;
        /* Bit 0 is set if the guest must upload the FW prior to using
           the controller. Obviously not needed here. */
        reply->ioc_facts.flags = 0;
        /* One entry is always free. */
        reply->ioc_facts.reply_queue_depth = s->reply_queue_entries - 1;
        reply->ioc_facts.request_frame_size = 128;
        /* Our own product ID :) */
        reply->ioc_facts.product_id = 0x2704;
        reply->ioc_facts.current_host_mfa_high_addr = s->host_mfa_high_addr;
        /* One entry is always free. */
        reply->ioc_facts.global_credits = s->request_queue_entries - 1;

        /* Event notifications not enabled. */
        reply->ioc_facts.event_state = 0;
        reply->ioc_facts.current_sense_buffer_high_addr =
            s->sense_buffer_high_addr;
        reply->ioc_facts.cur_reply_frame_size = s->reply_frame_size;
        reply->ioc_facts.max_devices = s->max_devices;
        reply->ioc_facts.max_buses = s->max_buses;
        reply->ioc_facts.fw_image_size = 0;
        reply->ioc_facts.fw_version = 0x1329200;
        break;
    }
    case MPT_MESSAGE_HDR_FUNCTION_PORT_FACTS:
    {
        PMptPortFactsRequest pport_factsReq = (PMptPortFactsRequest)msg;

        reply->port_facts.message_length = 10;
        reply->port_facts.port_number = pport_factsReq->port_number;

        if (s->ctrl_type == MPTCTRLTYPE_SCSI_SPI) {
            /* This controller only supports one bus with bus number 0. */
            if (pport_factsReq->port_number >= s->ports) {
                reply->port_facts.port_type = 0; /* Not existant. */
            } else {
                reply->port_facts.port_type = 0x01; /* SCSI Port. */
                reply->port_facts.max_devices =
                    MPTSCSI_PCI_SPI_DEVICES_PER_BUS_MAX;
                /* SCSI initiator and LUN supported. */
                reply->port_facts.protocol_flags = (1 << 3) | (1 << 0);
                reply->port_facts.port_scsi_id = 7; /* Default */
                reply->port_facts.max_persistent_ids = 0;
                /* Only applies for target mode which we dont support. */
                reply->port_facts.max_posted_cmd_buffers = 0;
                /* Only for the LAN controller. */
                reply->port_facts.max_lan_buckets = 0;
            }
        } else if (s->ctrl_type == MPTCTRLTYPE_SCSI_SAS) {
            if (pport_factsReq->port_number >= s->ports) {
                reply->port_facts.port_type = 0; /* Not existant. */
            } else {
                reply->port_facts.port_type = 0x30; /* SAS Port. */
                reply->port_facts.max_devices = s->ports;
                /* SCSI initiator and LUN supported. */
                reply->port_facts.protocol_flags = (1 << 3) | (1 << 0);
                reply->port_facts.port_scsi_id = s->ports;
                reply->port_facts.max_persistent_ids = 0;
                /* Only applies for target mode which we dont support. */
                reply->port_facts.max_posted_cmd_buffers = 0;
                /* Only for the LAN controller. */
                reply->port_facts.max_lan_buckets = 0;
            }
        }
        break;
    }
    case MPT_MESSAGE_HDR_FUNCTION_PORT_ENABLE:
    {
        /*
         * The port enable request notifies the IOC to make the port
         * available and perform appropriate discovery on the associated
         * link.
         */
        PMptPortEnableRequest pport_enableReq = (PMptPortEnableRequest)msg;

        reply->port_enable.message_length = 5;
        reply->port_enable.port_number = pport_enableReq->port_number;
        break;
    }
    case MPT_MESSAGE_HDR_FUNCTION_EVENT_NOTIFICATION:
    {
        PMptEventNotificationRequest pevent_notificationReq =
            (PMptEventNotificationRequest)msg;

        if (pevent_notificationReq->event_switch) {
            s->event_notification_enabled = true;
        } else {
            s->event_notification_enabled = false;
        }

        reply->event_notification.event_data_length = 1; /* 32bit Word. */
        reply->event_notification.message_length = 8;
        reply->event_notification.message_flags = (1 << 7);
        reply->event_notification.ack_required = 0;
        reply->event_notification.event = MPT_EVENT_EVENT_CHANGE;
        reply->event_notification.event_context = 0;
        reply->event_notification.event_data =
            s->event_notification_enabled ? 1 : 0;

        break;
    }
    case MPT_MESSAGE_HDR_FUNCTION_EVENT_ACK:
    {
        break;
    }
    case MPT_MESSAGE_HDR_FUNCTION_CONFIG:
    {
        PMptConfigurationRequest config_req =
            (PMptConfigurationRequest)msg;

        mpt_process_config_req(s, config_req, &reply->configuration);
        break;
    }
    case MPT_MESSAGE_HDR_FUNCTION_FW_UPLOAD:
    {
        PMptFWUploadRequest p_fw_upload_req = (PMptFWUploadRequest)msg;
        hwaddr iov_pa = p_fw_upload_req->sge.data_buf_addr_low;
        void *ptr;

        reply->fw_upload.image_type = p_fw_upload_req->image_type;
        reply->fw_upload.message_length = 6;
        assert(p_fw_upload_req->image_type == MPI_FW_UPLOAD_ITYPE_BIOS_FLASH);
        assert(p_fw_upload_req->sge.element_type == MPTSGENTRYTYPE_SIMPLE);
        assert(p_fw_upload_req->sge.bit_address == 0);
        assert(p_fw_upload_req->sge.end_of_list);
        assert(p_fw_upload_req->sge.last_element);
        reply->fw_upload.actual_image_size = memory_region_size(&s->dev.rom);
        assert(reply->fw_upload.actual_image_size >=
               p_fw_upload_req->tc_sge.image_offset +
               p_fw_upload_req->sge.length);
        ptr = memory_region_get_ram_ptr(&s->dev.rom);
        cpu_physical_memory_write(
            iov_pa,
            (uint8_t *)ptr + p_fw_upload_req->tc_sge.image_offset,
            p_fw_upload_req->sge.length);
        qemu_put_ram_ptr(ptr);
        reply->fw_upload.actual_image_size = memory_region_size(&s->dev.rom);
        break;
    }
    case MPT_MESSAGE_HDR_FUNCTION_FW_DOWNLOAD:
    {

        reply->fw_download.message_length = 5;
        break;
    }
    case MPT_MESSAGE_HDR_FUNCTION_SCSI_IO_REQUEST:
        /* Should be handled already. */
    default:
        trace_mpt_unhandled_cmd(msg->function, 0);
    }

    /* Copy common bits from request message frame to reply. */
    reply->header.function = msg->function;
    reply->header.message_context = msg->message_context;

    mpt_finish_address_reply(s, reply, fForceReplyPostFifo);
}

static uint64_t mpt_mmio_read(void *opaque, hwaddr addr,
                              unsigned size)
{
    MptState *s = opaque;
    uint32_t retval = 0;

    switch (addr & ~3) {
    case MPT_REG_DOORBELL:
        retval = MPT_REG_DOORBELL_SET_STATE(s->state) |
            MPT_REG_DOORBELL_SET_USED(s->doorbell) |
            MPT_REG_DOORBELL_SET_WHOINIT(s->who_init);
        /*
         * If there is a doorbell function in progress we pass the
         * return value instead of the status code. We transfer 16bits
         * of the reply during one read.
         */
        if (s->doorbell) {
            retval |= s->reply_buffer.areply[s->next_reply_entry_read++];
        } else {
            retval |= s->ioc_fault_code;
        }
        break;

    case MPT_REG_REPLY_QUEUE:
        if (s->reply_post_queue_next_entry_free_write !=
            s->reply_post_queue_next_address_read) {
            retval = s->reply_post_queue[
                s->reply_post_queue_next_address_read++];
            s->reply_post_queue_next_address_read %=
                s->reply_queue_entries;
        } else {
            /* The reply post queue is empty. Reset interrupt. */
            retval = 0xffffffff;
            s->intr_status &= ~MPT_REG_HOST_INTR_STATUS_REPLY_INTR;
            mpt_update_interrupt(s);
        }
        break;

    case MPT_REG_HOST_INTR_STATUS:
        retval = s->intr_status;
        break;

    case MPT_REG_HOST_INTR_MASK:
        retval = s->intr_mask;
        break;

    case MPT_REG_HOST_DIAGNOSTIC:
        if (s->diagnostic_enabled) {
            retval = MPT_REG_HOST_DIAGNOSTIC_DRWE;
        } else {
            retval = 0;
        }
        break;

    case MPT_REG_TEST_BASE_ADDRESS:
    case MPT_REG_DIAG_RW_DATA:
    case MPT_REG_DIAG_RW_ADDRESS:
    default:
        trace_mpt_mmio_invalid_readl(addr);
        break;
    }
    trace_mpt_mmio_readl(addr, retval);
    return retval;
}

static void mpt_mmio_write(void *opaque, hwaddr addr,
                           uint64_t val, unsigned size)
{
    static const uint8_t DiagnosticAccess[] = {0x04, 0x0b, 0x02, 0x07, 0x0d};

    MptState *s = opaque;

    trace_mpt_mmio_writel(addr, val);
    switch (addr) {
    case MPT_REG_REPLY_QUEUE:
        s->reply_free_queue[s->reply_free_queue_next_entry_free_write++] = val;
        s->reply_free_queue_next_entry_free_write %= s->reply_queue_entries;
        break;

    case MPT_REG_REQUEST_QUEUE:
        s->request_queue[s->request_queue_next_entry_free_write++] = val;
        s->request_queue_next_entry_free_write %= s->request_queue_entries;
        mpt_queue_consumer(s);
        break;

    case MPT_REG_DOORBELL:
        if (!s->doorbell) {
            uint32_t uFunction = MPT_REG_DOORBELL_GET_FUNCTION(val);

            switch (uFunction) {
            case MPT_DOORBELL_FUNCTION_IOC_MSG_UNIT_RESET:
                mpt_soft_reset(s);
                break;
            case MPT_DOORBELL_FUNCTION_IO_UNIT_RESET:
                break;
            case MPT_DOORBELL_FUNCTION_HANDSHAKE:
            {
                s->drbl_message_size = MPT_REG_DOORBELL_GET_SIZE(val);
                s->drbl_message_index = 0;
                s->doorbell = true;
                /* Update the interrupt status to notify the guest that
                   a doorbell function was started. */
                s->intr_status |=
                    MPT_REG_HOST_INTR_STATUS_SYSTEM_DOORBELL;
                mpt_update_interrupt(s);
            }
            break;
            case MPT_DOORBELL_FUNCTION_REPLY_FRAME_REMOVAL:
            default:
                trace_mpt_mmio_invalid_writel(addr, val);
                break;
            }
        } else {
            /*
             * We are already performing a doorbell function.
             * Get the remaining parameters.
             */
            s->drbl_message[s->drbl_message_index++] = val;
            if (s->drbl_message_index == s->drbl_message_size) {
                mpt_process_message(s, (MptMessageHdr *)s->drbl_message,
                                    &s->reply_buffer);
            }
        }
        break;

    case MPT_REG_HOST_INTR_STATUS:
        s->intr_status &= ~MPT_REG_HOST_INTR_STATUS_SYSTEM_DOORBELL;
        if (s->doorbell && s->drbl_message_size == s->drbl_message_index) {
            if (s->next_reply_entry_read == s->reply_size) {
                s->doorbell = false;
            }
            s->intr_status |= MPT_REG_HOST_INTR_STATUS_SYSTEM_DOORBELL;
        }
        mpt_update_interrupt(s);
        break;

    case MPT_REG_HOST_INTR_MASK:
        s->intr_mask = val & MPT_REG_HOST_INTR_MASK_W_MASK;
        mpt_update_interrupt(s);
        break;

    case MPT_REG_WRITE_SEQUENCE:
        /* Any value will cause a reset and disabling access. */
        if (s->diagnostic_enabled) {
            s->diagnostic_enabled = false;
            s->diagnostic_access_idx = 0;
        } else if ((val & 0xf) == DiagnosticAccess[s->diagnostic_access_idx]) {
            s->diagnostic_access_idx++;
            if (s->diagnostic_access_idx == sizeof(DiagnosticAccess)) {
                /*
                 * Key sequence successfully written. Enable access to
                 * diagnostic memory and register.
                 */
                s->diagnostic_enabled = true;
            }
        } else { /* Wrong value written - reset to beginning. */
            s->diagnostic_access_idx = 0;
        }
        break;

        break;

    case MPT_REG_HOST_DIAGNOSTIC:
        if (val & MPT_REG_HOST_DIAGNOSTIC_RESET_ADAPTER) {
            mpt_hard_reset(s);
        }
        break;
    default:
        trace_mpt_mmio_invalid_writel(addr, val);
        break;
    }
}

static const MemoryRegionOps mpt_mmio_ops = {
    .read = mpt_mmio_read,
    .write = mpt_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 8,
        .max_access_size = 8,
    }
};

static uint64_t mpt_port_read(void *opaque, hwaddr addr,
                              unsigned size)
{
    uint64_t val = mpt_mmio_read(opaque, addr & 0xff, size);
    trace_mpt_port_read(opaque, addr, val, size);
    return val;
}

static void mpt_port_write(void *opaque, hwaddr addr,
                           uint64_t val, unsigned size)
{
    trace_mpt_port_write(opaque, addr, val, size);
    mpt_mmio_write(opaque, addr & 0xff, val, size);
}

static const MemoryRegionOps mpt_port_ops = {
    .read = mpt_port_read,
    .write = mpt_port_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    }
};

static uint64_t mpt_diag_read(void *opaque, hwaddr addr,
                              unsigned size)
{
    trace_mpt_diag_readl(addr, 0);
    return 0;
}

static void mpt_diag_write(void *opaque, hwaddr addr,
                           uint64_t val, unsigned size)
{
    trace_mpt_diag_writel(addr, val);
}

static const MemoryRegionOps mpt_diag_ops = {
    .read = mpt_diag_read,
    .write = mpt_diag_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 8,
        .max_access_size = 8,
    }
};

static void mpt_soft_reset(MptState *s)
{
    int i;
    trace_mpt_reset();
    s->state = MPTSTATE_RESET;

    s->intr_status = 0;
    mpt_update_interrupt(s);

    /* Reset the queues. */
    s->reply_free_queue_next_entry_free_write = 0;
    s->reply_free_queue_next_address_read = 0;
    s->reply_post_queue_next_entry_free_write = 0;
    s->reply_post_queue_next_address_read = 0;
    s->request_queue_next_entry_free_write = 0;
    s->request_queue_next_address_read = 0;
    for (i = 0; i < MPT_MAX_CMDS; i++) {
        MptCmd *cmd = s->cmds[i];
        if (cmd) {
            mpt_abort_command(cmd);
            cmd->flags = 0;
            s->cmds[i] = 0;
        }
    }
    s->next_cmd = 0;
    s->state = MPTSTATE_READY;
}

static void mpt_config_pages_free(MptState *s)
{

    if (s->config_pages) {
        /* Destroy device list if we emulate a SAS controller. */
        if (s->ctrl_type == MPTCTRLTYPE_SCSI_SAS) {
            PMptConfigurationPagesSas psas_pages =
                &s->config_pages->u.sas_pages;
            PMptSASDevice p_sas_deviceCurr = psas_pages->p_sas_device_head;

            while (p_sas_deviceCurr) {
                PMptSASDevice pFree = p_sas_deviceCurr;

                p_sas_deviceCurr = p_sas_deviceCurr->p_next;
                g_free(pFree);
            }
            if (psas_pages->pa_phy_s) {
                g_free(psas_pages->pa_phy_s);
            }
            if (psas_pages->p_manufacturing_page_7) {
                g_free(psas_pages->p_manufacturing_page_7);
            }
            if (psas_pages->p_sas_io_unit_page_0) {
                g_free(psas_pages->p_sas_io_unit_page_0);
            }
            if (psas_pages->p_sas_io_unit_page_1) {
                g_free(psas_pages->p_sas_io_unit_page_1);
            }
        }

        g_free(s->config_pages);
    }
}

static void mpt_init_config_pages_spi(MptState *s)
{
    unsigned i;
    PMptConfigurationPagesSpi p_pages = &s->config_pages->u.spi_pages;

    /* Clear everything first. */
    memset(p_pages, 0, sizeof(PMptConfigurationPagesSpi));

    for (i = 0; i < ARRAY_SIZE(p_pages->port_pages); i++) {
        MptConfigurationPageSCSISPIPort0 *p_port_page_0 =
            &p_pages->port_pages[i].scsi_spi_port_page_0;
        MptConfigurationPageSCSISPIPort1 *p_port_page_1 =
            &p_pages->port_pages[i].scsi_spi_port_page_1;
        MptConfigurationPageSCSISPIPort2 *p_port_page_2 =
            &p_pages->port_pages[i].scsi_spi_port_page_2;

        /* SCSI-SPI port page 0. */
        p_port_page_0->u.fields.header.page_type =
            MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY
            | MPT_CONFIGURATION_PAGE_TYPE_SCSI_SPI_PORT;
        p_port_page_0->u.fields.header.page_number = 0;
        p_port_page_0->u.fields.header.page_length =
            sizeof(MptConfigurationPageSCSISPIPort0) / 4;
        p_port_page_0->u.fields.information_unit_transfers_capable = true;
        p_port_page_0->u.fields.dt_capable = true;
        p_port_page_0->u.fields.qas_capable = true;
        p_port_page_0->u.fields.minimum_synchronous_transfer_period = 0;
        p_port_page_0->u.fields.maximum_synchronous_offset = 0xff;
        p_port_page_0->u.fields.wide = true;
        p_port_page_0->u.fields.aip_capable = true;
        /* Single Ended. */
        p_port_page_0->u.fields.signaling_type = 0x3;

        /* SCSI-SPI port page 1. */
        p_port_page_1->u.fields.header.page_type =
            MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE
            | MPT_CONFIGURATION_PAGE_TYPE_SCSI_SPI_PORT;
        p_port_page_1->u.fields.header.page_number = 1;
        p_port_page_1->u.fields.header.page_length =
            sizeof(MptConfigurationPageSCSISPIPort1) / 4;
        p_port_page_1->u.fields.scsi_id = 7;
        p_port_page_1->u.fields.port_response_i_ds_bitmask = (1 << 7);
        p_port_page_1->u.fields.on_bus_timer_value = 0;

        /* SCSI-SPI port page 2. */
        p_port_page_2->u.fields.header.page_type =
            MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE
            | MPT_CONFIGURATION_PAGE_TYPE_SCSI_SPI_PORT;
        p_port_page_2->u.fields.header.page_number = 2;
        p_port_page_2->u.fields.header.page_length =
            sizeof(MptConfigurationPageSCSISPIPort2) / 4;
        p_port_page_2->u.fields.host_scsi_id = 7;
        p_port_page_2->u.fields.initialize_hba = 0x3;
        p_port_page_2->u.fields.termination_disabled = true;
        unsigned iDevice;

        for (iDevice = 0;
             iDevice < ARRAY_SIZE(p_port_page_2->u.fields.device_settings);
             iDevice++) {
            p_port_page_2->u.fields.device_settings[iDevice].boot_choice =
                true;
        }
        /* Everything else 0 for now. */
    }

    unsigned bus_cur;
    for (bus_cur = 0; bus_cur < ARRAY_SIZE(p_pages->buses); bus_cur++) {
        unsigned dev_cur;
        for (dev_cur = 0;
             dev_cur < ARRAY_SIZE(p_pages->buses[bus_cur].dev_pages);
             dev_cur++) {
            MptConfigurationPageSCSISPIDevice0 *p_page_0 =
                &p_pages->buses[bus_cur].dev_pages[dev_cur].scsi_spi_dev_page0;
            MptConfigurationPageSCSISPIDevice1 *p_page_1 =
                &p_pages->buses[bus_cur].dev_pages[dev_cur].scsi_spi_dev_page1;
            MptConfigurationPageSCSISPIDevice2 *p_page_2 =
                &p_pages->buses[bus_cur].dev_pages[dev_cur].scsi_spi_dev_page2;
            MptConfigurationPageSCSISPIDevice3 *p_page_3 =
                &p_pages->buses[bus_cur].dev_pages[dev_cur].scsi_spi_dev_page3;

            /* SCSI-SPI device page 0. */
            p_page_0->u.fields.header.page_type =
                MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY
                | MPT_CONFIGURATION_PAGE_TYPE_SCSI_SPI_DEVICE;
            p_page_0->u.fields.header.page_number = 0;
            p_page_0->u.fields.header.page_length =
                sizeof(MptConfigurationPageSCSISPIDevice0) / 4;
            /* Everything else 0 for now. */

            /* SCSI-SPI device page 1. */
            p_page_1->u.fields.header.page_type =
                MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE
                | MPT_CONFIGURATION_PAGE_TYPE_SCSI_SPI_DEVICE;
            p_page_1->u.fields.header.page_number = 1;
            p_page_1->u.fields.header.page_length =
                sizeof(MptConfigurationPageSCSISPIDevice1) / 4;
            /* Everything else 0 for now. */

            /* SCSI-SPI device page 2. */
            p_page_2->u.fields.header.page_type =
                MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE
                | MPT_CONFIGURATION_PAGE_TYPE_SCSI_SPI_DEVICE;
            p_page_2->u.fields.header.page_number = 2;
            p_page_2->u.fields.header.page_length =
                sizeof(MptConfigurationPageSCSISPIDevice2) / 4;
            /* Everything else 0 for now. */

            p_page_3->u.fields.header.page_type =
                MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY
                | MPT_CONFIGURATION_PAGE_TYPE_SCSI_SPI_DEVICE;
            p_page_3->u.fields.header.page_number = 3;
            p_page_3->u.fields.header.page_length =
                sizeof(MptConfigurationPageSCSISPIDevice3) / 4;
            /* Everything else 0 for now. */
        }
    }
}

static void mpt_init_config_pages_sas(MptState *s)
{
    PMptConfigurationPagesSas p_pages = &s->config_pages->u.sas_pages;

    /* Manufacturing Page 7 - Connector settings. */
    p_pages->cb_manufacturing_page_7 =
        MPTSCSI_MANUFACTURING7_GET_SIZE(s->ports);
    PMptConfigurationPageManufacturing7 p_manufacturing_page_7 =
        (PMptConfigurationPageManufacturing7)
        g_malloc0(p_pages->cb_manufacturing_page_7);
    MPT_CONFIG_PAGE_HEADER_INIT_MANUFACTURING(
        p_manufacturing_page_7, 0, 7,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_PERSISTENT_READONLY);
    /* Set size manually. */
    if (p_pages->cb_manufacturing_page_7 / 4 > 255) {
        p_manufacturing_page_7->u.fields.header.page_length = 255;
    } else {
        p_manufacturing_page_7->u.fields.header.page_length =
            p_pages->cb_manufacturing_page_7 / 4;
    }
    p_manufacturing_page_7->u.fields.num_phys = s->ports;
    p_pages->p_manufacturing_page_7 = p_manufacturing_page_7;

    /* SAS I/O unit page 0 - Port specific information. */
    p_pages->cb_sas_io_unit_page_0 = MPTSCSI_SASIOUNIT0_GET_SIZE(s->ports);
    PMptConfigurationPageSASIOUnit0 p_sas_page_0 =
        (PMptConfigurationPageSASIOUnit0)
        g_malloc0(p_pages->cb_sas_io_unit_page_0);

    MPT_CONFIG_EXTENDED_PAGE_HEADER_INIT(
        p_sas_page_0, p_pages->cb_sas_io_unit_page_0,
        0, MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY,
        MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASIOUNIT);
    p_sas_page_0->u.fields.num_phys = s->ports;
    p_pages->p_sas_io_unit_page_0 = p_sas_page_0;

    /* SAS I/O unit page 1 - Port specific settings. */
    p_pages->cb_sas_io_unit_page_1 = MPTSCSI_SASIOUNIT1_GET_SIZE(s->ports);
    PMptConfigurationPageSASIOUnit1 p_sas_page_1 =
        (PMptConfigurationPageSASIOUnit1)
        g_malloc0(p_pages->cb_sas_io_unit_page_1);

    MPT_CONFIG_EXTENDED_PAGE_HEADER_INIT(
        p_sas_page_1, p_pages->cb_sas_io_unit_page_1,
        1, MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE,
        MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASIOUNIT);
    p_sas_page_1->u.fields.num_phys = p_sas_page_0->u.fields.num_phys;
    p_sas_page_1->u.fields.control_flags = 0;
    p_sas_page_1->u.fields.additional_control_flags = 0;
    p_pages->p_sas_io_unit_page_1 = p_sas_page_1;

    /* SAS I/O unit page 2 - Port specific information. */
    p_pages->sas_io_unit_page_2.u.fields.ext_hdr.page_type =
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY
        | MPT_CONFIGURATION_PAGE_TYPE_EXTENDED;
    p_pages->sas_io_unit_page_2.u.fields.ext_hdr.page_number = 2;
    p_pages->sas_io_unit_page_2.u.fields.ext_hdr.ext_page_type =
        MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASIOUNIT;
    p_pages->sas_io_unit_page_2.u.fields.ext_hdr.ext_page_len =
        sizeof(MptConfigurationPageSASIOUnit2) / 4;

    /* SAS I/O unit page 3 - Port specific information. */
    p_pages->sas_io_unit_page_3.u.fields.ext_hdr.page_type =
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY
        | MPT_CONFIGURATION_PAGE_TYPE_EXTENDED;
    p_pages->sas_io_unit_page_3.u.fields.ext_hdr.page_number = 3;
    p_pages->sas_io_unit_page_3.u.fields.ext_hdr.ext_page_type =
        MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASIOUNIT;
    p_pages->sas_io_unit_page_3.u.fields.ext_hdr.ext_page_len =
        sizeof(MptConfigurationPageSASIOUnit3) / 4;

    p_pages->c_phy_s = s->ports;
    p_pages->pa_phy_s = (PMptPHY)g_malloc0(p_pages->c_phy_s * sizeof(MptPHY));

    /* Initialize the PHY configuration */
    unsigned i;
    for (i = 0; i < s->ports; i++) {
        PMptPHY p_phy_pages = &p_pages->pa_phy_s[i];
        uint16_t controller_handle = mpt_get_handle(s);

        p_manufacturing_page_7->u.fields.phy[i].location =
            MPTSCSI_MANUFACTURING7_LOCATION_AUTO;

        p_sas_page_0->u.fields.phy[i].port = i;
        p_sas_page_0->u.fields.phy[i].port_flags = 0;
        p_sas_page_0->u.fields.phy[i].phy_flags = 0;
        p_sas_page_0->u.fields.phy[i].negotiated_link_rate =
            MPTSCSI_SASIOUNIT0_NEGOTIATED_RATE_FAILED;
        p_sas_page_0->u.fields.phy[i].controller_phy_device_info =
            MPTSCSI_SASIOUNIT0_DEVICE_TYPE_SET(
                MPTSCSI_SASIOUNIT0_DEVICE_TYPE_NO);
        p_sas_page_0->u.fields.phy[i].controller_dev_handle =
            controller_handle;
        p_sas_page_0->u.fields.phy[i].attached_dev_handle = 0;
        p_sas_page_0->u.fields.phy[i].discovery_status = 0;

        p_sas_page_1->u.fields.phy[i].port = i;
        p_sas_page_1->u.fields.phy[i].port_flags = 0;
        p_sas_page_1->u.fields.phy[i].phy_flags = 0;
        p_sas_page_1->u.fields.phy[i].max_min_link_rate =
            MPTSCSI_SASIOUNIT1_LINK_RATE_MIN_SET(
                MPTSCSI_SASIOUNIT1_LINK_RATE_15GB)
            | MPTSCSI_SASIOUNIT1_LINK_RATE_MAX_SET(
                MPTSCSI_SASIOUNIT1_LINK_RATE_30GB);
        p_sas_page_1->u.fields.phy[i].controller_phy_device_info =
            MPTSCSI_SASIOUNIT0_DEVICE_TYPE_SET(
                MPTSCSI_SASIOUNIT0_DEVICE_TYPE_NO);

        /* SAS PHY page 0. */
        p_phy_pages->sas_phy_page_0.u.fields.ext_hdr.page_type =
            MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY
            | MPT_CONFIGURATION_PAGE_TYPE_EXTENDED;
        p_phy_pages->sas_phy_page_0.u.fields.ext_hdr.page_number = 0;
        p_phy_pages->sas_phy_page_0.u.fields.ext_hdr.ext_page_type =
            MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASPHYS;
        p_phy_pages->sas_phy_page_0.u.fields.ext_hdr.ext_page_len =
            sizeof(MptConfigurationPageSASPHY0) / 4;
        p_phy_pages->sas_phy_page_0.u.fields.attached_phy_identifier = i;
        p_phy_pages->sas_phy_page_0.u.fields.attached_device_info =
            MPTSCSI_SASPHY0_DEV_INFO_DEVICE_TYPE_SET(
                MPTSCSI_SASPHY0_DEV_INFO_DEVICE_TYPE_NO);
        p_phy_pages->sas_phy_page_0.u.fields.programmed_link_rate =
            MPTSCSI_SASIOUNIT1_LINK_RATE_MIN_SET(
                MPTSCSI_SASIOUNIT1_LINK_RATE_15GB)
            | MPTSCSI_SASIOUNIT1_LINK_RATE_MAX_SET(
                MPTSCSI_SASIOUNIT1_LINK_RATE_30GB);
        p_phy_pages->sas_phy_page_0.u.fields.hw_link_rate =
            MPTSCSI_SASIOUNIT1_LINK_RATE_MIN_SET(
                MPTSCSI_SASIOUNIT1_LINK_RATE_15GB)
            | MPTSCSI_SASIOUNIT1_LINK_RATE_MAX_SET(
                MPTSCSI_SASIOUNIT1_LINK_RATE_30GB);

        /* SAS PHY page 1. */
        p_phy_pages->sas_phy_page_1.u.fields.ext_hdr.page_type =
            MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY
            | MPT_CONFIGURATION_PAGE_TYPE_EXTENDED;
        p_phy_pages->sas_phy_page_1.u.fields.ext_hdr.page_number = 1;
        p_phy_pages->sas_phy_page_1.u.fields.ext_hdr.ext_page_type =
            MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASPHYS;
        p_phy_pages->sas_phy_page_1.u.fields.ext_hdr.ext_page_len =
            sizeof(MptConfigurationPageSASPHY1) / 4;

        /* Settings for present devices. */
        if (scsi_device_find(&s->bus, 0, i, 0)) {
            uint16_t device_handle = mpt_get_handle(s);
            SASADDRESS sas_address;
            PMptSASDevice p_sas_device =
                (PMptSASDevice)g_malloc0(sizeof(MptSASDevice));

            memset(&sas_address, 0, sizeof(SASADDRESS));
            sas_address.ll_address = s->sas_addr;

            p_sas_page_0->u.fields.phy[i].negotiated_link_rate =
                MPTSCSI_SASIOUNIT0_NEGOTIATED_RATE_SET(
                    MPTSCSI_SASIOUNIT0_NEGOTIATED_RATE_30GB);
            p_sas_page_0->u.fields.phy[i].controller_phy_device_info =
                MPTSCSI_SASIOUNIT0_DEVICE_TYPE_SET(
                    MPTSCSI_SASIOUNIT0_DEVICE_TYPE_END)
                | MPTSCSI_SASIOUNIT0_DEVICE_SSP_TARGET;
            p_sas_page_0->u.fields.phy[i].attached_dev_handle =
                device_handle;
            p_sas_page_1->u.fields.phy[i].controller_phy_device_info =
                MPTSCSI_SASIOUNIT0_DEVICE_TYPE_SET(
                    MPTSCSI_SASIOUNIT0_DEVICE_TYPE_END)
                | MPTSCSI_SASIOUNIT0_DEVICE_SSP_TARGET;
            p_sas_page_0->u.fields.phy[i].controller_dev_handle =
                device_handle;

            p_phy_pages->sas_phy_page_0.u.fields.attached_device_info =
                MPTSCSI_SASPHY0_DEV_INFO_DEVICE_TYPE_SET(
                    MPTSCSI_SASPHY0_DEV_INFO_DEVICE_TYPE_END);
            p_phy_pages->sas_phy_page_0.u.fields.sas_address =
                sas_address;
            p_phy_pages->sas_phy_page_0.u.fields.owner_dev_handle =
                device_handle;
            p_phy_pages->sas_phy_page_0.u.fields.attached_dev_handle =
                device_handle;

            /* SAS device page 0. */
            p_sas_device->sas_dev_page0.u.fields.ext_hdr.page_type =
                MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY
                | MPT_CONFIGURATION_PAGE_TYPE_EXTENDED;
            p_sas_device->sas_dev_page0.u.fields.ext_hdr.page_number = 0;
            p_sas_device->sas_dev_page0.u.fields.ext_hdr.ext_page_type =
                MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASDEVICE;
            p_sas_device->sas_dev_page0.u.fields.ext_hdr.ext_page_len =
                sizeof(MptConfigurationPageSASDevice0) / 4;
            p_sas_device->sas_dev_page0.u.fields.sas_address =
                sas_address;
            p_sas_device->sas_dev_page0.u.fields.parent_dev_handle =
                controller_handle;
            p_sas_device->sas_dev_page0.u.fields.phy_num = i;
            p_sas_device->sas_dev_page0.u.fields.access_status =
                MPTSCSI_SASDEVICE0_STATUS_NO_ERRORS;
            p_sas_device->sas_dev_page0.u.fields.dev_handle = device_handle;
            p_sas_device->sas_dev_page0.u.fields.target_id = i;
            p_sas_device->sas_dev_page0.u.fields.bus = 0;
            p_sas_device->sas_dev_page0.u.fields.device_info =
                MPTSCSI_SASPHY0_DEV_INFO_DEVICE_TYPE_SET(
                    MPTSCSI_SASPHY0_DEV_INFO_DEVICE_TYPE_END)
                | MPTSCSI_SASIOUNIT0_DEVICE_SSP_TARGET;
            p_sas_device->sas_dev_page0.u.fields.flags =
                MPTSCSI_SASDEVICE0_FLAGS_DEVICE_PRESENT
                | MPTSCSI_SASDEVICE0_FLAGS_DEVICE_MAPPED_TO_BUS_AND_TARGET_ID
                | MPTSCSI_SASDEVICE0_FLAGS_DEVICE_MAPPING_PERSISTENT;
            p_sas_device->sas_dev_page0.u.fields.physical_port = i;

            /* SAS device page 1. */
            p_sas_device->sas_dev_page1.u.fields.ext_hdr.page_type =
                MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY
                | MPT_CONFIGURATION_PAGE_TYPE_EXTENDED;
            p_sas_device->sas_dev_page1.u.fields.ext_hdr.page_number = 1;
            p_sas_device->sas_dev_page1.u.fields.ext_hdr.ext_page_type =
                MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASDEVICE;
            p_sas_device->sas_dev_page1.u.fields.ext_hdr.ext_page_len =
                sizeof(MptConfigurationPageSASDevice1) / 4;
            p_sas_device->sas_dev_page1.u.fields.sas_address = sas_address;
            p_sas_device->sas_dev_page1.u.fields.dev_handle = device_handle;
            p_sas_device->sas_dev_page1.u.fields.target_id = i;
            p_sas_device->sas_dev_page1.u.fields.bus = 0;

            /* SAS device page 2. */
            p_sas_device->sas_dev_page2.u.fields.ext_hdr.page_type =
                MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY
                | MPT_CONFIGURATION_PAGE_TYPE_EXTENDED;
            p_sas_device->sas_dev_page2.u.fields.ext_hdr.page_number =
                2;
            p_sas_device->sas_dev_page2.u.fields.ext_hdr.ext_page_type =
                MPT_CONFIGURATION_PAGE_TYPE_EXTENDED_SASDEVICE;
            p_sas_device->sas_dev_page2.u.fields.ext_hdr.ext_page_len =
                sizeof(MptConfigurationPageSASDevice2) / 4;
            p_sas_device->sas_dev_page2.u.fields.sas_address =
                sas_address;

            /* Link into device list. */
            if (!p_pages->c_devices) {
                p_pages->p_sas_device_head = p_sas_device;
                p_pages->p_sas_device_tail = p_sas_device;
                p_pages->c_devices = 1;
            } else {
                p_sas_device->p_prev = p_pages->p_sas_device_tail;
                p_pages->p_sas_device_tail->p_next = p_sas_device;
                p_pages->p_sas_device_tail = p_sas_device;
                p_pages->c_devices++;
            }
        }
    }
}

static void mpt_init_config_pages(MptState *s)
{
    /* Initialize the common pages. */
    PMptConfigurationPagesSupported p_pages =
        (PMptConfigurationPagesSupported)
        g_malloc0(sizeof(MptConfigurationPagesSupported));

    s->config_pages = p_pages;

    /* Clear everything first. */
    memset(p_pages, 0, sizeof(MptConfigurationPagesSupported));

    /* Manufacturing Page 0. */
    MPT_CONFIG_PAGE_HEADER_INIT_MANUFACTURING(
        &p_pages->manufacturing_page_0,
        MptConfigurationPageManufacturing0, 0,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_PERSISTENT_READONLY);
    strncpy((char *)p_pages->manufacturing_page_0.u.fields.chip_name,
            "QEMU MPT Fusion", 16);
    strncpy((char *)p_pages->manufacturing_page_0.u.fields.chip_revision,
            "1.0", 8);
    strncpy((char *)p_pages->manufacturing_page_0.u.fields.board_name,
            "QEMU MPT Fusion", 16);
    strncpy((char *)p_pages->manufacturing_page_0.u.fields.board_assembly,
            "Verizon", 8);
    strncpy((char *)p_pages->manufacturing_page_0.u.fields.board_tracer_number,
            "DEADBEEFDEADBEEF", 16);

    /* Manufacturing Page 1 - Leave it 0 for now. */
    MPT_CONFIG_PAGE_HEADER_INIT_MANUFACTURING(
        &p_pages->manufacturing_page_1,
        MptConfigurationPageManufacturing1, 1,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_PERSISTENT_READONLY);

    /* Manufacturing Page 2. */
    MPT_CONFIG_PAGE_HEADER_INIT_MANUFACTURING(
        &p_pages->manufacturing_page_2,
        MptConfigurationPageManufacturing2, 2,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_PERSISTENT_READONLY);

    if (s->ctrl_type == MPTCTRLTYPE_SCSI_SPI) {
        p_pages->manufacturing_page_2.u.fields.pci_device_id =
            PCI_DEVICE_ID_LSI_53C1030;
        p_pages->manufacturing_page_2.u.fields.pci_revision_id =
            MPTSCSI_PCI_SPI_REVISION_ID;
    } else if (s->ctrl_type == MPTCTRLTYPE_SCSI_SAS) {
        p_pages->manufacturing_page_2.u.fields.pci_device_id =
            PCI_DEVICE_ID_LSI_SAS1068;
        p_pages->manufacturing_page_2.u.fields.pci_revision_id =
            MPTSCSI_PCI_SAS_REVISION_ID;
    }

    /* Manufacturing Page 3. */
    MPT_CONFIG_PAGE_HEADER_INIT_MANUFACTURING(
        &p_pages->manufacturing_page_3,
        MptConfigurationPageManufacturing3, 3,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_PERSISTENT_READONLY);

    if (s->ctrl_type == MPTCTRLTYPE_SCSI_SPI) {
        p_pages->manufacturing_page_3.u.fields.pci_device_id =
            PCI_DEVICE_ID_LSI_53C1030;
        p_pages->manufacturing_page_3.u.fields.pci_revision_id =
            MPTSCSI_PCI_SPI_REVISION_ID;
    } else if (s->ctrl_type == MPTCTRLTYPE_SCSI_SAS) {
        p_pages->manufacturing_page_3.u.fields.pci_device_id =
            PCI_DEVICE_ID_LSI_SAS1068;
        p_pages->manufacturing_page_3.u.fields.pci_revision_id =
            MPTSCSI_PCI_SAS_REVISION_ID;
    }

    /* Manufacturing Page 4 - Leave it 0 for now. */
    MPT_CONFIG_PAGE_HEADER_INIT_MANUFACTURING(
        &p_pages->manufacturing_page_4,
        MptConfigurationPageManufacturing4, 4,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_PERSISTENT_READONLY);

    /* Manufacturing Page 5 - WWID settings. */
    MPT_CONFIG_PAGE_HEADER_INIT_MANUFACTURING(
        &p_pages->manufacturing_page_5,
        MptConfigurationPageManufacturing5, 5,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_PERSISTENT_READONLY);

    /* Manufacturing Page 6 - Product specific settings. */
    MPT_CONFIG_PAGE_HEADER_INIT_MANUFACTURING(
        &p_pages->manufacturing_page_6,
        MptConfigurationPageManufacturing6, 6,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE);

    /* Manufacturing Page 8 -  Product specific settings. */
    MPT_CONFIG_PAGE_HEADER_INIT_MANUFACTURING(
        &p_pages->manufacturing_page_8,
        MptConfigurationPageManufacturing8, 8,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE);

    /* Manufacturing Page 9 -  Product specific settings. */
    MPT_CONFIG_PAGE_HEADER_INIT_MANUFACTURING(
        &p_pages->manufacturing_page_9,
        MptConfigurationPageManufacturing9, 9,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE);

    /* Manufacturing Page 10 -  Product specific settings. */
    MPT_CONFIG_PAGE_HEADER_INIT_MANUFACTURING(
        &p_pages->manufacturing_page_10,
        MptConfigurationPageManufacturing10, 10,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE);

    /* I/O Unit page 0. */
    MPT_CONFIG_PAGE_HEADER_INIT_IO_UNIT(
        &p_pages->io_unit_page_0,
        MptConfigurationPageIOUnit0, 0,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY);
    p_pages->io_unit_page_0.u.fields.unique_identifier = 0xcafe;

    /* I/O Unit page 1. */
    MPT_CONFIG_PAGE_HEADER_INIT_IO_UNIT(
        &p_pages->io_unit_page_1,
        MptConfigurationPageIOUnit1, 1,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY);
    p_pages->io_unit_page_1.u.fields.single_function = true;
    p_pages->io_unit_page_1.u.fields.all_paths_mapped = false;
    p_pages->io_unit_page_1.u.fields.integrated_raid_disabled = true;
    p_pages->io_unit_page_1.u.fields.f32bit_access_forced = false;

    /* I/O Unit page 2. */
    MPT_CONFIG_PAGE_HEADER_INIT_IO_UNIT(
        &p_pages->io_unit_page_2,
        MptConfigurationPageIOUnit2, 2,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_PERSISTENT);
    p_pages->io_unit_page_2.u.fields.pause_on_error = false;
    p_pages->io_unit_page_2.u.fields.verbose_mode_enabled = false;
    p_pages->io_unit_page_2.u.fields.disable_color_video = false;
    p_pages->io_unit_page_2.u.fields.not_hook_int_40h = false;
    p_pages->io_unit_page_2.u.fields.bios_version = 0xdeadbeef;
    p_pages->io_unit_page_2.u.fields.adapter_order[0].adapter_enabled = true;
    p_pages->io_unit_page_2.u.fields.adapter_order[0].adapter_embedded = true;
    p_pages->io_unit_page_2.u.fields.adapter_order[0].pci_bus_number = 0;
    p_pages->io_unit_page_2.u.fields.adapter_order[0].pci_dev_fn = s->dev.devfn;

    /* I/O Unit page 3. */
    MPT_CONFIG_PAGE_HEADER_INIT_IO_UNIT(
        &p_pages->io_unit_page_3,
        MptConfigurationPageIOUnit3, 3,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE);
    p_pages->io_unit_page_3.u.fields.gpio_count = 0;

    /* I/O Unit page 4. */
    MPT_CONFIG_PAGE_HEADER_INIT_IO_UNIT(
        &p_pages->io_unit_page_4,
        MptConfigurationPageIOUnit4, 4,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE);

    /* IOC page 0. */
    MPT_CONFIG_PAGE_HEADER_INIT_IOC(
        &p_pages->ioc_page_0,
        MptConfigurationPageIOC0, 0,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY);
    p_pages->ioc_page_0.u.fields.total_nv_Store = 0;
    p_pages->ioc_page_0.u.fields.free_nv_store = 0;

    p_pages->ioc_page_0.u.fields.vendor_id =
        PCI_VENDOR_ID_LSI_LOGIC;
    p_pages->ioc_page_0.u.fields.subsystem_vendor_id =
        PCI_VENDOR_ID_LSI_LOGIC;
    p_pages->ioc_page_0.u.fields.subsystem_vendor_id =
        PCI_VENDOR_ID_LSI_LOGIC;
    if (s->ctrl_type == MPTCTRLTYPE_SCSI_SPI) {
        p_pages->ioc_page_0.u.fields.device_id =
            PCI_DEVICE_ID_LSI_53C1030;
        p_pages->ioc_page_0.u.fields.revision_id =
            MPTSCSI_PCI_SPI_REVISION_ID;
        p_pages->ioc_page_0.u.fields.class_code =
            MPTSCSI_PCI_SPI_CLASS_CODE;
        p_pages->ioc_page_0.u.fields.subsystem_id =
            MPTSCSI_PCI_SPI_SUBSYSTEM_ID;
    } else if (s->ctrl_type == MPTCTRLTYPE_SCSI_SAS) {
        p_pages->ioc_page_0.u.fields.device_id =
            PCI_DEVICE_ID_LSI_SAS1068;
        p_pages->ioc_page_0.u.fields.revision_id =
            MPTSCSI_PCI_SAS_REVISION_ID;
        p_pages->ioc_page_0.u.fields.class_code =
            MPTSCSI_PCI_SAS_CLASS_CODE;
        p_pages->ioc_page_0.u.fields.subsystem_id =
            MPTSCSI_PCI_SAS_SUBSYSTEM_ID;
    }

    /* IOC page 1. */
    MPT_CONFIG_PAGE_HEADER_INIT_IOC(
        &p_pages->ioc_page_1,
        MptConfigurationPageIOC1, 1,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE);
    p_pages->ioc_page_1.u.fields.reply_coalescing_enabled = false;
    p_pages->ioc_page_1.u.fields.coalescing_timeout = 0;
    p_pages->ioc_page_1.u.fields.coalescing_depth = 0;

    /* IOC page 2. */
    MPT_CONFIG_PAGE_HEADER_INIT_IOC(
        &p_pages->ioc_page_2,
        MptConfigurationPageIOC2, 2,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY);
    /* Everything else here is 0. */

    /* IOC page 3. */
    MPT_CONFIG_PAGE_HEADER_INIT_IOC(
        &p_pages->ioc_page_3,
        MptConfigurationPageIOC3, 3,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY);
    /* Everything else here is 0. */

    /* IOC page 4. */
    MPT_CONFIG_PAGE_HEADER_INIT_IOC(
        &p_pages->ioc_page_4,
        MptConfigurationPageIOC4, 4,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY);
    /* Everything else here is 0. */

    /* IOC page 6. */
    MPT_CONFIG_PAGE_HEADER_INIT_IOC(
        &p_pages->ioc_page_6,
        MptConfigurationPageIOC6, 6,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_READONLY);
    /* Everything else here is 0. */

    /* BIOS page 1. */
    MPT_CONFIG_PAGE_HEADER_INIT_BIOS(
        &p_pages->bios_page_1,
        MptConfigurationPageBIOS1, 1,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE);

    /* BIOS page 2. */
    MPT_CONFIG_PAGE_HEADER_INIT_BIOS(
        &p_pages->bios_page_2,
        MptConfigurationPageBIOS2, 2,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE);

    /* BIOS page 4. */
    MPT_CONFIG_PAGE_HEADER_INIT_BIOS(
        &p_pages->bios_page_4,
        MptConfigurationPageBIOS4, 4,
        MPT_CONFIGURATION_PAGE_ATTRIBUTE_CHANGEABLE);

    if (s->ctrl_type == MPTCTRLTYPE_SCSI_SPI) {
        mpt_init_config_pages_spi(s);
    } else if (s->ctrl_type == MPTCTRLTYPE_SCSI_SAS) {
        mpt_init_config_pages_sas(s);
    }
}


static int mpt_hard_reset(MptState *s)
{

    s->intr_mask |= MPT_REG_HOST_INTR_MASK_DOORBELL |
        MPT_REG_HOST_INTR_MASK_REPLY;
    mpt_soft_reset(s);

    /* Set default values. */
    if (s->ctrl_type == MPTCTRLTYPE_SCSI_SPI) {
        s->max_devices = MPTSCSI_PCI_SPI_DEVICES_MAX;
    } else if (s->ctrl_type == MPTCTRLTYPE_SCSI_SAS) {
        s->max_devices = MPTSCSI_PCI_SAS_DEVICES_MAX;
    }
    s->max_buses = 1;
    s->reply_frame_size = 128; /* @todo Figure out where it is needed. */
    s->next_handle = 1;

    mpt_config_pages_free(s);
    mpt_init_config_pages(s);

    /* Mark that we finished performing the reset. */
    s->state = MPTSTATE_READY;
    return 0;
}

static void mpt_scsi_reset(DeviceState *dev)
{
    MptState *s = DO_UPCAST(MptState, dev.qdev, dev);

    mpt_hard_reset(s);
}

static void mpt_queues_free(MptState *s)
{
    assert(s->reply_free_queue);

    g_free(s->reply_free_queue);

    s->reply_free_queue = NULL;
    s->reply_post_queue = NULL;
    s->request_queue = NULL;
}

static int mpt_queues_alloc(MptState *s)
{
    uint32_t cbQueues;

    assert(!s->reply_free_queue);

    cbQueues = 2*s->reply_queue_entries * sizeof(uint32_t);
    cbQueues += s->request_queue_entries * sizeof(uint32_t);

    s->reply_free_queue = g_malloc0(cbQueues);

    s->reply_post_queue = s->reply_free_queue + s->reply_queue_entries;

    s->request_queue = s->reply_post_queue + s->reply_queue_entries;

    return 0;
}

static void mpt_config_save(QEMUFile *f, void *pv, size_t size)
{
    MptState *s = container_of(pv, MptState, config_pages);

    qemu_put_buffer(f, (void *)s->config_pages,
                    sizeof(MptConfigurationPagesSupported));
}

static int mpt_config_load(QEMUFile *f, void *pv, size_t size)
{
    MptState *s = container_of(pv, MptState, config_pages);
    int ret = qemu_get_buffer(f, (void *)s->config_pages,
                              sizeof(MptConfigurationPagesSupported));
    if (ret != sizeof(MptConfigurationPagesSupported)) {
        return -EINVAL;
    }
    return 0;
}

static VMStateInfo mpt_config_vmstate_info = {
    .name = "lsimpt_configs",
    .get  = mpt_config_load,
    .put  = mpt_config_save,
};

static void mpt_queue_save(QEMUFile *f, void *pv, size_t size)
{
    MptState *s = container_of(pv, MptState, reply_free_queue);
    uint32_t cbQueues;

    cbQueues = 2*s->reply_queue_entries * sizeof(uint32_t);
    cbQueues += s->request_queue_entries * sizeof(uint32_t);

    qemu_put_buffer(f, (void *)s->reply_free_queue, cbQueues);
}

static int mpt_queue_load(QEMUFile *f, void *pv, size_t size)
{
    MptState *s = container_of(pv, MptState, reply_free_queue);
    uint32_t cbQueues;
    int ret;

    if (s->reply_free_queue) {
        mpt_queues_free(s);
    }
    mpt_queues_alloc(s);

    cbQueues = 2*s->reply_queue_entries * sizeof(uint32_t);
    cbQueues += s->request_queue_entries * sizeof(uint32_t);

    ret = qemu_get_buffer(f, (void *)s->reply_free_queue, cbQueues);
    if (ret != cbQueues) {
        return -EINVAL;
    }
    return 0;
}

static VMStateInfo mpt_queue_vmstate_info = {
    .name = "lsimpt_queues",
    .get  = mpt_queue_load,
    .put  = mpt_queue_save,
};

static const VMStateDescription vmstate_mpt = {
    .name = "lsimpt",
    .version_id = 0,
    .minimum_version_id = 0,
    .minimum_version_id_old = 0,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(dev, MptState),

        VMSTATE_BUFFER_UNSAFE_INFO(config_pages, MptState, 0,
                                   mpt_config_vmstate_info, 0),

        VMSTATE_UINT32(ctrl_type, MptState),
        VMSTATE_UINT32(state, MptState),
        VMSTATE_UINT32(who_init, MptState),
        VMSTATE_UINT16(next_handle, MptState),
        VMSTATE_UINT32(ports, MptState),
        VMSTATE_UINT32(flags, MptState),
        VMSTATE_UINT32(intr_mask, MptState),
        VMSTATE_UINT32(intr_status, MptState),
        VMSTATE_UINT32(doorbell, MptState),
        VMSTATE_UINT32(busy, MptState),
        VMSTATE_BOOL(msi_used, MptState),
        VMSTATE_BOOL(event_notification_enabled, MptState),
        VMSTATE_BOOL(diagnostic_enabled, MptState),
        VMSTATE_UINT32(diagnostic_access_idx, MptState),
        VMSTATE_UINT16(max_devices, MptState),
        VMSTATE_UINT16(max_buses, MptState),
        VMSTATE_UINT64(sas_addr, MptState),
        VMSTATE_BUFFER_UNSAFE(drbl_message, MptState, 0,
                              (sizeof(MptRequestUnion)+sizeof(uint32_t)-1)/
                              sizeof(uint32_t)),
        VMSTATE_UINT16(drbl_message_index, MptState),
        VMSTATE_UINT16(drbl_message_size, MptState),
        VMSTATE_BUFFER_UNSAFE(reply_buffer, MptState, 0,
                              sizeof(MptReplyUnion)),
        VMSTATE_UINT16(next_reply_entry_read, MptState),
        VMSTATE_UINT16(reply_size, MptState),
        VMSTATE_UINT16(ioc_fault_code, MptState),
        VMSTATE_UINT16(reply_frame_size, MptState),
        VMSTATE_UINT32(host_mfa_high_addr, MptState),
        VMSTATE_UINT32(sense_buffer_high_addr, MptState),
        VMSTATE_UINT32(reply_queue_entries, MptState),
        VMSTATE_UINT32(request_queue_entries, MptState),

        VMSTATE_UINT32(reply_free_queue_next_entry_free_write, MptState),
        VMSTATE_UINT32(reply_free_queue_next_address_read, MptState),
        VMSTATE_UINT32(reply_post_queue_next_entry_free_write, MptState),
        VMSTATE_UINT32(reply_post_queue_next_address_read, MptState),
        VMSTATE_UINT32(request_queue_next_entry_free_write, MptState),
        VMSTATE_UINT32(request_queue_next_address_read, MptState),
        VMSTATE_UINT32(next_cmd, MptState),

        VMSTATE_BUFFER_UNSAFE_INFO(reply_free_queue, MptState, 0,
                                   mpt_queue_vmstate_info, 0),

        VMSTATE_END_OF_LIST()
    }
};

static bool
mpt_msi_init(MptState *s) {
#define LSISAS_MSI_NUM_VECTORS   (1)
#define LSISAS_MSI_OFFSET        (0x80)
#define LSISAS_USE_64BIT         (true)
#define LSISAS_PER_VECTOR_MASK   (false)

    int res;

    if (!mpt_use_msi(s) || vmware_hw) {
        s->msi_used = false;
        return s->msi_used;
    }

    res = msi_init(&s->dev, LSISAS_MSI_OFFSET, LSISAS_MSI_NUM_VECTORS,
                   LSISAS_USE_64BIT, LSISAS_PER_VECTOR_MASK);
    if (0 > res) {
        fprintf(stderr, "%s: Failed to initialize MSI, error %d\n", __func__, res);
	s->msi_used = false;
    } else {
        s->msi_used = true;
    }

    return s->msi_used;
}

static void
mpt_cleanup_msi(MptState *s)
{
    if (s->msi_used) {
        msi_uninit(&s->dev);
    }
}


#ifdef USE_MSIX
static bool
mpt_msix_init(MptState *s) {
    int res = msix_init(&s->dev, LSISAS_MAX_INTRS,
	                &s->msix_bar, LSISAS_MSIX_BAR_IDX, 0,
                        &s->msix_bar, LSISAS_MSIX_BAR_IDX, 0x800,
                        0x90);
    if (0 > res) {
        fprintf(stderr, "%s: Failed to initialize MSI-X, error %d\n",
                __func__, res);
        s->msix_used = false;
    } else {
        if (!xxx_use_msix_vectors(s, LSISAS_MAX_INTRS)) {
            fprintf(stderr, "%s: Failed to use MSI-X vectors, error %d\n",
                    __func__, res);
            msix_uninit(&s->dev, &s->msix_bar, &s->msix_bar);
            s->msix_used = false;
        } else {
            s->msix_used = true;
        }
    }
}


static void
mpt_cleanup_msix(MptState *s)
{
    if (s->msix_used) {
        msix_vector_unuse(&s->dev, LSISAS_MAX_INTRS);
        msix_uninit(&s->dev, &s->msix_bar, &s->msix_bar);
    }
}

static void
mpt_msix_save(QEMUFile *f, void *opaque)
{
    msix_save(&((MptState *)opaque)->dev, f);
}

static int
mpt_msix_load(QEMUFile *f, void *opaque, int version_id)
{
    msix_load(&((MptState *)opaque)->dev, f);
    return 0;
}
#endif

static bool
mpt_pcie_init(MptState *s) {
#ifdef USE_PCIE
    PCIDevice *dev = &s->dev;
    uint8_t *conf = dev->config;
    int lanes = 8;

    if (pci_is_express(dev)) {
	int offset = pcie_cap_init(dev, 0x40, PCI_EXP_TYPE_ENDPOINT, 0);
	if (offset < 0)
	    return false;
	pci_word_test_and_clear_mask(conf + PCI_STATUS, PCI_STATUS_66MHZ | PCI_STATUS_FAST_BACK);
	pci_word_test_and_clear_mask(conf + PCI_SEC_STATUS, PCI_STATUS_66MHZ | PCI_STATUS_FAST_BACK);
	if (vmware_hw) {
	    lanes = 32; /* vmware lies */
	}
	pci_set_long_by_mask(conf + offset + PCI_EXP_LNKCAP, PCI_EXP_LNKCAP_MLW, lanes);
	pci_set_long_by_mask(conf + offset + PCI_EXP_LNKSTA, PCI_EXP_LNKCAP_MLW, lanes);
    }
    return true;
#else
    return false;
#endif
}

static void mpt_scsi_uninit(PCIDevice *d)
{
    MptState *s = DO_UPCAST(MptState, dev, d);

    mpt_queues_free(s);
#ifdef USE_MSIX
    msix_uninit(&s->dev, &s->mmio_io);
#endif
    mpt_cleanup_msi(s);

    memory_region_destroy(&s->mmio_io);
    memory_region_destroy(&s->port_io);
    memory_region_destroy(&s->diag_io);
}

static const struct SCSIBusInfo mpt_scsi_info = {
    .tcq = true,
    .max_target = MPTSCSI_PCI_SAS_PORTS_MAX,
    .max_lun = 1,

    .transfer_data = mpt_xfer_complete,
    .get_sg_list = mpt_get_sg_list,
    .complete = mpt_command_complete,
    .cancel = mpt_command_cancel,
};

static int mpt_scsi_init(PCIDevice *dev, MPTCTRLTYPE ctrl_type)
{
    MptState *s = DO_UPCAST(MptState, dev, dev);
    uint8_t *pci_conf;
    char *name;

    s->ctrl_type = ctrl_type;

    pci_conf = s->dev.config;

    if (vmware_hw && vmware_hw < 7) {
        /* Older defn. has these as zero... */
        pci_set_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID, 0);
        pci_set_word(pci_conf + PCI_SUBSYSTEM_ID, 0);
    }

    if (vmware_hw) {
        /* PCI latency timer = 64 */
        pci_conf[PCI_LATENCY_TIMER] = 0x40;
        pci_set_word(pci_conf + PCI_STATUS,
                     PCI_STATUS_FAST_BACK | PCI_STATUS_DEVSEL_MEDIUM); /* medium devsel */
        pci_conf[PCI_MIN_GNT] = 0x06;
        pci_conf[PCI_MAX_LAT] = 0xff;
    } else {
        /* PCI latency timer = 0 */
        pci_conf[PCI_LATENCY_TIMER] = 0;
    }
    /* Interrupt pin 1 */
    pci_conf[PCI_INTERRUPT_PIN] = 0x01;

    name = g_strdup_printf("lsimpt_io-%s",
                           dev->qdev.id && *dev->qdev.id ? dev->qdev.id : dev->name);
    memory_region_init_io(&s->port_io, &mpt_port_ops, s,
                          name, 128);
    g_free(name);
    name = g_strdup_printf("lsimpt_mmio-%s",
                           dev->qdev.id && *dev->qdev.id ? dev->qdev.id : dev->name);
    memory_region_init_io(&s->mmio_io, &mpt_mmio_ops, s,
                          name, 0x1000);
    g_free(name);
    if (!vmware_hw) {
        name = g_strdup_printf("lsimpt_diag-%s", dev->name);
        memory_region_init_io(&s->diag_io, &mpt_diag_ops, s,
                              name, 0x10000);
        g_free(name);
    }

    pci_register_bar(&s->dev, 0, PCI_BASE_ADDRESS_SPACE_IO, &s->port_io);
    if (vmware_hw) {
        pci_register_bar(&s->dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64, &s->mmio_io);
    } else {
        pci_register_bar(&s->dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_32, &s->mmio_io);
        /* if using 64 bit bar for mmio, this needs to use 3 instead of 2. */
        pci_register_bar(&s->dev, 2, PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_TYPE_32, &s->diag_io);
    }

    mpt_msi_init(s);

    if (pci_is_express(&s->dev)) {
	mpt_pcie_init(s);
    }

#ifdef USE_MSIX
    /* MSI-X support is currently broken */
    /*if (mpt_use_msix(s) &&
        msix_init(&s->dev, 15, &s->mmio_io, 0, 0x2000)) {
        s->flags &= ~MPT_MASK_USE_MSIX; //???
	}*/
    if (mpt_use_msix(s) && mpt_msix_init(s)) {
	s->flags |= MPT_MASK_USE_MSIX;
        msix_vector_use(&s->dev, 0);
    }
    else
	s->flags &= ~MPT_MASK_USE_MSIX;
#else
    s->flags &= ~MPT_MASK_USE_MSIX;
#endif

    if (!s->sas_addr) {
        s->sas_addr = ((NAA_LOCALLY_ASSIGNED_ID << 24) |
                       IEEE_COMPANY_LOCALLY_ASSIGNED) << 36;
        s->sas_addr |= (pci_bus_num(dev->bus) << 16);
        s->sas_addr |= (PCI_SLOT(dev->devfn) << 8);
        s->sas_addr |= PCI_FUNC(dev->devfn);
    }
    s->reply_queue_entries = MPTSCSI_REPLY_QUEUE_DEPTH_DEFAULT + 1;
    s->request_queue_entries = MPTSCSI_REQUEST_QUEUE_DEPTH_DEFAULT + 1;
    mpt_queues_alloc(s);

    trace_mpt_init(mpt_use_msix(s) ? "MSI-X" : "INTx",
                   mpt_is_sas(s) ? "sas" : "scsi");

    if (s->ctrl_type == MPTCTRLTYPE_SCSI_SPI) {
        s->ports = MPTSCSI_PCI_SPI_PORTS_MAX;
        s->max_devices = s->ports * MPTSCSI_PCI_SPI_DEVICES_PER_BUS_MAX;
    } else if (s->ctrl_type == MPTCTRLTYPE_SCSI_SAS) {
        s->max_devices = s->ports * MPTSCSI_PCI_SAS_DEVICES_PER_PORT_MAX;
    }

    scsi_bus_new(&s->bus, &dev->qdev, &mpt_scsi_info);
    scsi_bus_legacy_handle_cmdline(&s->bus);
    return 0;
}

static int mpt_scsi_spi_init(PCIDevice *dev)
{
    return mpt_scsi_init(dev, MPTCTRLTYPE_SCSI_SPI);
}

static int mpt_scsi_sas_init(PCIDevice *dev)
{
    return mpt_scsi_init(dev, MPTCTRLTYPE_SCSI_SAS);
}

static Property mptscsi_properties[] = {
    DEFINE_PROP_BIT("use_msi", MptState, flags,
                    MPT_FLAG_USE_MSI, false),
#ifdef USE_MSIX
    DEFINE_PROP_BIT("use_msix", MptState, flags,
                    MPT_FLAG_USE_MSIX, false),
#endif
    DEFINE_PROP_END_OF_LIST(),
};

static Property mptsas_properties[] = {
    DEFINE_PROP_UINT32("ports", MptState, ports,
                       MPTSCSI_PCI_SAS_PORTS_DEFAULT),
    DEFINE_PROP_HEX64("sas_address", MptState, sas_addr, 0),
    DEFINE_PROP_BIT("use_msi", MptState, flags,
                    MPT_FLAG_USE_MSI, false),
#ifdef USE_MSIX
    DEFINE_PROP_BIT("use_msix", MptState, flags,
                    MPT_FLAG_USE_MSIX, false),
#endif
    DEFINE_PROP_END_OF_LIST(),
};

static void mptscsi_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    /* Note: This is a PCI-X (PCI-eXtended) device.
     * Currently MSI (Message Signaled Interrupts)
     * is not supported.
     */

    pc->init = mpt_scsi_spi_init;
    pc->exit = mpt_scsi_uninit;
    pc->vendor_id = PCI_VENDOR_ID_LSI_LOGIC;
    pc->device_id = PCI_DEVICE_ID_LSI_53C1030;
    pc->class_id = PCI_CLASS_STORAGE_SCSI;
    if (vmware_hw) {
        pc->revision = 0x01;
        pc->subsystem_vendor_id = PCI_VENDOR_ID_VMWARE;
        pc->subsystem_id = 0x1976;
    } else {
        pc->subsystem_vendor_id = PCI_VENDOR_ID_LSI_LOGIC;
        pc->subsystem_id = MPTSCSI_PCI_SPI_SUBSYSTEM_ID;
    }
    dc->props = mptscsi_properties;
    dc->reset = mpt_scsi_reset;
    dc->vmsd = &vmstate_mpt;
    dc->desc = MPTSCSI_PCI_SPI_DESC;
}

static void mptsas_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    /* Note: This is a PCI-X (PCI-eXtended) device.
     * Currently MSI (Message Signaled Interrupts)
     * is not supported.
     */

    pc->init = mpt_scsi_sas_init;
    pc->exit = mpt_scsi_uninit;
    pc->romfile = 0;
    pc->vendor_id = PCI_VENDOR_ID_LSI_LOGIC;
    pc->device_id = PCI_DEVICE_ID_LSI_SAS1068;
    if (vmware_hw) {
        pc->revision = 0x01;
        pc->subsystem_vendor_id = PCI_VENDOR_ID_VMWARE;
        pc->subsystem_id = 0x1976;
    } else {
        pc->subsystem_vendor_id = PCI_VENDOR_ID_LSI_LOGIC;
        pc->subsystem_id = MPTSCSI_PCI_SAS_SUBSYSTEM_ID;
    }
    pc->class_id = PCI_CLASS_STORAGE_SAS;
    dc->props = mptsas_properties;
    dc->reset = mpt_scsi_reset;
    dc->vmsd = &vmstate_mpt;
    dc->desc = MPTSCSI_PCI_SAS_DESC;
}

static void mptsase_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->init = mpt_scsi_sas_init;
    pc->exit = mpt_scsi_uninit;
    pc->romfile = 0;
    pc->vendor_id = PCI_VENDOR_ID_LSI_LOGIC;
    if (vmware_hw) {
        pc->revision = 0x01;
	pc->device_id = PCI_DEVICE_ID_LSI_SAS1068; /* vmware blew this */
        pc->subsystem_vendor_id = PCI_VENDOR_ID_VMWARE;
        pc->subsystem_id = 0x1976;
    } else {
	pc->device_id = PCI_DEVICE_ID_LSI_SAS1068E;
	pc->subsystem_vendor_id = PCI_VENDOR_ID_LSI_LOGIC;
        pc->subsystem_id = MPTSCSI_PCI_SAS_E_SUBSYSTEM_ID;
    }
    pc->is_express = 1;
    pc->class_id = PCI_CLASS_STORAGE_SAS;
    dc->props = mptsas_properties;
    dc->reset = mpt_scsi_reset;
    dc->vmsd = &vmstate_mpt;
    dc->desc = MPTSCSI_PCI_SAS_E_DESC;
}

static const TypeInfo mpt_info[] = {
    {
        .name = MPTSCSI_PCI_SPI_CTRLNAME,
        .parent = TYPE_PCI_DEVICE,
        .instance_size = sizeof(MptState),
        .class_init = mptscsi_class_init,
    }, {
        .name = MPTSCSI_PCI_SAS_CTRLNAME,
        .parent = TYPE_PCI_DEVICE,
        .instance_size = sizeof(MptState),
        .class_init = mptsas_class_init,
    }, {
        .name = MPTSCSI_PCI_SAS_E_CTRLNAME,
        .parent = TYPE_PCI_DEVICE,
        .instance_size = sizeof(MptState),
        .class_init = mptsase_class_init,
    }
};

static void mpt_register_types(void)
{
    unsigned i;
    for (i = 0; i < ARRAY_SIZE(mpt_info); i++) {
        type_register(&mpt_info[i]);
    }
}

type_init(mpt_register_types)
