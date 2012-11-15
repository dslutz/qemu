#include "vmxnet/vmware_adjust.h"

#define PCNET_IOPORT_SIZE       0x20
#define PCNET_PNPMMIO_SIZE      0x20

#define VMXNET_PNPMMIO_MORPH_SIZE 0x04
#define VMXNET_PNPMMIO_SIZE     0x40

#define PCNET_LOOPTEST_CRC	1
#define PCNET_LOOPTEST_NOCRC	2

#include "memory.h"

/* BUS CONFIGURATION REGISTERS */
#define BCR_MSRDA    0
#define BCR_MSWRA    1
#define BCR_MC       2
#define BCR_LNKST    4
#define BCR_LED1     5
#define BCR_LED2     6
#define BCR_LED3     7
#define BCR_FDC      9
#define BCR_BSBC     18
#define BCR_EECAS    19
#define BCR_SWS      20
#define BCR_PLAT     22
#define BCR_PCISVID  23
#define BCR_PCISID   24
#define BCR_SRAMSIZ  25
#define BCR_SRAMB    26
#define BCR_SRAMIC   27
#define BCR_EBADDRL  28
#define BCR_EBADDRU  29
#define BCR_EBD      30
#define BCR_STVAL    31
#define BCR_MIICAS   32
#define BCR_MIIADDR  33
#define BCR_MIIMDR   34
#define BCR_PCIVID   35
#define BCR_PMC_A    36
#define BCR_DATA0    37
#define BCR_DATA1    38
#define BCR_DATA2    39
#define BCR_DATA3    40
#define BCR_DATA4    41
#define BCR_DATA5    42
#define BCR_DATA6    43
#define BCR_DATA7    44
#define BCR_PMR1     45
#define BCR_PMR2     46
#define BCR_PMR3     47

#define BCR_TMAULOOP(S)  !!((S)->bcr[BCR_MC  ] & 0x4000)
#define BCR_APROMWE(S)   !!((S)->bcr[BCR_MC  ] & 0x0100)
#define BCR_DWIO(S)      !!((S)->bcr[BCR_BSBC] & 0x0080)
#define BCR_SSIZE32(S)   !!((S)->bcr[BCR_SWS ] & 0x0100)
#define BCR_SWSTYLE(S)     ((S)->bcr[BCR_SWS ] & 0x00FF)

#define CSR_DRX(S)       !!(((S)->csr[15])&0x0001)
#define CSR_DTX(S)       !!(((S)->csr[15])&0x0002)
#define CSR_LOOP(S)      !!(((S)->csr[15])&0x0004)
#define CSR_DXMTFCS(S)   !!(((S)->csr[15])&0x0008)
#define CSR_INTL(S)      !!(((S)->csr[15])&0x0040)
#define CSR_DRCVPA(S)    !!(((S)->csr[15])&0x2000)
#define CSR_DRCVBC(S)    !!(((S)->csr[15])&0x4000)
#define CSR_PROM(S)      !!(((S)->csr[15])&0x8000)

typedef struct PCNetState_st PCNetState;
typedef struct PCNetState2_st PCNetState2;
typedef struct PCNetVState_st PCNetVState;

struct PCNetState_st {
    NICState *nic;
    NICConf conf;
    QEMUTimer *poll_timer;
    int rap, isr, lnkst;
    uint32_t rdra, tdra;
    uint8_t prom[16];
    uint16_t csr[128];
    uint16_t bcr[32];
    int xmit_pos;
    uint64_t timer;
    MemoryRegion mmio;
    uint8_t buffer[4096];
    qemu_irq irq;
    void (*phys_mem_read)(void *dma_opaque, hwaddr addr,
                         uint8_t *buf, int len, int do_bswap);
    void (*phys_mem_write)(void *dma_opaque, hwaddr addr,
                          uint8_t *buf, int len, int do_bswap);
    void *dma_opaque;
    int tx_busy;
    int looptest;
};

struct PCNetState2_st {
    uint64_t VMXDATA;
    uint64_t vmxRxRing;
    uint64_t vmxRxRing2;
    uint64_t vmxTxRing;
    uint16_t vmxRxRingIndex;
    uint16_t vmxRxLastInterruptIndex;
    uint16_t vmxRxRingLength;
    uint16_t vmxRxRing2Index;
    uint16_t vmxRxRing2Length;
    uint16_t vmxTxRingIndex;
    uint16_t vmxTxLastInterruptIndex;
    uint16_t vmxTxRingLength;
    uint16_t vmxInterruptEnabled;
    bool fVMXNet;
    uint32_t cLinkDownReported;
    uint16_t bcr2[50-32];
    uint16_t aMII[16];
    uint16_t aMorph[1];
    uint32_t VMXDATALENGTH;
    uint32_t aVmxnet[VMXNET_CHIP_IO_RESV_SIZE];
};

struct PCNetVState_st {
    PCNetState s1;
    PCNetState2 s2;
};

void pcnet_h_reset(void *opaque);
void vlance_h_reset(void *opaque, uint16_t vid, uint16_t sid, uint16_t svid);
void pcnet_ioport_writew(void *opaque, uint32_t addr, uint32_t val);
uint32_t pcnet_ioport_readw(void *opaque, uint32_t addr);
void pcnet_ioport_writel(void *opaque, uint32_t addr, uint32_t val);
uint32_t pcnet_ioport_readl(void *opaque, uint32_t addr);
void vlance_ioport_writew(void *opaque, uint32_t addr, uint32_t val);
uint32_t vlance_ioport_readw(void *opaque, uint32_t addr);
void vlance_ioport_writel(void *opaque, uint32_t addr, uint32_t val);
uint32_t vlance_ioport_readl(void *opaque, uint32_t addr);
uint32_t pcnet_bcr_readw(PCNetState *s, uint32_t rap);
uint32_t vlance_bcr_readw(PCNetVState *vs, uint32_t rap);
int pcnet_can_receive(NetClientState *nc);
ssize_t pcnet_receive(NetClientState *nc, const uint8_t *buf, size_t size_);
void pcnet_set_link_status(NetClientState *nc);
void vlance_set_link_status(NetClientState *nc);
int vlance_can_receive(NetClientState *nc);
ssize_t vlance_receive(NetClientState *nc, const uint8_t *buf, size_t size_);
void pcnet_common_cleanup(PCNetState *d);
int pcnet_common_init(DeviceState *dev, PCNetState *s, NetClientInfo *info);
void pcnetPollRxTx(PCNetVState *vs);
void pcnet_update_irq(PCNetState *s);
void vmxnetUpdateIrq(PCNetVState *vs);
void vmxnetAsyncTransmit(PCNetVState *vs);
extern const VMStateDescription vmstate_pcnet;
extern const VMStateDescription vmstate_vlance;
