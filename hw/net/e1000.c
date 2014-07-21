/*
 * QEMU e1000 emulation
 *
 * Software developer's manual:
 * http://download.intel.com/design/network/manuals/8254x_GBe_SDM.pdf
 *
 * Nir Peleg, Tutis Systems Ltd. for Qumranet Inc.
 * Copyright (c) 2008 Qumranet
 * Based on work done by:
 * Copyright (c) 2007 Dan Aloni
 * Copyright (c) 2004 Antony T Curtis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */


#define CONFIG_RATE_LIMIT

#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "net/tap.h"
#include "net/net.h"
#include "net/eth.h"
#include "qemu-common.h"
#include "qemu/iov.h"
#include "net/checksum.h"
#include "hw/loader.h"
#include "sysemu/sysemu.h"
#include "sysemu/dma.h"
#include <time.h>
#ifdef CONFIG_RATE_LIMIT
#include "qemu/thread.h"
#endif

#include "e1000_regs.h"

#define E1000_DEBUG

#ifdef E1000_DEBUG
enum {
    DEBUG_GENERAL,	DEBUG_IO,	DEBUG_MMIO,	DEBUG_INTERRUPT,
    DEBUG_RX,		DEBUG_TX,	DEBUG_MDIC,	DEBUG_EEPROM,
    DEBUG_UNKNOWN,	DEBUG_TXSUM,	DEBUG_TXERR,	DEBUG_RXERR,
    DEBUG_RXFILTER,     DEBUG_PHY,      DEBUG_NOTYET,
#ifdef CONFIG_RATE_LIMIT
    DEBUG_RATE,
#endif
};
#define DBGBIT(x)	(1<<DEBUG_##x)
static int debugflags = DBGBIT(TXERR) | DBGBIT(GENERAL);

#define	DBGOUT(what, fmt, ...) do { \
    if (debugflags & DBGBIT(what)) \
        fprintf(stderr, "e1000: " fmt, ## __VA_ARGS__); \
    } while (0)
#else
#define	DBGOUT(what, fmt, ...) do {} while (0)
#endif

#define IOPORT_SIZE       0x40
#define PNPMMIO_SIZE      0x20000
#define MIN_BUF_SIZE      60 /* Min. octets in an ethernet frame sans FCS */

/* this is the size past which hardware will drop packets when setting LPE=0 */
#define MAXIMUM_ETHERNET_VLAN_SIZE 1522
/* this is the size past which hardware will drop packets when setting LPE=1 */
#define MAXIMUM_ETHERNET_LPE_SIZE 16384

#define MAXIMUM_ETHERNET_HDR_LEN (14+4)

/*
 * HW models:
 *  E1000_DEV_ID_82540EM works with Windows and Linux
 *  E1000_DEV_ID_82573L OK with windoze and Linux 2.6.22,
 *	appears to perform better than 82540EM, but breaks with Linux 2.6.18
 *  E1000_DEV_ID_82544GC_COPPER appears to work; not well tested
 *  Others never tested
 */
enum { E1000_DEVID = E1000_DEV_ID_82540EM };
enum { E1000_VMW_DEVID = E1000_DEV_ID_82545EM_COPPER };

/*
 * May need to specify additional MAC-to-PHY entries --
 * Intel's Windows driver refuses to initialize unless they match
 */
enum {
    PHY_ID2_INIT = E1000_DEVID == E1000_DEV_ID_82573L ?		0xcc2 :
                   E1000_DEVID == E1000_DEV_ID_82544GC_COPPER ?	0xc30 :
                   /* default to E1000_DEV_ID_82540EM */	0xc20
};

#define NANOSECONDS_PER_SECOND  1000000000
#define USECS_PER_SECOND 1000000

typedef struct E1000State_st {
    /*< private >*/
    PCIDevice parent_obj;
    /*< public >*/

    NICState *nic;
    NICConf conf;
    MemoryRegion mmio;
    MemoryRegion io;

    uint32_t mac_reg[0x8000];
    uint16_t phy_reg[0x20];
    uint16_t eeprom_data[64];

    uint32_t rxbuf_size;
    uint32_t rxbuf_min_shift;
    struct e1000_tx {
        unsigned char header[256];
        unsigned char vlan_header[4];
        /* Fields vlan and data must not be reordered or separated. */
        unsigned char vlan[4];
        unsigned char data[0x10000];
        uint16_t size;
        unsigned char sum_needed;
        unsigned char vlan_needed;
        uint8_t ipcss;
        uint8_t ipcso;
        uint16_t ipcse;
        uint8_t tucss;
        uint8_t tucso;
        uint16_t tucse;
        uint8_t hdr_len;
        uint16_t mss;
        uint32_t paylen;
        uint16_t tso_frames;
        char tse;
        int8_t ip;
        int8_t tcp;
        char cptse;     // current packet tse bit
    } tx;

    struct {
        uint32_t val_in;	// shifted in from guest driver
        uint16_t bitnum_in;
        uint16_t bitnum_out;
        uint16_t reading;
        uint32_t old_eecd;
    } eecd_state;

    QEMUTimer *autoneg_timer;

    QEMUTimer *mit_timer;      /* Mitigation timer. */
    bool mit_timer_on;         /* Mitigation timer is running. */
    bool mit_irq_level;        /* Tracks interrupt pin level. */
    uint32_t mit_ide;          /* Tracks E1000_TXD_CMD_IDE bit. */

/* Compatibility flags for migration to/from qemu 1.3.0 and older */
#define E1000_FLAG_AUTONEG_BIT 0
#define E1000_FLAG_MIT_BIT 1
#define E1000_FLAG_AUTONEG (1 << E1000_FLAG_AUTONEG_BIT)
#define E1000_FLAG_MIT (1 << E1000_FLAG_MIT_BIT)
    uint32_t compat_flags;

    bool	 peer_has_vhdr;

#ifdef CONFIG_RATE_LIMIT
    uint64_t     bps_limit;
    uint64_t     slice_end;
    QemuThread   *co_thread;
    QemuCond     *co_cond;
    QemuMutex    co_mutex;
    bool         io_limits_enabled;
    bool         co_running;
    bool         co_shutdown;
    bool         co_cond_inited;
#endif
} E1000State;

#define TYPE_E1000 "e1000"
#define TYPE_E1000VMW "e1000_vmw"

#define E1000(obj) \
    OBJECT_CHECK(E1000State, (obj), TYPE_E1000)
#define E1000VMW(obj) \
    OBJECT_CHECK(E1000State, (obj), TYPE_E1000VMW)

#ifdef CONFIG_RATE_LIMIT
#define MUTEX_TRYLOCK(s)               \
        qemu_mutex_trylock(&s->co_mutex)

#define MUTEX_LOCK(s)                  \
        qemu_mutex_lock(&s->co_mutex);

#define MUTEX_UNLOCK(s)                \
        qemu_mutex_unlock(&s->co_mutex);
#else
#define MUTEX_TRYLOCK(s)  0
#define MUTEX_LOCK(s)
#define MUTEX_UNLOCK(s)
#endif

#define	defreg(x)	x = (E1000_##x>>2)
enum {
    defreg(CTRL),	defreg(EECD),	defreg(EERD),	defreg(GPRC),
    defreg(GPTC),	defreg(ICR),	defreg(ICS),	defreg(IMC),
    defreg(IMS),	defreg(LEDCTL),	defreg(MANC),	defreg(MDIC),
    defreg(MPC),	defreg(PBA),	defreg(RCTL),	defreg(RDBAH),
    defreg(RDBAL),	defreg(RDH),	defreg(RDLEN),	defreg(RDT),
    defreg(STATUS),	defreg(SWSM),	defreg(TCTL),	defreg(TDBAH),
    defreg(TDBAL),	defreg(TDH),	defreg(TDLEN),	defreg(TDT),
    defreg(TORH),	defreg(TORL),	defreg(TOTH),	defreg(TOTL),
    defreg(TPR),	defreg(TPT),	defreg(TXDCTL),	defreg(WUFC),
    defreg(RA),		defreg(MTA),	defreg(CRCERRS),defreg(VFTA),
    defreg(VET),        defreg(RDTR),   defreg(RADV),   defreg(TADV),
    defreg(ITR),	defreg(RXCSUM),
};


#ifdef CONFIG_RATE_LIMIT
static void e1000_io_limits_enable(E1000State *s, uint64_t bytes_per_int, uint32_t int_usec)
{
    if (bytes_per_int == 0 || int_usec == 0) {
	/* disable the limit by setting it to a gigantic value */
	s->bps_limit = (~0ULL) >> 4;
	if (s->co_cond_inited)
            qemu_cond_signal(s->co_cond);
	printf("setting bps_limit to infinite\n");

	return;
    }

    // check limits for sanity

    if ((8 * bytes_per_int * USECS_PER_SECOND) / int_usec > 0) {

	s->bps_limit = 8 * bytes_per_int * USECS_PER_SECOND / int_usec;
	printf ("setting bps_limit to %lu (%lu, %u)\n", 
		s->bps_limit, bytes_per_int, int_usec);
	if (!s->co_cond_inited) {
	    /* 
	     * Only initialize these once. Don't reset as they may
	     * still be in use.
	     */
	    s->co_cond_inited = true;
	    s->co_cond = g_malloc0(sizeof(QemuCond));
	    qemu_cond_init(s->co_cond);
	}
	s->slice_end = 0;
	s->io_limits_enabled = true;
	s->co_shutdown = false;
    } else {
	printf("no QOS rate limit set (bytes_per_int: %lu int_usec: %u)\n", 
               bytes_per_int, int_usec);
    }
}
#endif

static void
e1000_link_down(E1000State *s)
{
    s->mac_reg[STATUS] &= ~E1000_STATUS_LU;
    s->phy_reg[PHY_STATUS] &= ~MII_SR_LINK_STATUS;
}

static void
e1000_link_up(E1000State *s)
{
    s->mac_reg[STATUS] |= E1000_STATUS_LU;
    s->phy_reg[PHY_STATUS] |= MII_SR_LINK_STATUS;
}

static void
set_phy_ctrl(E1000State *s, int index, uint16_t val)
{
    /*
     * QEMU 1.3 does not support link auto-negotiation emulation, so if we
     * migrate during auto negotiation, after migration the link will be
     * down.
     */
    if (!(s->compat_flags & E1000_FLAG_AUTONEG)) {
        return;
    }
    if ((val & MII_CR_AUTO_NEG_EN) && (val & MII_CR_RESTART_AUTO_NEG)) {
        e1000_link_down(s);
        s->phy_reg[PHY_STATUS] &= ~MII_SR_AUTONEG_COMPLETE;
        DBGOUT(PHY, "Start link auto negotiation\n");
        timer_mod(s->autoneg_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);
    }
}

static void
e1000_autoneg_timer(void *opaque)
{
    E1000State *s = opaque;
    if (!qemu_get_queue(s->nic)->link_down) {
        e1000_link_up(s);
    }
    s->phy_reg[PHY_STATUS] |= MII_SR_AUTONEG_COMPLETE;
    DBGOUT(PHY, "Auto negotiation is completed\n");
}

static void (*phyreg_writeops[])(E1000State *, int, uint16_t) = {
    [PHY_CTRL] = set_phy_ctrl,
};

enum { NPHYWRITEOPS = ARRAY_SIZE(phyreg_writeops) };

enum { PHY_R = 1, PHY_W = 2, PHY_RW = PHY_R | PHY_W };
static const char phy_regcap[0x20] = {
    [PHY_STATUS] = PHY_R,	[M88E1000_EXT_PHY_SPEC_CTRL] = PHY_RW,
    [PHY_ID1] = PHY_R,		[M88E1000_PHY_SPEC_CTRL] = PHY_RW,
    [PHY_CTRL] = PHY_RW,	[PHY_1000T_CTRL] = PHY_RW,
    [PHY_LP_ABILITY] = PHY_R,	[PHY_1000T_STATUS] = PHY_R,
    [PHY_AUTONEG_ADV] = PHY_RW,	[M88E1000_RX_ERR_CNTR] = PHY_R,
    [PHY_ID2] = PHY_R,		[M88E1000_PHY_SPEC_STATUS] = PHY_R
};

static const uint16_t phy_reg_init[] = {
    [PHY_CTRL] = 0x1140,
    [PHY_STATUS] = 0x794d, /* link initially up with not completed autoneg */
    [PHY_ID1] = 0x141,				[PHY_ID2] = PHY_ID2_INIT,
    [PHY_1000T_CTRL] = 0x0e00,			[M88E1000_PHY_SPEC_CTRL] = 0x360,
    [M88E1000_EXT_PHY_SPEC_CTRL] = 0x0d60,	[PHY_AUTONEG_ADV] = 0xde1,
    [PHY_LP_ABILITY] = 0x1e0,			[PHY_1000T_STATUS] = 0x3c00,
    [M88E1000_PHY_SPEC_STATUS] = 0xac00,
};

static const uint32_t mac_reg_init[] = {
    [PBA] =     0x00100030,
    [LEDCTL] =  0x602,
    [CTRL] =    E1000_CTRL_SWDPIN2 | E1000_CTRL_SWDPIN0 |
                E1000_CTRL_SPD_1000 | E1000_CTRL_SLU,
    [STATUS] =  0x80000000 | E1000_STATUS_GIO_MASTER_ENABLE |
                E1000_STATUS_ASDV | E1000_STATUS_MTXCKOK |
                E1000_STATUS_SPEED_1000 | E1000_STATUS_FD |
                E1000_STATUS_LU,
    [MANC] =    E1000_MANC_EN_MNG2HOST | E1000_MANC_RCV_TCO_EN |
                E1000_MANC_ARP_EN | E1000_MANC_0298_EN |
                E1000_MANC_RMCP_EN,
};

/* Helper function, *curr == 0 means the value is not set */
static inline void
mit_update_delay(uint32_t *curr, uint32_t value)
{
    if (value && (*curr == 0 || value < *curr)) {
        *curr = value;
    }
}

static void
set_interrupt_cause(E1000State *s, int index, uint32_t val)
{
    PCIDevice *d = PCI_DEVICE(s);
    uint32_t pending_ints;
    uint32_t mit_delay;

    if (val && (E1000_DEVID >= E1000_DEV_ID_82547EI_MOBILE)) {
        /* Only for 8257x */
        val |= E1000_ICR_INT_ASSERTED;
    }
    s->mac_reg[ICR] = val;

    /*
     * Make sure ICR and ICS registers have the same value.
     * The spec says that the ICS register is write-only.  However in practice,
     * on real hardware ICS is readable, and for reads it has the same value as
     * ICR (except that ICS does not have the clear on read behaviour of ICR).
     *
     * The VxWorks PRO/1000 driver uses this behaviour.
     */
    s->mac_reg[ICS] = val;

    pending_ints = (s->mac_reg[IMS] & s->mac_reg[ICR]);
    if (!s->mit_irq_level && pending_ints) {
        /*
         * Here we detect a potential raising edge. We postpone raising the
         * interrupt line if we are inside the mitigation delay window
         * (s->mit_timer_on == 1).
         * We provide a partial implementation of interrupt mitigation,
         * emulating only RADV, TADV and ITR (lower 16 bits, 1024ns units for
         * RADV and TADV, 256ns units for ITR). RDTR is only used to enable
         * RADV; relative timers based on TIDV and RDTR are not implemented.
         */
        if (s->mit_timer_on) {
            return;
        }
        if (s->compat_flags & E1000_FLAG_MIT) {
            /* Compute the next mitigation delay according to pending
             * interrupts and the current values of RADV (provided
             * RDTR!=0), TADV and ITR.
             * Then rearm the timer.
             */
            mit_delay = 0;
            if (s->mit_ide &&
                    (pending_ints & (E1000_ICR_TXQE | E1000_ICR_TXDW))) {
                mit_update_delay(&mit_delay, s->mac_reg[TADV] * 4);
            }
            if (s->mac_reg[RDTR] && (pending_ints & E1000_ICS_RXT0)) {
                mit_update_delay(&mit_delay, s->mac_reg[RADV] * 4);
            }
            mit_update_delay(&mit_delay, s->mac_reg[ITR]);

            if (mit_delay) {
                s->mit_timer_on = 1;
                timer_mod(s->mit_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                          mit_delay * 256);
            }
            s->mit_ide = 0;
        }
    }

    s->mit_irq_level = (pending_ints != 0);
    pci_set_irq(d, s->mit_irq_level);
}

static void
e1000_mit_timer(void *opaque)
{
    E1000State *s = opaque;

    s->mit_timer_on = 0;

    if (MUTEX_TRYLOCK(s)) {
        /* if we can't get the mutex, just return */
        return;
    }

    /* Call set_interrupt_cause to update the irq level (if necessary). */
    set_interrupt_cause(s, 0, s->mac_reg[ICR]);
    MUTEX_UNLOCK(s);
}

static void
set_ics(E1000State *s, int index, uint32_t val)
{
    DBGOUT(INTERRUPT, "set_ics %x, ICR %x, IMR %x\n", val, s->mac_reg[ICR],
        s->mac_reg[IMS]);
    set_interrupt_cause(s, 0, val | s->mac_reg[ICR]);
}

static void
set_ics_lock(E1000State *s, int index, uint32_t val)
{
    MUTEX_LOCK(s);
    set_ics(s, index, val);
    MUTEX_UNLOCK(s);
}

static int
rxbufsize(uint32_t v)
{
    v &= E1000_RCTL_BSEX | E1000_RCTL_SZ_16384 | E1000_RCTL_SZ_8192 |
         E1000_RCTL_SZ_4096 | E1000_RCTL_SZ_2048 | E1000_RCTL_SZ_1024 |
         E1000_RCTL_SZ_512 | E1000_RCTL_SZ_256;
    switch (v) {
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_16384:
        return 16384;
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_8192:
        return 8192;
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_4096:
        return 4096;
    case E1000_RCTL_SZ_1024:
        return 1024;
    case E1000_RCTL_SZ_512:
        return 512;
    case E1000_RCTL_SZ_256:
        return 256;
    }
    return 2048;
}

static void e1000_reset(void *opaque)
{
    E1000State *d = opaque;
    uint8_t *macaddr = d->conf.macaddr.a;
    int i;

#ifdef CONFIG_RATE_LIMIT
    printf("e1000_reset\n");

    while (d->co_running) {
        d->co_shutdown = true;
        qemu_cond_signal(d->co_cond);
        sched_yield();
    }
#endif

    MUTEX_LOCK(d);
	
    timer_del(d->autoneg_timer);
    timer_del(d->mit_timer);
    d->mit_timer_on = 0;
    d->mit_irq_level = 0;
    d->mit_ide = 0;
    memset(d->phy_reg, 0, sizeof d->phy_reg);
    memmove(d->phy_reg, phy_reg_init, sizeof phy_reg_init);
    memset(d->mac_reg, 0, sizeof d->mac_reg);
    memmove(d->mac_reg, mac_reg_init, sizeof mac_reg_init);
    d->rxbuf_min_shift = 1;
    memset(&d->tx, 0, sizeof d->tx);

    if (qemu_get_queue(d->nic)->link_down) {
        e1000_link_down(d);
    }

    /* Some guests expect pre-initialized RAH/RAL (AddrValid flag + MACaddr) */
    d->mac_reg[RA] = 0;
    d->mac_reg[RA + 1] = E1000_RAH_AV;
    for (i = 0; i < 4; i++) {
        d->mac_reg[RA] |= macaddr[i] << (8 * i);
        d->mac_reg[RA + 1] |= (i < 2) ? macaddr[i + 4] << (8 * i) : 0;
    }

    MUTEX_UNLOCK(d);
    qemu_format_nic_info_str(qemu_get_queue(d->nic), macaddr);
}

static void
set_ctrl(E1000State *s, int index, uint32_t val)
{
    /* RST is self clearing */
    s->mac_reg[CTRL] = val & ~E1000_CTRL_RST;
}

static void
set_rxcsum(E1000State *s, int index, uint32_t val)
{
    printf("setting RXCSUM to 0x%x (was 0x%x)\n", val, s->mac_reg[RXCSUM]);
    s->mac_reg[RXCSUM] = val;
}

static void
set_rx_control(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[RCTL] = val;
    s->rxbuf_size = rxbufsize(val);
    s->rxbuf_min_shift = ((val / E1000_RCTL_RDMTS_QUAT) & 3) + 1;
    DBGOUT(RX, "RCTL: %d, mac_reg[RCTL] = 0x%x\n", s->mac_reg[RDT],
           s->mac_reg[RCTL]);
    qemu_flush_queued_packets(qemu_get_queue(s->nic));
}

static void
set_mdic(E1000State *s, int index, uint32_t val)
{
    uint32_t data = val & E1000_MDIC_DATA_MASK;
    uint32_t addr = ((val & E1000_MDIC_REG_MASK) >> E1000_MDIC_REG_SHIFT);

    if ((val & E1000_MDIC_PHY_MASK) >> E1000_MDIC_PHY_SHIFT != 1) // phy #
        val = s->mac_reg[MDIC] | E1000_MDIC_ERROR;
    else if (val & E1000_MDIC_OP_READ) {
        DBGOUT(MDIC, "MDIC read reg 0x%x\n", addr);
        if (!(phy_regcap[addr] & PHY_R)) {
            DBGOUT(MDIC, "MDIC read reg %x unhandled\n", addr);
            val |= E1000_MDIC_ERROR;
        } else
            val = (val ^ data) | s->phy_reg[addr];
    } else if (val & E1000_MDIC_OP_WRITE) {
        DBGOUT(MDIC, "MDIC write reg 0x%x, value 0x%x\n", addr, data);
        if (!(phy_regcap[addr] & PHY_W)) {
            DBGOUT(MDIC, "MDIC write reg %x unhandled\n", addr);
            val |= E1000_MDIC_ERROR;
        } else {
            if (addr < NPHYWRITEOPS && phyreg_writeops[addr]) {
                phyreg_writeops[addr](s, index, data);
            }
            s->phy_reg[addr] = data;
        }
    }
    s->mac_reg[MDIC] = val | E1000_MDIC_READY;

    if (val & E1000_MDIC_INT_EN) {
        set_ics(s, 0, E1000_ICR_MDAC);
    }
}

static uint32_t
get_eecd(E1000State *s, int index)
{
    uint32_t ret = E1000_EECD_PRES|E1000_EECD_GNT | s->eecd_state.old_eecd;

    DBGOUT(EEPROM, "reading eeprom bit %d (reading %d)\n",
           s->eecd_state.bitnum_out, s->eecd_state.reading);
    if (!s->eecd_state.reading ||
        ((s->eeprom_data[(s->eecd_state.bitnum_out >> 4) & 0x3f] >>
          ((s->eecd_state.bitnum_out & 0xf) ^ 0xf))) & 1)
        ret |= E1000_EECD_DO;
    return ret;
}

static void
set_eecd(E1000State *s, int index, uint32_t val)
{
    uint32_t oldval = s->eecd_state.old_eecd;

    s->eecd_state.old_eecd = val & (E1000_EECD_SK | E1000_EECD_CS |
            E1000_EECD_DI|E1000_EECD_FWE_MASK|E1000_EECD_REQ);
    if (!(E1000_EECD_CS & val))			// CS inactive; nothing to do
	return;
    if (E1000_EECD_CS & (val ^ oldval)) {	// CS rise edge; reset state
	s->eecd_state.val_in = 0;
	s->eecd_state.bitnum_in = 0;
	s->eecd_state.bitnum_out = 0;
	s->eecd_state.reading = 0;
    }
    if (!(E1000_EECD_SK & (val ^ oldval)))	// no clock edge
        return;
    if (!(E1000_EECD_SK & val)) {		// falling edge
        s->eecd_state.bitnum_out++;
        return;
    }
    s->eecd_state.val_in <<= 1;
    if (val & E1000_EECD_DI)
        s->eecd_state.val_in |= 1;
    if (++s->eecd_state.bitnum_in == 9 && !s->eecd_state.reading) {
        s->eecd_state.bitnum_out = ((s->eecd_state.val_in & 0x3f)<<4)-1;
        s->eecd_state.reading = (((s->eecd_state.val_in >> 6) & 7) ==
            EEPROM_READ_OPCODE_MICROWIRE);
    }
    DBGOUT(EEPROM, "eeprom bitnum in %d out %d, reading %d\n",
           s->eecd_state.bitnum_in, s->eecd_state.bitnum_out,
           s->eecd_state.reading);
}

static uint32_t
flash_eerd_read(E1000State *s, int x)
{
    unsigned int index, r = s->mac_reg[EERD] & ~E1000_EEPROM_RW_REG_START;

    if ((s->mac_reg[EERD] & E1000_EEPROM_RW_REG_START) == 0)
        return (s->mac_reg[EERD]);

    if ((index = r >> E1000_EEPROM_RW_ADDR_SHIFT) > EEPROM_CHECKSUM_REG)
        return (E1000_EEPROM_RW_REG_DONE | r);

    return ((s->eeprom_data[index] << E1000_EEPROM_RW_REG_DATA) |
           E1000_EEPROM_RW_REG_DONE | r);
}

static void
putsum(uint8_t *data, uint32_t n, uint32_t sloc, uint32_t css, uint32_t cse)
{
    uint32_t sum;

    if (cse && cse < n)
        n = cse + 1;
    if (sloc < n-1) {
        sum = net_checksum_add(n-css, data+css);
        stw_be_p(data + sloc, net_checksum_finish(sum));
    }
}

static inline int
vlan_enabled(E1000State *s)
{
    return ((s->mac_reg[CTRL] & E1000_CTRL_VME) != 0);
}

static inline int
vlan_rx_filter_enabled(E1000State *s)
{
    return ((s->mac_reg[RCTL] & E1000_RCTL_VFE) != 0);
}

static inline int
is_vlan_packet(E1000State *s, const uint8_t *buf)
{
    return (be16_to_cpup((uint16_t *)(buf + 12)) ==
                le16_to_cpup((uint16_t *)(s->mac_reg + VET)));
}

static inline int
is_vlan_txd(uint32_t txd_lower)
{
    return ((txd_lower & E1000_TXD_CMD_VLE) != 0);
}

/* FCS aka Ethernet CRC-32. We don't get it from backends and can't
 * fill it in, just pad descriptor length by 4 bytes unless guest
 * told us to strip it off the packet. */
static inline int
fcs_len(E1000State *s)
{
    return (s->mac_reg[RCTL] & E1000_RCTL_SECRC) ? 0 : 4;
}

#define FUDGE 125000 /* nanosleep + overhead */

static void
e1000_send_packet(E1000State *s, const uint8_t *buf, int size)
{
    NetClientState *nc = qemu_get_queue(s->nic);
    struct e1000_tx *tp = &s->tx;

    if (s->phy_reg[PHY_CTRL] & MII_CR_LOOPBACK) {
        MUTEX_UNLOCK(s);
        nc->info->receive(nc, buf, size);
        MUTEX_LOCK(s);
        return;
    }

    MUTEX_UNLOCK(s);

#ifdef CONFIG_RATE_LIMIT
    if (s->io_limits_enabled) {
        uint64_t delay;
        uint64_t pkt_time = ((uint64_t)size * 8 * NANOSECONDS_PER_SECOND) / s->bps_limit;
        uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

        delay = now >= s->slice_end ? 0 : s->slice_end - now;

        if (delay > FUDGE) {
            struct timespec req;

            req.tv_sec = 0;
            req.tv_nsec = delay - FUDGE;
            nanosleep(&req, NULL);
            now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        }

        if (s->slice_end > now) now = s->slice_end;
        s->slice_end = now + pkt_time;
    }
#endif

    /* see whether we have the option of doing any offloading */

    if (!s->peer_has_vhdr) {
        qemu_send_packet(nc, buf, size);
        MUTEX_LOCK(s);
        return;
    } 

    /* OK, offloading is allowed and we may need to do some */
    /* we're not doing UDP offloading, by the way */

    struct iovec iov[2];
    struct virtio_net_hdr virt_hdr;

    memset(&virt_hdr, 0, sizeof(virt_hdr));
    
    iov[0].iov_base = &virt_hdr;
    iov[0].iov_len = sizeof(virt_hdr);

    iov[1].iov_base = (uint8_t *)buf;
    iov[1].iov_len = size;

    /* is this a payload that allows for any offloading? */

    if (!(s->mac_reg[RXCSUM] & E1000_RXCSUM_TUOFL) ||
        !(tp->tcp) ||
        !(tp->tucso) ||
        !(tp->sum_needed & E1000_TXD_POPTS_TXSM)) {

        qemu_sendv_packet(nc, iov, 2);
        MUTEX_LOCK(s);
        return;
    }

    /* Note: segmentation offloading implies checksum offloading */

    virt_hdr.gso_type = VIRTIO_NET_HDR_GSO_NONE;
    virt_hdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    virt_hdr.csum_start = tp->tucso - offsetof(struct tcp_hdr, th_sum);
    virt_hdr.csum_offset = offsetof(struct tcp_hdr, th_sum);

    if (tp->tse && tp->cptse) {
        virt_hdr.hdr_len = tp->hdr_len;
        virt_hdr.gso_size = IP_FRAG_ALIGN_SIZE(tp->mss);
        if (tp->ip)
            virt_hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
        else
            virt_hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
    }

    qemu_sendv_packet(nc, iov, 2);

    MUTEX_LOCK(s);

    return;
}

static void
xmit_seg(E1000State *s)
{
    uint16_t len, *sp;
    unsigned int frames = s->tx.tso_frames, css, sofar, n;
    struct e1000_tx *tp = &s->tx;

    if (tp->tse && tp->cptse) {
        css = tp->ipcss;
        DBGOUT(TXSUM, "frames %d size %d ipcss %d\n",
               frames, tp->size, css);
        if (tp->ip) {		// IPv4
            stw_be_p(tp->data+css+2, tp->size - css);
            stw_be_p(tp->data+css+4,
                          be16_to_cpup((uint16_t *)(tp->data+css+4))+frames);
        } else			// IPv6
            stw_be_p(tp->data+css+4, tp->size - css);
        css = tp->tucss;
        len = tp->size - css;
        DBGOUT(TXSUM, "tcp %d tucss %d len %d\n", tp->tcp, css, len);
        if (tp->tcp) {
            sofar = frames * tp->mss;
            stl_be_p(tp->data+css+4, ldl_be_p(tp->data+css+4)+sofar); /* seq */
            if (tp->paylen - sofar > tp->mss)
                tp->data[css + 13] &= ~9;		// PSH, FIN
        } else	// UDP
            stw_be_p(tp->data+css+4, len);
        if (tp->sum_needed & E1000_TXD_POPTS_TXSM) {
            unsigned int phsum;
            // add pseudo-header length before checksum calculation
            sp = (uint16_t *)(tp->data + tp->tucso);
            phsum = be16_to_cpup(sp) + len;
            phsum = (phsum >> 16) + (phsum & 0xffff);
            stw_be_p(sp, phsum);
        }
        tp->tso_frames++;
    }

    if ((tp->sum_needed & E1000_TXD_POPTS_TXSM) &&
        !((s->peer_has_vhdr) && 
          (s->mac_reg[RXCSUM] & E1000_RXCSUM_TUOFL) &&
          tp->tcp)
        ) {
        putsum(tp->data, tp->size, tp->tucso, tp->tucss, tp->tucse);
    }
    if (tp->sum_needed & E1000_TXD_POPTS_IXSM)
        putsum(tp->data, tp->size, tp->ipcso, tp->ipcss, tp->ipcse);
    if (tp->vlan_needed) {
        memmove(tp->vlan, tp->data, 4);
        memmove(tp->data, tp->data + 4, 8);
        memcpy(tp->data + 8, tp->vlan_header, 4);
        e1000_send_packet(s, tp->vlan, tp->size + 4);
    } else
        e1000_send_packet(s, tp->data, tp->size);
    s->mac_reg[TPT]++;
    s->mac_reg[GPTC]++;
    n = s->mac_reg[TOTL];
    if ((s->mac_reg[TOTL] += s->tx.size) < n)
        s->mac_reg[TOTH]++;
}

static void
process_tx_desc(E1000State *s, struct e1000_tx_desc *dp)
{
    PCIDevice *d = PCI_DEVICE(s);
    uint32_t txd_lower = le32_to_cpu(dp->lower.data);
    uint32_t dtype = txd_lower & (E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D);
    unsigned int split_size = txd_lower & 0xffff, bytes, sz, op;
    unsigned int msh = 0xfffff;
    uint64_t addr;
    struct e1000_context_desc *xp = (struct e1000_context_desc *)dp;
    struct e1000_tx *tp = &s->tx;

    s->mit_ide |= (txd_lower & E1000_TXD_CMD_IDE);
    if (dtype == E1000_TXD_CMD_DEXT) {	// context descriptor
        op = le32_to_cpu(xp->cmd_and_length);
        tp->ipcss = xp->lower_setup.ip_fields.ipcss;
        tp->ipcso = xp->lower_setup.ip_fields.ipcso;
        tp->ipcse = le16_to_cpu(xp->lower_setup.ip_fields.ipcse);
        tp->tucss = xp->upper_setup.tcp_fields.tucss;
        tp->tucso = xp->upper_setup.tcp_fields.tucso;
        tp->tucse = le16_to_cpu(xp->upper_setup.tcp_fields.tucse);
        tp->paylen = op & 0xfffff;
        tp->hdr_len = xp->tcp_seg_setup.fields.hdr_len;
        tp->mss = le16_to_cpu(xp->tcp_seg_setup.fields.mss);
        tp->ip = (op & E1000_TXD_CMD_IP) ? 1 : 0;
        tp->tcp = (op & E1000_TXD_CMD_TCP) ? 1 : 0;
        tp->tse = (op & E1000_TXD_CMD_TSE) ? 1 : 0;
        tp->tso_frames = 0;
        if (tp->tucso == 0) {   // this is probably wrong
            DBGOUT(TXSUM, "TCP/UDP: cso 0!\n");
            tp->tucso = tp->tucss + (tp->tcp ? 16 : 6);
        }
        return;
    } else if (dtype == (E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D)) {
        // data descriptor
        if (tp->size == 0) {
            tp->sum_needed = le32_to_cpu(dp->upper.data) >> 8;
        }
        tp->cptse = ( txd_lower & E1000_TXD_CMD_TSE ) ? 1 : 0;
    } else {
        // legacy descriptor
        tp->cptse = 0;
    }

    if (vlan_enabled(s) && is_vlan_txd(txd_lower) &&
        (tp->cptse || txd_lower & E1000_TXD_CMD_EOP)) {
        tp->vlan_needed = 1;
        stw_be_p(tp->vlan_header,
                      le16_to_cpup((uint16_t *)(s->mac_reg + VET)));
        stw_be_p(tp->vlan_header + 2,
                      le16_to_cpu(dp->upper.fields.special));
    }
        
    addr = le64_to_cpu(dp->buffer_addr);
    if (tp->tse && tp->cptse) {
        if (s->peer_has_vhdr) {
            msh = sizeof(tp->data);
        } else
            msh = tp->hdr_len + tp->mss;
        do {
            bytes = split_size;
            if (tp->size + bytes > msh)
                bytes = msh - tp->size;

            bytes = MIN(sizeof(tp->data) - tp->size, bytes);
            pci_dma_read(d, addr, tp->data + tp->size, bytes);
            sz = tp->size + bytes;
            if (sz >= tp->hdr_len && tp->size < tp->hdr_len) {
                memmove(tp->header, tp->data, tp->hdr_len);
            }
            tp->size = sz;
            addr += bytes;
            if (sz == msh) {
                xmit_seg(s);
                memmove(tp->data, tp->header, tp->hdr_len);
                tp->size = tp->hdr_len;
            }
        } while (split_size -= bytes);
    } else if (!tp->tse && tp->cptse) {
        // context descriptor TSE is not set, while data descriptor TSE is set
        DBGOUT(TXERR, "TCP segmentation error\n");
    } else {
        split_size = MIN(sizeof(tp->data) - tp->size, split_size);
        pci_dma_read(d, addr, tp->data + tp->size, split_size);
        tp->size += split_size;
    }

    if (!(txd_lower & E1000_TXD_CMD_EOP))
        return;
    if (!(tp->tse && tp->cptse && tp->size < tp->hdr_len)) {
        xmit_seg(s);
    }
    tp->tso_frames = 0;
    tp->sum_needed = 0;
    tp->vlan_needed = 0;
    tp->size = 0;
    tp->cptse = 0;
}

static uint32_t
txdesc_writeback(E1000State *s, dma_addr_t base, struct e1000_tx_desc *dp)
{
    PCIDevice *d = PCI_DEVICE(s);
    uint32_t txd_upper, txd_lower = le32_to_cpu(dp->lower.data);

    if (!(txd_lower & (E1000_TXD_CMD_RS|E1000_TXD_CMD_RPS)))
        return 0;
    txd_upper = (le32_to_cpu(dp->upper.data) | E1000_TXD_STAT_DD) &
                ~(E1000_TXD_STAT_EC | E1000_TXD_STAT_LC | E1000_TXD_STAT_TU);
    dp->upper.data = cpu_to_le32(txd_upper);
    pci_dma_write(d, base + ((char *)&dp->upper - (char *)dp),
                  &dp->upper, sizeof(dp->upper));
    return E1000_ICR_TXDW;
}

static uint64_t tx_desc_base(E1000State *s)
{
    uint64_t bah = s->mac_reg[TDBAH];
    uint64_t bal = s->mac_reg[TDBAL] & ~0xf;

    return (bah << 32) + bal;
}

static void
start_xmit_co(E1000State *s)
{
    PCIDevice *d = PCI_DEVICE(s);
    dma_addr_t base;
    struct e1000_tx_desc desc;
    // uint32_t tdh_start = s->mac_reg[TDH],
    uint32_t cause = E1000_ICS_TXQE;

    while ((s->mac_reg[TDH] != s->mac_reg[TDT])
#ifdef CONFIG_RATE_LIMIT
           && !s->co_shutdown
#endif
        ) {
        base = tx_desc_base(s) +
               sizeof(struct e1000_tx_desc) * s->mac_reg[TDH];
        pci_dma_read(d, base, &desc, sizeof(desc));

        DBGOUT(TX, "index %d: %p : %x %x\n", s->mac_reg[TDH],
               (void *)(intptr_t)desc.buffer_addr, desc.lower.data,
               desc.upper.data);

        process_tx_desc(s, &desc);
        cause |= txdesc_writeback(s, base, &desc);

        if (++s->mac_reg[TDH] * sizeof(desc) >= s->mac_reg[TDLEN])
            s->mac_reg[TDH] = 0;
#if 0
        /* the following could happen if guest sw assigns
         * bogus values to TDT/TDLEN.
         * there's nothing too intelligent we could do about this.
         */
        if (s->mac_reg[TDH] == tdh_start && !s->co_shutdown) {
            DBGOUT(TXERR, "TDH wraparound @%x, TDT %x, TDLEN %x\n",
                   tdh_start, s->mac_reg[TDT], s->mac_reg[TDLEN]);
            break;
        }
#endif
    }
    set_ics(s, 0, cause);
}

#ifdef CONFIG_RATE_LIMIT
static gpointer e1000_xmit_co_entry(gpointer opaque)
{
    E1000State *s = (E1000State *)opaque;

    DBGOUT(RATE, "xmit_co_entry: s=%p\n", opaque);
    while (!s->co_shutdown) {
        MUTEX_LOCK(s);
        start_xmit_co(s);
        qemu_cond_wait(s->co_cond, &s->co_mutex);
        MUTEX_UNLOCK(s);
    }
    s->co_running = false;
    s->co_shutdown = false;
    return NULL;
}
#endif

static void
start_xmit(E1000State *s)
{
#ifdef CONFIG_RATE_LIMIT
    PCIDevice *pdev = PCI_DEVICE(s);
#endif
    if (!(s->mac_reg[TCTL] & E1000_TCTL_EN)) {
        DBGOUT(TX, "tx disabled\n");
        return;
    }

#ifdef CONFIG_RATE_LIMIT
    if (pdev->qdev.bytes_per_int || pdev->qdev.int_usec) {
        e1000_io_limits_enable(s, pdev->qdev.bytes_per_int, 
                               pdev->qdev.int_usec);
        pdev->qdev.bytes_per_int = 0;
        pdev->qdev.int_usec = 0;
    }
#endif

#ifdef CONFIG_RATE_LIMIT
    if (s->io_limits_enabled) {
        if (!s->co_running) {
            s->co_running = true;
            DBGOUT(RATE, "e1000 starting coroutine: s=%p\n", s);
            s->co_thread = g_malloc0(sizeof(QemuThread));
            qemu_thread_create(s->co_thread, "e1000", e1000_xmit_co_entry, s, QEMU_THREAD_JOINABLE);
        }
        else
            qemu_cond_signal(s->co_cond);
    }
    else
        start_xmit_co(s);
#else
    start_xmit_co(s);
#endif
}

static int
receive_filter(E1000State *s, const uint8_t *buf, int size)
{
    static const uint8_t bcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const int mta_shift[] = {4, 3, 2, 0};
    uint32_t f, rctl = s->mac_reg[RCTL], ra[2], *rp;

    if (is_vlan_packet(s, buf) && vlan_rx_filter_enabled(s)) {
        uint16_t vid = be16_to_cpup((uint16_t *)(buf + 14));
        uint32_t vfta = le32_to_cpup((uint32_t *)(s->mac_reg + VFTA) +
                                     ((vid >> 5) & 0x7f));
        if ((vfta & (1 << (vid & 0x1f))) == 0)
            return 0;
    }

    if (rctl & E1000_RCTL_UPE)          // promiscuous
        return 1;

    if ((buf[0] & 1) && (rctl & E1000_RCTL_MPE))    // promiscuous mcast
        return 1;

    if ((rctl & E1000_RCTL_BAM) && !memcmp(buf, bcast, sizeof bcast))
        return 1;

    for (rp = s->mac_reg + RA; rp < s->mac_reg + RA + 32; rp += 2) {
        if (!(rp[1] & E1000_RAH_AV))
            continue;
        ra[0] = cpu_to_le32(rp[0]);
        ra[1] = cpu_to_le32(rp[1]);
        if (!memcmp(buf, (uint8_t *)ra, 6)) {
            DBGOUT(RXFILTER,
                   "unicast match[%d]: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   (int)(rp - s->mac_reg - RA)/2,
                   buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
            return 1;
        }
    }
    DBGOUT(RXFILTER, "unicast mismatch: %02x:%02x:%02x:%02x:%02x:%02x\n",
           buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);

    f = mta_shift[(rctl >> E1000_RCTL_MO_SHIFT) & 3];
    f = (((buf[5] << 8) | buf[4]) >> f) & 0xfff;
    if (s->mac_reg[MTA + (f >> 5)] & (1 << (f & 0x1f)))
        return 1;
    DBGOUT(RXFILTER,
           "dropping, inexact filter mismatch: %02x:%02x:%02x:%02x:%02x:%02x MO %d MTA[%d] %x\n",
           buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
           (rctl >> E1000_RCTL_MO_SHIFT) & 3, f >> 5,
           s->mac_reg[MTA + (f >> 5)]);

    return 0;
}

static void
e1000_set_link_status(NetClientState *nc)
{
    E1000State *s = qemu_get_nic_opaque(nc);
    uint32_t old_status = s->mac_reg[STATUS];

    if (nc->link_down) {
        e1000_link_down(s);
    } else {
        e1000_link_up(s);
    }

    if (s->mac_reg[STATUS] != old_status)
        set_ics_lock(s, 0, E1000_ICR_LSC);
}

static bool e1000_has_rxbufs(E1000State *s, size_t total_size)
{
    int bufs;
    /* Fast-path short packets */
    if (total_size <= s->rxbuf_size) {
        return s->mac_reg[RDH] != s->mac_reg[RDT];
    }
    if (s->mac_reg[RDH] < s->mac_reg[RDT]) {
        bufs = s->mac_reg[RDT] - s->mac_reg[RDH];
    } else if (s->mac_reg[RDH] > s->mac_reg[RDT]) {
        bufs = s->mac_reg[RDLEN] /  sizeof(struct e1000_rx_desc) +
            s->mac_reg[RDT] - s->mac_reg[RDH];
    } else {
        return false;
    }
    return total_size <= bufs * s->rxbuf_size;
}

static int
e1000_can_receive(NetClientState *nc)
{
    E1000State *s = qemu_get_nic_opaque(nc);

    return (s->mac_reg[STATUS] & E1000_STATUS_LU) &&
        (s->mac_reg[RCTL] & E1000_RCTL_EN) && e1000_has_rxbufs(s, 1);
}

static uint64_t rx_desc_base(E1000State *s)
{
    uint64_t bah = s->mac_reg[RDBAH];
    uint64_t bal = s->mac_reg[RDBAL] & ~0xf;

    return (bah << 32) + bal;
}

static ssize_t
e1000_receive_iov(NetClientState *nc, const struct iovec *iov, int iovcnt)
{
    E1000State *s = qemu_get_nic_opaque(nc);
    PCIDevice *d = PCI_DEVICE(s);
    struct e1000_rx_desc desc;
    dma_addr_t base;
    unsigned int n, rdt;
    uint32_t rdh_start;
    uint16_t vlan_special = 0;
    uint8_t vlan_status = 0;
    uint8_t min_buf[MIN_BUF_SIZE];
    struct iovec min_iov;
    uint8_t *filter_buf = iov->iov_base;
    size_t size = iov_size(iov, iovcnt);
    size_t iov_ofs = 0;
    size_t desc_offset;
    size_t desc_size;
    size_t total_size;

    if (!(s->mac_reg[STATUS] & E1000_STATUS_LU)) {
        return -1;
    }

    if (!(s->mac_reg[RCTL] & E1000_RCTL_EN)) {
        return -1;
    }

    if (s->peer_has_vhdr) {
        iov_ofs = sizeof(struct virtio_net_hdr);
        filter_buf += iov_ofs;
        if (size <= iov_ofs)
            return size;
        size -= iov_ofs;
        while (iov->iov_len <= iov_ofs) {
            iov_ofs -= iov->iov_len;
            iovcnt--;
            iov++;
        }
    }

    /* Pad to minimum Ethernet frame length */
    if (size < sizeof(min_buf)) {
        iov_to_buf(iov, iovcnt, iov_ofs, min_buf, size);
        memset(&min_buf[size], 0, sizeof(min_buf) - size);
        min_iov.iov_base = filter_buf = min_buf;
        min_iov.iov_len = size = sizeof(min_buf);
        iovcnt = 1;
        iov = &min_iov;
        iov_ofs = 0;
    } else if (iov->iov_len - iov_ofs < MAXIMUM_ETHERNET_HDR_LEN) {
        /* This is very unlikely, but may happen. */
        iov_to_buf(iov, iovcnt, iov_ofs, min_buf, MAXIMUM_ETHERNET_HDR_LEN);
        filter_buf = min_buf;
    }

    /* Discard oversized packets if !LPE and !SBP. */
    if ((size > MAXIMUM_ETHERNET_LPE_SIZE ||
        (size > MAXIMUM_ETHERNET_VLAN_SIZE
        && !(s->mac_reg[RCTL] & E1000_RCTL_LPE)))
        && !(s->mac_reg[RCTL] & E1000_RCTL_SBP)) {
        return size;
    }

    if (!receive_filter(s, filter_buf, size)) {
        return size;
    }

    if (vlan_enabled(s) && is_vlan_packet(s, filter_buf)) {
        vlan_special = cpu_to_le16(be16_to_cpup((uint16_t *)(filter_buf
                                                                + 14)));
        iov_ofs += 4;
        if (filter_buf == iov->iov_base + iov_ofs - 4) {
            memmove(filter_buf + iov_ofs, filter_buf, 12);
        } else {
            iov_from_buf(iov, iovcnt, iov_ofs, filter_buf, 12);
            while (iov->iov_len <= iov_ofs) {
                iov_ofs -= iov->iov_len;
                iov++;
            }
        }
        vlan_status = E1000_RXD_STAT_VP;
        size -= 4;
    }

    rdh_start = s->mac_reg[RDH];
    desc_offset = 0;
    total_size = size + fcs_len(s);
    if (!e1000_has_rxbufs(s, total_size)) {
            set_ics_lock(s, 0, E1000_ICS_RXO);
            return -1;
    }
    do {
        desc_size = total_size - desc_offset;
        if (desc_size > s->rxbuf_size) {
            desc_size = s->rxbuf_size;
        }
        base = rx_desc_base(s) + sizeof(desc) * s->mac_reg[RDH];
        pci_dma_read(d, base, &desc, sizeof(desc));
        desc.special = vlan_special;
        desc.status |= (vlan_status | E1000_RXD_STAT_DD);
        if (desc.buffer_addr) {
            if (desc_offset < size) {
                size_t iov_copy;
                hwaddr ba = le64_to_cpu(desc.buffer_addr);
                size_t copy_size = size - desc_offset;
                if (copy_size > s->rxbuf_size) {
                    copy_size = s->rxbuf_size;
                }
                do {
                    iov_copy = MIN(copy_size, iov->iov_len - iov_ofs);
                    pci_dma_write(d, ba, iov->iov_base + iov_ofs, iov_copy);
                    copy_size -= iov_copy;
                    ba += iov_copy;
                    iov_ofs += iov_copy;
                    if (iov_ofs == iov->iov_len) {
                        iov++;
                        iov_ofs = 0;
                    }
                } while (copy_size);
            }
            desc_offset += desc_size;
            desc.length = cpu_to_le16(desc_size);
            if (desc_offset >= total_size) {
                desc.status |= E1000_RXD_STAT_EOP | E1000_RXD_STAT_IXSM;
            } else {
                /* Guest zeroing out status is not a hardware requirement.
                   Clear EOP in case guest didn't do it. */
                desc.status &= ~E1000_RXD_STAT_EOP;
            }
        } else { // as per intel docs; skip descriptors with null buf addr
            DBGOUT(RX, "Null RX descriptor!!\n");
        }
        pci_dma_write(d, base, &desc, sizeof(desc));

        if (++s->mac_reg[RDH] * sizeof(desc) >= s->mac_reg[RDLEN])
            s->mac_reg[RDH] = 0;
        /* see comment in start_xmit; same here */
        if (s->mac_reg[RDH] == rdh_start) {
            DBGOUT(RXERR, "RDH wraparound @%x, RDT %x, RDLEN %x\n",
                   rdh_start, s->mac_reg[RDT], s->mac_reg[RDLEN]);
            set_ics_lock(s, 0, E1000_ICS_RXO);
            return -1;
        }
    } while (desc_offset < total_size);

    s->mac_reg[GPRC]++;
    s->mac_reg[TPR]++;
    /* TOR - Total Octets Received:
     * This register includes bytes received in a packet from the <Destination
     * Address> field through the <CRC> field, inclusively.
     */
    n = s->mac_reg[TORL] + size + /* Always include FCS length. */ 4;
    if (n < s->mac_reg[TORL])
        s->mac_reg[TORH]++;
    s->mac_reg[TORL] = n;

    n = E1000_ICS_RXT0;
    if ((rdt = s->mac_reg[RDT]) < s->mac_reg[RDH])
        rdt += s->mac_reg[RDLEN] / sizeof(desc);
    if (((rdt - s->mac_reg[RDH]) * sizeof(desc)) <= s->mac_reg[RDLEN] >>
        s->rxbuf_min_shift)
        n |= E1000_ICS_RXDMT0;

    set_ics_lock(s, 0, n);

    return size;
}

static ssize_t
e1000_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    const struct iovec iov = {
        .iov_base = (uint8_t *)buf,
        .iov_len = size
    };

    return e1000_receive_iov(nc, &iov, 1);
}

static uint32_t
mac_readreg(E1000State *s, int index)
{
    return s->mac_reg[index];
}

static uint32_t
mac_icr_read(E1000State *s, int index)
{
    uint32_t ret = s->mac_reg[ICR];

    DBGOUT(INTERRUPT, "ICR read: %x\n", ret);
    set_interrupt_cause(s, 0, 0);
    return ret;
}

static uint32_t
mac_read_clr4(E1000State *s, int index)
{
    uint32_t ret = s->mac_reg[index];

    s->mac_reg[index] = 0;
    return ret;
}

static uint32_t
mac_read_clr8(E1000State *s, int index)
{
    uint32_t ret = s->mac_reg[index];

    s->mac_reg[index] = 0;
    s->mac_reg[index-1] = 0;
    return ret;
}

static void
mac_writereg(E1000State *s, int index, uint32_t val)
{
    uint32_t macaddr[2];

    s->mac_reg[index] = val;

    if (index == RA + 1) {
        macaddr[0] = cpu_to_le32(s->mac_reg[RA]);
        macaddr[1] = cpu_to_le32(s->mac_reg[RA + 1]);
        qemu_format_nic_info_str(qemu_get_queue(s->nic), (uint8_t *)macaddr);
    }
}

static void
set_rdt(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val & 0xffff;
    if (e1000_has_rxbufs(s, 1)) {
        qemu_flush_queued_packets(qemu_get_queue(s->nic));
    }
}

static void
set_16bit(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val & 0xffff;
}

static void
set_dlen(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val & 0xfff80;
}

static void
set_tctl(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val;
    s->mac_reg[TDT] &= 0xffff;
    start_xmit(s);
}

static void
set_icr(E1000State *s, int index, uint32_t val)
{
    DBGOUT(INTERRUPT, "set_icr %x\n", val);
    set_interrupt_cause(s, 0, s->mac_reg[ICR] & ~val);
}

static void
set_imc(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[IMS] &= ~val;
    set_ics(s, 0, 0);
}

static void
set_ims(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[IMS] |= val;
    set_ics(s, 0, 0);
}

#define getreg(x)   [x] = mac_readreg
static uint32_t (*macreg_readops[])(E1000State *, int) = {
    getreg(PBA),	getreg(RCTL),	getreg(TDH),	getreg(TXDCTL),
    getreg(WUFC),	getreg(TDT),	getreg(CTRL),	getreg(LEDCTL),
    getreg(MANC),	getreg(MDIC),	getreg(SWSM),	getreg(STATUS),
    getreg(TORL),	getreg(TOTL),	getreg(IMS),	getreg(TCTL),
    getreg(RDH),	getreg(RDT),	getreg(VET),	getreg(ICS),
    getreg(TDBAL),	getreg(TDBAH),	getreg(RDBAH),	getreg(RDBAL),
    getreg(TDLEN),      getreg(RDLEN),  getreg(RDTR),   getreg(RADV),
    getreg(TADV),       getreg(ITR),

    [TOTH] = mac_read_clr8,	[TORH] = mac_read_clr8,	[GPRC] = mac_read_clr4,
    [GPTC] = mac_read_clr4,	[TPR] = mac_read_clr4,	[TPT] = mac_read_clr4,
    [ICR] = mac_icr_read,	[EECD] = get_eecd,	[EERD] = flash_eerd_read,
    [CRCERRS ... MPC] = &mac_readreg,
    [RA ... RA+31] = &mac_readreg,
    [MTA ... MTA+127] = &mac_readreg,
    [VFTA ... VFTA+127] = &mac_readreg,
};
enum { NREADOPS = ARRAY_SIZE(macreg_readops) };

#define putreg(x)   [x] = mac_writereg
static void (*macreg_writeops[])(E1000State *, int, uint32_t) = {
    putreg(PBA),	putreg(EERD),	putreg(SWSM),	putreg(WUFC),
    putreg(TDBAL),	putreg(TDBAH),	putreg(TXDCTL),	putreg(RDBAH),
    putreg(RDBAL),	putreg(LEDCTL), putreg(VET),
    [TDLEN] = set_dlen,	[RDLEN] = set_dlen,	[TCTL] = set_tctl,
    [TDT] = set_tctl,	[MDIC] = set_mdic,	[ICS] = set_ics,
    [TDH] = set_16bit,	[RDH] = set_16bit,	[RDT] = set_rdt,
    [IMC] = set_imc,	[IMS] = set_ims,	[ICR] = set_icr,
    [EECD] = set_eecd,	[RCTL] = set_rx_control, [CTRL] = set_ctrl,
    [RDTR] = set_16bit, [RADV] = set_16bit,     [TADV] = set_16bit,
    [ITR] = set_16bit,  [RXCSUM] = set_rxcsum,
    [RA ... RA+31] = &mac_writereg,
    [MTA ... MTA+127] = &mac_writereg,
    [VFTA ... VFTA+127] = &mac_writereg,
};

enum { NWRITEOPS = ARRAY_SIZE(macreg_writeops) };

static void
e1000_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                 unsigned size)
{
    E1000State *s = opaque;
    unsigned int index = (addr & 0x1ffff) >> 2;

    if (index < NWRITEOPS && macreg_writeops[index]) {
        MUTEX_LOCK(s);
        macreg_writeops[index](s, index, val);
        MUTEX_UNLOCK(s);
    } else if (index < NREADOPS && macreg_readops[index]) {
        DBGOUT(MMIO, "e1000_mmio_writel RO %x: 0x%04"PRIx64"\n", index<<2, val);
    } else {
        DBGOUT(UNKNOWN, "MMIO unknown write addr=0x%08x,val=0x%08"PRIx64"\n",
               index<<2, val);
    }
}

static uint64_t
e1000_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    E1000State *s = opaque;
    unsigned int index = (addr & 0x1ffff) >> 2;

    if (index < NREADOPS && macreg_readops[index])
    {
        uint64_t ret;
        MUTEX_LOCK(s);
        ret = macreg_readops[index](s, index);
        MUTEX_UNLOCK(s);
        return ret;
    }
    DBGOUT(UNKNOWN, "MMIO unknown read addr=0x%08x\n", index<<2);
    return 0;
}

static const MemoryRegionOps e1000_mmio_ops = {
    .read = e1000_mmio_read,
    .write = e1000_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static uint64_t e1000_io_read(void *opaque, hwaddr addr,
                              unsigned size)
{
    E1000State *s = opaque;

    (void)s;
    return 0;
}

static void e1000_io_write(void *opaque, hwaddr addr,
                           uint64_t val, unsigned size)
{
    E1000State *s = opaque;

    (void)s;
}

static const MemoryRegionOps e1000_io_ops = {
    .read = e1000_io_read,
    .write = e1000_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static bool is_version_1(void *opaque, int version_id)
{
    return version_id == 1;
}

static void e1000_pre_save(void *opaque)
{
    E1000State *s = opaque;
    NetClientState *nc = qemu_get_queue(s->nic);

    /* If the mitigation timer is active, emulate a timeout now. */
    if (s->mit_timer_on) {
        e1000_mit_timer(s);
    }

    if (!(s->compat_flags & E1000_FLAG_AUTONEG)) {
        return;
    }

    /*
     * If link is down and auto-negotiation is ongoing, complete
     * auto-negotiation immediately.  This allows is to look at
     * MII_SR_AUTONEG_COMPLETE to infer link status on load.
     */
    if (nc->link_down &&
        s->phy_reg[PHY_CTRL] & MII_CR_AUTO_NEG_EN &&
        s->phy_reg[PHY_CTRL] & MII_CR_RESTART_AUTO_NEG) {
         s->phy_reg[PHY_STATUS] |= MII_SR_AUTONEG_COMPLETE;
    }
}

static int e1000_post_load(void *opaque, int version_id)
{
    E1000State *s = opaque;
    NetClientState *nc = qemu_get_queue(s->nic);

    if (!(s->compat_flags & E1000_FLAG_MIT)) {
        s->mac_reg[ITR] = s->mac_reg[RDTR] = s->mac_reg[RADV] =
            s->mac_reg[TADV] = 0;
        s->mit_irq_level = false;
    }
    s->mit_ide = 0;
    s->mit_timer_on = false;

    /* nc.link_down can't be migrated, so infer link_down according
     * to link status bit in mac_reg[STATUS].
     * Alternatively, restart link negotiation if it was in progress. */
    nc->link_down = (s->mac_reg[STATUS] & E1000_STATUS_LU) == 0;

    if (!(s->compat_flags & E1000_FLAG_AUTONEG)) {
        return 0;
    }

    if (s->phy_reg[PHY_CTRL] & MII_CR_AUTO_NEG_EN &&
        s->phy_reg[PHY_CTRL] & MII_CR_RESTART_AUTO_NEG &&
        !(s->phy_reg[PHY_STATUS] & MII_SR_AUTONEG_COMPLETE)) {
        nc->link_down = false;
        timer_mod(s->autoneg_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);
    }

    return 0;
}

static bool e1000_mit_state_needed(void *opaque)
{
    E1000State *s = opaque;

    return s->compat_flags & E1000_FLAG_MIT;
}

static const VMStateDescription vmstate_e1000_mit_state = {
    .name = "e1000/mit_state",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields    = (VMStateField[]) {
        VMSTATE_UINT32(mac_reg[RDTR], E1000State),
        VMSTATE_UINT32(mac_reg[RADV], E1000State),
        VMSTATE_UINT32(mac_reg[TADV], E1000State),
        VMSTATE_UINT32(mac_reg[ITR], E1000State),
        VMSTATE_BOOL(mit_irq_level, E1000State),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_e1000 = {
    .name = "e1000",
    .version_id = 2,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .pre_save = e1000_pre_save,
    .post_load = e1000_post_load,
    .fields      = (VMStateField []) {
        VMSTATE_PCI_DEVICE(parent_obj, E1000State),
        VMSTATE_UNUSED_TEST(is_version_1, 4), /* was instance id */
        VMSTATE_UNUSED(4), /* Was mmio_base.  */
        VMSTATE_UINT32(rxbuf_size, E1000State),
        VMSTATE_UINT32(rxbuf_min_shift, E1000State),
        VMSTATE_UINT32(eecd_state.val_in, E1000State),
        VMSTATE_UINT16(eecd_state.bitnum_in, E1000State),
        VMSTATE_UINT16(eecd_state.bitnum_out, E1000State),
        VMSTATE_UINT16(eecd_state.reading, E1000State),
        VMSTATE_UINT32(eecd_state.old_eecd, E1000State),
        VMSTATE_UINT8(tx.ipcss, E1000State),
        VMSTATE_UINT8(tx.ipcso, E1000State),
        VMSTATE_UINT16(tx.ipcse, E1000State),
        VMSTATE_UINT8(tx.tucss, E1000State),
        VMSTATE_UINT8(tx.tucso, E1000State),
        VMSTATE_UINT16(tx.tucse, E1000State),
        VMSTATE_UINT32(tx.paylen, E1000State),
        VMSTATE_UINT8(tx.hdr_len, E1000State),
        VMSTATE_UINT16(tx.mss, E1000State),
        VMSTATE_UINT16(tx.size, E1000State),
        VMSTATE_UINT16(tx.tso_frames, E1000State),
        VMSTATE_UINT8(tx.sum_needed, E1000State),
        VMSTATE_INT8(tx.ip, E1000State),
        VMSTATE_INT8(tx.tcp, E1000State),
        VMSTATE_BUFFER(tx.header, E1000State),
        VMSTATE_BUFFER(tx.data, E1000State),
        VMSTATE_UINT16_ARRAY(eeprom_data, E1000State, 64),
        VMSTATE_UINT16_ARRAY(phy_reg, E1000State, 0x20),
        VMSTATE_UINT32(mac_reg[CTRL], E1000State),
        VMSTATE_UINT32(mac_reg[EECD], E1000State),
        VMSTATE_UINT32(mac_reg[EERD], E1000State),
        VMSTATE_UINT32(mac_reg[GPRC], E1000State),
        VMSTATE_UINT32(mac_reg[GPTC], E1000State),
        VMSTATE_UINT32(mac_reg[ICR], E1000State),
        VMSTATE_UINT32(mac_reg[ICS], E1000State),
        VMSTATE_UINT32(mac_reg[IMC], E1000State),
        VMSTATE_UINT32(mac_reg[IMS], E1000State),
        VMSTATE_UINT32(mac_reg[LEDCTL], E1000State),
        VMSTATE_UINT32(mac_reg[MANC], E1000State),
        VMSTATE_UINT32(mac_reg[MDIC], E1000State),
        VMSTATE_UINT32(mac_reg[MPC], E1000State),
        VMSTATE_UINT32(mac_reg[PBA], E1000State),
        VMSTATE_UINT32(mac_reg[RCTL], E1000State),
        VMSTATE_UINT32(mac_reg[RDBAH], E1000State),
        VMSTATE_UINT32(mac_reg[RDBAL], E1000State),
        VMSTATE_UINT32(mac_reg[RDH], E1000State),
        VMSTATE_UINT32(mac_reg[RDLEN], E1000State),
        VMSTATE_UINT32(mac_reg[RDT], E1000State),
        VMSTATE_UINT32(mac_reg[STATUS], E1000State),
        VMSTATE_UINT32(mac_reg[SWSM], E1000State),
        VMSTATE_UINT32(mac_reg[TCTL], E1000State),
        VMSTATE_UINT32(mac_reg[TDBAH], E1000State),
        VMSTATE_UINT32(mac_reg[TDBAL], E1000State),
        VMSTATE_UINT32(mac_reg[TDH], E1000State),
        VMSTATE_UINT32(mac_reg[TDLEN], E1000State),
        VMSTATE_UINT32(mac_reg[TDT], E1000State),
        VMSTATE_UINT32(mac_reg[TORH], E1000State),
        VMSTATE_UINT32(mac_reg[TORL], E1000State),
        VMSTATE_UINT32(mac_reg[TOTH], E1000State),
        VMSTATE_UINT32(mac_reg[TOTL], E1000State),
        VMSTATE_UINT32(mac_reg[TPR], E1000State),
        VMSTATE_UINT32(mac_reg[TPT], E1000State),
        VMSTATE_UINT32(mac_reg[TXDCTL], E1000State),
        VMSTATE_UINT32(mac_reg[WUFC], E1000State),
        VMSTATE_UINT32(mac_reg[VET], E1000State),
        VMSTATE_UINT32_SUB_ARRAY(mac_reg, E1000State, RA, 32),
        VMSTATE_UINT32_SUB_ARRAY(mac_reg, E1000State, MTA, 128),
        VMSTATE_UINT32_SUB_ARRAY(mac_reg, E1000State, VFTA, 128),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (VMStateSubsection[]) {
        {
            .vmsd = &vmstate_e1000_mit_state,
            .needed = e1000_mit_state_needed,
        }, {
            /* empty */
        }
    }
};

static const uint16_t e1000_eeprom_template[64] = {
    0x0000, 0x0000, 0x0000, 0x0000,      0xffff, 0x0000,      0x0000, 0x0000,
    0x3000, 0x1000, 0x6403, E1000_DEVID, 0x8086, E1000_DEVID, 0x8086, 0x3040,
    0x0008, 0x2000, 0x7e14, 0x0048,      0x1000, 0x00d8,      0x0000, 0x2700,
    0x6cc9, 0x3150, 0x0722, 0x040b,      0x0984, 0x0000,      0xc000, 0x0706,
    0x1008, 0x0000, 0x0f04, 0x7fff,      0x4d01, 0xffff,      0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff,      0xffff, 0xffff,      0xffff, 0xffff,
    0x0100, 0x4000, 0x121c, 0xffff,      0xffff, 0xffff,      0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff,      0xffff, 0xffff,      0xffff, 0x0000,
};

static const uint16_t e1000_vmw_eeprom_template[64] = {
    0x0000, 0x0000, 0x0000, 0x0000,      0xffff, 0x0000,      0x0000, 0x0000,
    0x3000, 0x1000, 0x6403, E1000_VMW_DEVID, 0x8086, E1000_VMW_DEVID, 0x8086, 0x3040,
    0x0008, 0x2000, 0x7e14, 0x0048,      0x1000, 0x00d8,      0x0000, 0x2700,
    0x6cc9, 0x3150, 0x0722, 0x040b,      0x0984, 0x0000,      0xc000, 0x0706,
    0x1008, 0x0000, 0x0f04, 0x7fff,      0x4d01, 0xffff,      0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff,      0xffff, 0xffff,      0xffff, 0xffff,
    0x0100, 0x4000, 0x121c, 0xffff,      0xffff, 0xffff,      0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff,      0xffff, 0xffff,      0xffff, 0x0000,
};

/* PCI interface */

static void
e1000_mmio_setup(E1000State *d)
{
    int i;
    const uint32_t excluded_regs[] = {
        E1000_MDIC, E1000_ICR, E1000_ICS, E1000_IMS,
        E1000_IMC, E1000_TCTL, E1000_TDT, PNPMMIO_SIZE
    };

    memory_region_init_io(&d->mmio, OBJECT(d), &e1000_mmio_ops, d,
                          "e1000-mmio", PNPMMIO_SIZE);
    memory_region_add_coalescing(&d->mmio, 0, excluded_regs[0]);
    for (i = 0; excluded_regs[i] != PNPMMIO_SIZE; i++)
        memory_region_add_coalescing(&d->mmio, excluded_regs[i] + 4,
                                     excluded_regs[i+1] - excluded_regs[i] - 4);
    memory_region_init_io(&d->io, OBJECT(d), &e1000_io_ops, d, "e1000-io", IOPORT_SIZE);
}

static void
e1000_cleanup(NetClientState *nc)
{
    E1000State *s = qemu_get_nic_opaque(nc);

    s->nic = NULL;
}

static void
pci_e1000_uninit(PCIDevice *dev)
{
    E1000State *d = E1000(dev);

#ifdef CONFIG_RATE_LIMIT
    if (d->co_thread != NULL) {
        d->co_shutdown = true;
        qemu_cond_signal(d->co_cond);
        qemu_thread_join(d->co_thread);
        d->co_thread = NULL;
    }

    if (d->co_cond_inited) {
        qemu_cond_destroy(d->co_cond);
        qemu_mutex_destroy(&d->co_mutex);
        d->co_cond_inited = false;
    }
#endif

    timer_del(d->autoneg_timer);
    timer_free(d->autoneg_timer);
    timer_del(d->mit_timer);
    timer_free(d->mit_timer);
    memory_region_destroy(&d->mmio);
    memory_region_destroy(&d->io);
    qemu_del_nic(d->nic);
}

static NetClientInfo net_e1000_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NIC,
    .size = sizeof(NICState),
    .can_receive = e1000_can_receive,
    .receive = e1000_receive,
    .receive_iov = e1000_receive_iov,
    .cleanup = e1000_cleanup,
    .link_status_changed = e1000_set_link_status,
};

static bool e1000_peer_has_vnet_hdr(E1000State *d)
{
    NetClientState *peer = qemu_get_queue(d->nic)->peer;

    if (peer &&
        peer->info->type == NET_CLIENT_OPTIONS_KIND_TAP &&
        qemu_has_vnet_hdr(peer)) {
        return true;
    }
    return false;
}

static int pci_e1000_common_init(PCIDevice *pci_dev, E1000State *d)
{
    DeviceState *dev = DEVICE(pci_dev);
#ifdef CONFIG_RATE_LIMIT
    NICConf *conf = &d->conf;
#endif
    uint8_t *pci_conf;
    uint16_t checksum = 0;
    int i;
    uint8_t *macaddr;

    pci_conf = pci_dev->config;

    if (vmware_hw) {
        /* Power Management Capabilities */
        int cfg_offset = 0xe4;
        int cfg_size = 8;
        int r;

        pci_set_word(pci_conf + PCI_STATUS,
                 PCI_STATUS_66MHZ | PCI_STATUS_DEVSEL_MEDIUM);

        r = pci_add_capability(pci_dev, PCI_CAP_ID_PCIX,
                               cfg_offset, cfg_size);
        assert(r >= 0);
        pci_set_word(pci_conf + cfg_offset + PCI_X_CMD,
                     PCI_X_CMD_ERO);
        pci_set_long(pci_conf + cfg_offset + PCI_X_STATUS,
                     PCI_X_STATUS_64BIT | PCI_X_STATUS_133MHZ | 0x0440fff8);

        cfg_offset -= cfg_size;
        cfg_size = PCI_PM_SIZEOF;
        assert(cfg_offset + cfg_size < 0xff);
        r = pci_add_capability(pci_dev, PCI_CAP_ID_PM,
                               cfg_offset, cfg_size);
        assert(r >= 0);
        pci_set_word(pci_conf + cfg_offset + PCI_PM_PMC,
                     PCI_PM_CAP_PME_D0 | PCI_PM_CAP_PME_D3 |
                     PCI_PM_CAP_PME_D3cold | PCI_PM_CAP_DSI | 0x2);
        pci_set_word(pci_conf + cfg_offset + PCI_PM_CTRL, 0x2000);
        pci_set_word(pci_conf + cfg_offset + PCI_PM_PPB_EXTENSIONS,
                     0x2800);
        /* Special bits */
        pci_set_word(pci_conf + PCI_COMMAND,
                 PCI_COMMAND_INVALIDATE | PCI_COMMAND_SERR);
        /* Write protect SERR. Should be the same as 
         * command_serr_enable=0 */
        pci_word_test_and_clear_mask(pci_dev->wmask + PCI_COMMAND,
                                     PCI_COMMAND_SERR);
        pci_conf[PCI_MIN_GNT] = 0xff;
    }
    /* TODO: RST# value should be 0, PCI spec 6.2.4 */
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;

    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    e1000_mmio_setup(d);

    if (vmware_hw) {
        pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_TYPE_64,
                         &d->mmio);

        pci_register_bar(pci_dev, 4, PCI_BASE_ADDRESS_SPACE_IO, &d->io);
    } else {
        pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->mmio);

        pci_register_bar(pci_dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &d->io);
    }
    if (PCI_DEVICE_GET_CLASS(pci_dev)->device_id == E1000_VMW_DEVID) {
        memmove(d->eeprom_data, e1000_vmw_eeprom_template,
            sizeof e1000_vmw_eeprom_template);
    } else {
        memmove(d->eeprom_data, e1000_eeprom_template,
            sizeof e1000_eeprom_template);
    }

    qemu_macaddr_default_if_unset(&d->conf.macaddr);
    macaddr = d->conf.macaddr.a;
    for (i = 0; i < 3; i++)
        d->eeprom_data[i] = (macaddr[2*i+1]<<8) | macaddr[2*i];
    for (i = 0; i < EEPROM_CHECKSUM_REG; i++)
        checksum += d->eeprom_data[i];
    checksum = (uint16_t) EEPROM_SUM - checksum;
    d->eeprom_data[EEPROM_CHECKSUM_REG] = checksum;

    d->nic = qemu_new_nic(&net_e1000_info, &d->conf,
                          object_get_typename(OBJECT(d)), dev->id, d);

    qemu_format_nic_info_str(qemu_get_queue(d->nic), macaddr);

    add_boot_device_path(d->conf.bootindex, dev, "/ethernet-phy@0");

    d->autoneg_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, e1000_autoneg_timer, d);
    d->mit_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, e1000_mit_timer, d);

#ifdef CONFIG_RATE_LIMIT
    d->io_limits_enabled = false;
    d->co_running = false;
    d->co_shutdown = false;
    d->co_cond_inited = false;
    d->co_thread = NULL;
    d->slice_end = 0;
    qemu_mutex_init(&d->co_mutex);

    if (conf->bytes_per_int || conf->int_usec) {
       /* Load the structure with the initial limits here.
        * Check the limits on each send packet in case they change dynamically
        */
       e1000_io_limits_enable(d, conf->bytes_per_int, conf->int_usec);
       conf->bytes_per_int = 0;
       conf->int_usec = 0;
    }
#endif

    d->peer_has_vhdr = e1000_peer_has_vnet_hdr(d);
    if (d->peer_has_vhdr) {
        printf("e1000 vhdr enabled\n");
        qemu_set_vnet_hdr_len(qemu_get_queue(d->nic)->peer,
                             sizeof(struct virtio_net_hdr));

        qemu_using_vnet_hdr(qemu_get_queue(d->nic)->peer, 1);
    } else
        printf("e1000 vhdr disabled\n");

    return 0;
}

static int pci_e1000_init(PCIDevice *pci_dev)
{
    DeviceState *dev = DEVICE(pci_dev);
    E1000State *d = E1000(dev);

    return pci_e1000_common_init(pci_dev, d);
}

static int pci_e1000_vmw_init(PCIDevice *pci_dev)
{
    DeviceState *dev = DEVICE(pci_dev);
    E1000State *d = E1000VMW(dev);

    return pci_e1000_common_init(pci_dev, d);
}

static void qdev_e1000_reset(DeviceState *dev)
{
    E1000State *d = E1000(dev);
    e1000_reset(d);
}

static void qdev_e1000_vmw_reset(DeviceState *dev)
{
    E1000State *d = E1000VMW(dev);
    e1000_reset(d);
}

static Property e1000_properties[] = {
    DEFINE_NIC_PROPERTIES(E1000State, conf),
    DEFINE_PROP_BIT("autonegotiation", E1000State,
                    compat_flags, E1000_FLAG_AUTONEG_BIT, true),
    DEFINE_PROP_BIT("mitigation", E1000State,
                    compat_flags, E1000_FLAG_MIT_BIT, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void e1000_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = pci_e1000_init;
    k->exit = pci_e1000_uninit;
    k->romfile = "efi-e1000.rom";
    k->vendor_id = PCI_VENDOR_ID_INTEL;
    k->device_id = E1000_DEVID;
    k->revision = 0x03;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "Intel Gigabit Ethernet";
    dc->reset = qdev_e1000_reset;
    dc->vmsd = &vmstate_e1000;
    dc->props = e1000_properties;
}

static const TypeInfo e1000_info = {
    .name          = TYPE_E1000,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(E1000State),
    .class_init    = e1000_class_init,
};

static void e1000_register_types(void)
{
    type_register_static(&e1000_info);
}

type_init(e1000_register_types)

/*
 * VMWare support: We introduce a subclass ("e1000_vmw") of e1000
 * whose PCI device ID is 0x100F instead of 0x100E.  The NIC "model"
 * name for this subclass is "e1000_vmw".  Note that not all of the
 * structures, statics and methods in this file have been duplicated
 * for use by the e1000_vmw subclass.  We may, in the future, need to
 * create duplicate structures or other code to handle PHY_ID2_INIT,
 * phy_reg_init, e1000_reset, and set_interrupt_cause.
 */

static void e1000_vmw_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = pci_e1000_vmw_init;
    k->exit = pci_e1000_uninit;
    k->romfile = "pxe-e1000.rom";
    k->vendor_id = PCI_VENDOR_ID_INTEL;
    k->device_id = E1000_VMW_DEVID;
    k->subsystem_vendor_id = PCI_VENDOR_ID_VMWARE;
    k->subsystem_id = PCI_DEVICE_ID_VMWARE_NET2;
    if (vmware_hw) {
        k->revision = 0x01;
    } else {
        k->revision = 0x03;
    }
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    dc->desc = "Intel Gigabit Ethernet";
    dc->reset = qdev_e1000_vmw_reset;
    dc->vmsd = &vmstate_e1000;
    dc->props = e1000_properties;
}

static TypeInfo e1000_vmw_info = {
    .name          = "e1000_vmw",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(E1000State),
    .class_init    = e1000_vmw_class_init,
};

static void e1000_vmw_register_types(void)
{
    type_register_static(&e1000_vmw_info);
}

type_init(e1000_vmw_register_types)

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
