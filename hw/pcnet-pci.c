/*
 * QEMU AMD PC-Net II (Am79C970A) PCI emulation
 *
 * Copyright (c) 2004 Antony T Curtis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* This software was written to be compatible with the specification:
 * AMD Am79C970A PCnet-PCI II Ethernet Controller Data-Sheet
 * AMD Publication# 19436  Rev:E  Amendment/0  Issue Date: June 2000
 */

#include "pci.h"
#include "net.h"
#include "loader.h"
#include "qemu-timer.h"
#include "dma.h"
#include "trace.h"

#include "pcnet.h"

typedef struct {
    PCIDevice pci_dev;
    MemoryRegion io_bar;
    PCNetState state;
} PCIPCNetState;

typedef struct {
    PCIDevice pci_dev;
    MemoryRegion io_bar;
    PCNetVmxState state;
} PCIPCNetVmxState;

static void pcnet_aprom_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCNetState *s = opaque;

    trace_pcnet_aprom_writeb(opaque, addr, val);
    if (BCR_APROMWE(s)) {
        s->prom[addr & 15] = val;
    }
}

static uint32_t pcnet_aprom_readb(void *opaque, uint32_t addr)
{
    PCNetState *s = opaque;
    uint32_t val = s->prom[addr & 15];

    trace_pcnet_aprom_readb(opaque, addr, val);
    return val;
}

static uint64_t pcnet_ioport_read(void *opaque, hwaddr addr,
                                  unsigned size)
{
    PCNetState *d = opaque;

    trace_pcnet_ioport_read(opaque, addr, size);
    if (addr < 0x10) {
        if (!BCR_DWIO(d) && size == 1) {
            return pcnet_aprom_readb(d, addr);
        } else if (!BCR_DWIO(d) && (addr & 1) == 0 && size == 2) {
            return pcnet_aprom_readb(d, addr) |
                   (pcnet_aprom_readb(d, addr + 1) << 8);
        } else if (BCR_DWIO(d) && (addr & 3) == 0 && size == 4) {
            return pcnet_aprom_readb(d, addr) |
                   (pcnet_aprom_readb(d, addr + 1) << 8) |
                   (pcnet_aprom_readb(d, addr + 2) << 16) |
                   (pcnet_aprom_readb(d, addr + 3) << 24);
        }
    } else {
        if (size == 2) {
            return pcnet_ioport_readw(d, addr);
        } else if (size == 4) {
            return pcnet_ioport_readl(d, addr);
        }
    }
    return ((uint64_t)1 << (size * 8)) - 1;
}

static void pcnet_ioport_write(void *opaque, hwaddr addr,
                               uint64_t data, unsigned size)
{
    PCNetState *d = opaque;

    trace_pcnet_ioport_write(opaque, addr, data, size);
    if (addr < 0x10) {
        if (!BCR_DWIO(d) && size == 1) {
            pcnet_aprom_writeb(d, addr, data);
        } else if (!BCR_DWIO(d) && (addr & 1) == 0 && size == 2) {
            pcnet_aprom_writeb(d, addr, data & 0xff);
            pcnet_aprom_writeb(d, addr + 1, data >> 8);
        } else if (BCR_DWIO(d) && (addr & 3) == 0 && size == 4) {
            pcnet_aprom_writeb(d, addr, data & 0xff);
            pcnet_aprom_writeb(d, addr + 1, (data >> 8) & 0xff);
            pcnet_aprom_writeb(d, addr + 2, (data >> 16) & 0xff);
            pcnet_aprom_writeb(d, addr + 3, data >> 24);
        }
    } else {
        if (size == 2) {
            pcnet_ioport_writew(d, addr, data);
        } else if (size == 4) {
            pcnet_ioport_writel(d, addr, data);
        }
    }
}

static const MemoryRegionOps pcnet_io_ops = {
    .read = pcnet_ioport_read,
    .write = pcnet_ioport_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void vlance_morph_ioport_writeb(PCNetVmxState *vs, uint32_t addr, uint32_t val)
{
    trace_vlance_morph_ioport_writeb(vs, addr, val);
    switch (addr & 0x03) {
    case 0x00:
        vs->s2.morph[0] = (vs->s2.morph[0] & 0xff00) | (val & 0xff);
        break;
    }
}

static uint32_t vlance_morph_ioport_readb(PCNetVmxState *vs, uint32_t addr)
{
    uint32_t val = ~0U;

    switch (addr & 0x03) {
	case 0x00: /* RESET */
	    val = vs->s2.morph[0] & 0xff;
	    break;
	}

    pcnet_update_irq(&vs->s1);
    trace_vlance_morph_ioport_readb(vs, addr, val);
    return val;
}

static void vlance_morph_ioport_writew(PCNetVmxState *vs, uint32_t addr, uint32_t val)
{
    trace_vlance_morph_ioport_writew(vs, addr, val);
    switch (addr & 0x03) {
    case 0x00: /* RDP */
        vs->s2.morph[0] = val;
        break;
    }
}

static uint32_t vlance_morph_ioport_readw(PCNetVmxState *vs, uint32_t addr)
{
    uint32_t val = ~0U;

    switch (addr & 0x03) {
    case 0x00:
        val = vs->s2.morph[0];
        break;
    }

    pcnet_update_irq(&vs->s1);
    trace_vlance_morph_ioport_readw(vs, addr, val);
    return val;
}

static void vlance_morph_ioport_writel(PCNetVmxState *vs, uint32_t addr, uint32_t val)
{
    trace_vlance_morph_ioport_writel(vs, addr, val);
    switch (addr & 0x03) {
    case 0x00: /* RDP */
        vs->s2.morph[0] = val;
    }
}

static uint32_t vlance_morph_ioport_readl(PCNetVmxState *vs, uint32_t addr)
{
    uint32_t val = ~0U;

    switch (addr & 0x03) {
    case 0x00:
        val = vs->s2.morph[0];
        break;
    }

    pcnet_update_irq(&vs->s1);
    trace_vlance_morph_ioport_readl(vs, addr, val);
    return val;
}

static void vmxnet_ioport_writeb(PCNetVmxState *vs, uint32_t addr, uint32_t val)
{
    trace_vmxnet_ioport_writeb(vs, addr, val);
    switch (addr & 0x3f) {
    case 0x00:
        vs->s2.vmxnet_reg[0] = (vs->s2.vmxnet_reg[0] & 0xff00) | (val & 0xff);
        break;
    case VMXNET_MAC_ADDR:
    case VMXNET_MAC_ADDR+1:
    case VMXNET_MAC_ADDR+2:
    case VMXNET_MAC_ADDR+3:
    case VMXNET_MAC_ADDR+4:
    case VMXNET_MAC_ADDR+5:
        vs->s1.prom[(addr-VMXNET_MAC_ADDR) & 0x0f] = val & 0xff;
        break;
    default:
        fprintf(stderr, "Unhandled %s: addr=%#010x val=%#06x\n",
               __func__, addr, val);
        break;
    }
}

static uint32_t vmxnet_ioport_readb(PCNetVmxState *vs, uint32_t addr)
{
    uint32_t val = ~0U;

    switch (addr & 0x3f) {
	case VMXNET_MAC_ADDR:
	case VMXNET_MAC_ADDR+1:
	case VMXNET_MAC_ADDR+2:
	case VMXNET_MAC_ADDR+3:
	case VMXNET_MAC_ADDR+4:
	case VMXNET_MAC_ADDR+5:
	    val = vs->s1.prom[(addr-VMXNET_MAC_ADDR) & 0x0f] & 0xff;
	    break;
	case VMXNET_LOW_VERSION:
	    val = vs->s2.vmxnet_reg[VMXNET_LOW_VERSION] & 0xff;
	    break;
	case VMXNET_HIGH_VERSION:
	    val = vs->s2.vmxnet_reg[VMXNET_HIGH_VERSION] & 0xff;
	    break;
	default: 
            fprintf(stderr, "Unhandled %s: addr=%#010x val=%#06x \n",
                   __func__, addr, val & 0xff);
	    break;
	}

    pcnet_update_irq(&vs->s1);
    trace_vmxnet_ioport_readb(vs, addr, val);
    return val;
}

static void vmxnet_ioport_writew(PCNetVmxState *vs, uint32_t addr, uint32_t val)
{
    trace_vmxnet_ioport_writew(vs, addr, val);
    switch (addr & 0x3f) {
    case 0x00: /* RDP */
        vs->s2.vmxnet_reg[0] = val;
        break;
    default:
        fprintf(stderr, "Unhandled %s: addr=%#010x val=%#06x\n",
                __func__, addr, val);
        break;
    }
}

static uint32_t vmxnet_ioport_readw(PCNetVmxState *vs, uint32_t addr)
{
    uint32_t val = ~0U;

    switch (addr & 0x3f) {
    case 0x00:
        val = vs->s2.vmxnet_reg[0];
        break;
    case VMXNET_LOW_VERSION:
        val = vs->s2.vmxnet_reg[VMXNET_LOW_VERSION] & 0xFFFF;
        break;
    case VMXNET_HIGH_VERSION:
        val = vs->s2.vmxnet_reg[VMXNET_HIGH_VERSION] & 0xFFFF;
        break;
    default:
        fprintf(stderr, "Unhandled %s: addr=%#010x val=%#06x\n",
                __func__, addr, val & 0xffff);
        break;
    }

    pcnet_update_irq(&vs->s1);
    trace_vmxnet_ioport_readw(vs, addr, val & 0xffff);
    return val;
}

static void vmxnet_ioport_writel(PCNetVmxState *vs, uint32_t addr, uint32_t val)
{
    PCNetState *s = &vs->s1;
    Vmxnet2_DriverData dd;
    uint16_t *ladrf;

    trace_vmxnet_ioport_writel(vs, addr, val);
    switch (addr & 0x3f) {
    case VMXNET_COMMAND_ADDR:
	    vs->s2.vmxnet_reg[VMXNET_COMMAND_ADDR] = val;
	    if (val == VMXNET_CMD_INTR_DISABLE) {
		vs->s2.vmx_interrupt_enabled = false;
		vmxnet_update_irq(vs);
	    } else if (val == VMXNET_CMD_INTR_ENABLE) {
		vs->s2.vmx_interrupt_enabled = true;
		vmxnet_update_irq(vs);
	    } else if (val == VMXNET_CMD_INTR_ACK) {
		vmxnet_update_irq(vs);
	    } else if (val == VMXNET_CMD_UPDATE_LADRF) {
		s->phys_mem_read(s->dma_opaque, vs->s2.vmxdata_addr, (void *) &dd, sizeof(dd), 0);
		ladrf = (uint16_t *) dd.LADRF;
		if ((dd.ifflags & VMXNET_IFF_MULTICAST)) {
		    s->csr[8] = ladrf[0];
		    s->csr[9] = ladrf[1];
		    s->csr[10] = ladrf[2];
		    s->csr[11] = ladrf[3];
		}
	    } else if (val == VMXNET_CMD_UPDATE_IFF) {
                s->phys_mem_read(s->dma_opaque, vs->s2.vmxdata_addr, (void *) &dd, sizeof(dd), 0);
		ladrf = (uint16_t *) dd.LADRF;
		s->csr[8] = ladrf[0];
		s->csr[9] = ladrf[1];
		s->csr[10] = ladrf[2];
		s->csr[11] = ladrf[3];
		if (!(dd.ifflags & VMXNET_IFF_MULTICAST)) {
		    s->csr[8] = 0;
		    s->csr[9] = 0;
		    s->csr[10] = 0;
		    s->csr[11] = 0;
		}
		if (dd.ifflags & ~(VMXNET_IFF_PROMISC | VMXNET_IFF_BROADCAST | VMXNET_IFF_MULTICAST)) {
		    // Linux driver sets most bits to 1.
                    // fprintf(stderr, "Unhandled IFF ifflags = 0x%x\n", dd.ifflags);
		}
		if (!!(dd.ifflags & VMXNET_IFF_PROMISC) ^ CSR_PROM(s)) {
		    /* check for promiscuous mode change */
#if 0
		    if (vs->s2.pDrv)
			vs->s2.pDrv->pfnSetPromiscuousMode(vs->s2.pDrv, !!(dd.ifflags & VMXNET_IFF_PROMISC));
#endif
		    s->csr[15] = (dd.ifflags & VMXNET_IFF_PROMISC) ? (s->csr[15] | 0x8000) : (s->csr[15] & ~0x8000);
		}
		if (!!(dd.ifflags & VMXNET_IFF_BROADCAST) ^ CSR_DRCVBC(s))  {
		    s->csr[15] = !(dd.ifflags & VMXNET_IFF_BROADCAST) ? (s->csr[15] | 0x4000) : (s->csr[15] & ~0x4000);
		}
		if (!!(dd.ifflags & VMXNET_IFF_BROADCAST) ^ CSR_DRCVBC(s))  {
		    s->csr[15] = !(dd.ifflags & VMXNET_IFF_BROADCAST) ? (s->csr[15] | 0x4000) : (s->csr[15] & ~0x4000);
		}
	    } else {
		if ((val != VMXNET_CMD_GET_FEATURES) && (val != VMXNET_CMD_GET_CAPABILITIES) &&
		    (val != VMXNET_CMD_GET_NUM_RX_BUFFERS) && (val != VMXNET_CMD_GET_NUM_TX_BUFFERS)) {
		    fprintf(stderr, "Unhandled Command %s: addr=%#010x val=%#010x\n", __func__, addr, val);
		}
	    }
	    break;
	case VMXNET_INIT_ADDR:
	    vs->s2.vmxdata_addr = val;
            s->phys_mem_read(s->dma_opaque, vs->s2.vmxdata_addr, (void *) &dd, sizeof(dd), 0);
            trace_vmxnet_init_addr(vs->s2.vmxdata_addr, dd.rxRingLength, dd.rxRingOffset, dd.rxRingLength2, dd.rxRingOffset2, dd.txRingLength, dd.txRingOffset);
            if (val) {
                vs->s2.vmx_rx_ring = val + dd.rxRingOffset;
                vs->s2.vmx_rx_ring_length = dd.rxRingLength;
                vs->s2.vmx_rx_ring2 = val + dd.rxRingOffset2;
                vs->s2.vmx_rx_ring2_length = dd.rxRingLength2;
                vs->s2.vmx_tx_ring = val + dd.txRingOffset;
                vs->s2.vmx_tx_ring_length = dd.txRingLength;
                vs->s2.vmx_interrupt_enabled = true;
            } else {
                vs->s2.vmx_interrupt_enabled = false;
            }
	    vs->s2.vmx_rx_ring_index = 0;
	    vs->s2.vmx_rx_last_interrupt_index = -1;
	    vs->s2.vmx_tx_last_interrupt_index = -1;
	    vs->s2.vmx_rx_ring2_index = 0;
	    vs->s2.vmx_tx_ring_index = 0;
	    ladrf = (uint16_t *) dd.LADRF;
	    s->csr[8] = ladrf[0];
	    s->csr[9] = ladrf[1];
	    s->csr[10] = ladrf[2];
	    s->csr[11] = ladrf[3];
	    if (!(dd.ifflags & VMXNET_IFF_MULTICAST)) {
		s->csr[8] = 0;
		s->csr[9] = 0;
		s->csr[10] = 0;
		s->csr[11] = 0;
	    }
	    if (dd.ifflags & ~(VMXNET_IFF_PROMISC | VMXNET_IFF_BROADCAST | VMXNET_IFF_MULTICAST)) {
		// Linux driver sets most bits to 1.
                // fprintf(stderr, "vmxnet: Unhandled init IFF ifflags = 0x%x\n", dd.ifflags);
	    }
	    if (!!(dd.ifflags & VMXNET_IFF_PROMISC) ^ CSR_PROM(s)) {
		/* check for promiscuous mode change */
#if 0
		if (vs->s2.pDrv)
		    vs->s2.pDrv->pfnSetPromiscuousMode(vs->s2.pDrv, !!(dd.ifflags & VMXNET_IFF_PROMISC));
#endif
		s->csr[15] = (dd.ifflags & VMXNET_IFF_PROMISC) ? (s->csr[15] | 0x8000) : (s->csr[15] & ~0x8000);
	    }
	    if (!!(dd.ifflags & VMXNET_IFF_BROADCAST) ^ CSR_DRCVBC(s))  {
		s->csr[15] = !(dd.ifflags & VMXNET_IFF_BROADCAST) ? (s->csr[15] | 0x4000) : (s->csr[15] & ~0x4000);
	    }
	    break;
	case VMXNET_INIT_LENGTH:
	    vs->s2.vmxdata_length = val;
	    vs->s2.vmxnet_reg[VMXNET_INIT_LENGTH] = val;
	    break;
	default:
            fprintf(stderr, "Unhandled %s: addr=%#010x val=%#010x\n",
                    __func__, addr, val);
	    break;
	}
}

static uint32_t vmxnet_ioport_readl(PCNetVmxState *vs, uint32_t addr)
{
    uint32_t val = ~0U;

    switch (addr & 0x3f) {
    case 0x00:
        val = vs->s2.vmxnet_reg[0];
        break;
    case VMXNET_LOW_VERSION:
        val = vs->s2.vmxnet_reg[VMXNET_LOW_VERSION];
        break;
    case VMXNET_HIGH_VERSION:
        val = vs->s2.vmxnet_reg[VMXNET_HIGH_VERSION];
        break;
    case VMXNET_COMMAND_ADDR:
        switch (vs->s2.vmxnet_reg[VMXNET_COMMAND_ADDR])
        {
        case VMXNET_CMD_GET_FEATURES:
            val = 0;
            break;
        case VMXNET_CMD_GET_CAPABILITIES:
            val = 0;
            break;
        case VMXNET_CMD_GET_NUM_RX_BUFFERS:
            val = 100;
            break;
        case VMXNET_CMD_GET_NUM_TX_BUFFERS:
            val = 100;
            break;
        default:
            fprintf(stderr, "Unhandled command %s: addr=%#010x val=%#010x\n",
                    __func__, addr, val);
            break;
        }
        break;
    case VMXNET_STATUS_ADDR:
        if (vs->s1.lnkst) {
            val = VMXNET_STATUS_CONNECTED;
        } else {
            val = 0;
            vs->s2.link_down_reported++;
        }
        val |= VMXNET_STATUS_ENABLED;
        break;
    case VMXNET_TX_ADDR:
        val = 0;
        vmxnet_poll_rx_tx(vs);
        break;
    default:
        fprintf(stderr, "Unhandled %s: addr=%#010x val=%#010x\n",
                __func__, addr, val);
        break;
    }
    vmxnet_update_irq(vs);
    trace_vmxnet_ioport_readl(vs, addr, val);
    return val;
}

static uint64_t vlance_ioport_read(void *opaque, hwaddr addr,
                                  unsigned size)
{
    PCNetVmxState *vs = opaque;

    trace_vlance_ioport_read(opaque, addr, size);
    if (vs->s2.vmxdata_addr) {
        vmxnet_transmit(vs);
    }
    if (vs->s2.vmxnet2) {
        if (size == 1) {
            return vmxnet_ioport_readb(vs, addr);
        } else if (size == 2) {
            return vmxnet_ioport_readw(vs, addr);
        } else if (size == 4) {
            return vmxnet_ioport_readl(vs, addr);
        }
    } else if (addr < PCNET_IOPORT_SIZE) {
        if (addr < 0x10 || size == 1) {
            return pcnet_ioport_read(opaque, addr, size);
        } else if (size == 2) {
            return vlance_ioport_readw(vs, addr);
        } else if (size == 4) {
            return vlance_ioport_readl(vs, addr);
        }
    } else if (addr < PCNET_IOPORT_SIZE + MORPH_PORT_SIZE)  {
        hwaddr addr1 = addr - PCNET_IOPORT_SIZE;

        if (size == 1) {
            return vlance_morph_ioport_readb(vs, addr1);
        } else if (size == 2) {
            return vlance_morph_ioport_readw(vs, addr1);
        } else if (size == 4) {
            return vlance_morph_ioport_readl(vs, addr1);
        }
    } else if (addr < PCNET_IOPORT_SIZE + MORPH_PORT_SIZE + VMXNET_CHIP_IO_RESV_SIZE)  {
        hwaddr addr1 = addr - PCNET_IOPORT_SIZE - MORPH_PORT_SIZE;

        if (size == 1) {
            return vmxnet_ioport_readb(vs, addr1);
        } else if (size == 2) {
            return vmxnet_ioport_readw(vs, addr1);
        } else if (size == 4) {
            return vmxnet_ioport_readl(vs, addr1);
        }
    } else {
        fprintf(stderr, "%s: Bad read @ %llx,%d\n",
               __func__, (long long unsigned int)addr, size);
    }
    return ((uint64_t)1 << (size * 8)) - 1;
}

static void vlance_ioport_write(void *opaque, hwaddr addr,
                               uint64_t data, unsigned size)
{
    PCNetVmxState *vs = opaque;

    trace_vlance_ioport_write(opaque, addr, data, size);
    if (vs->s2.vmxdata_addr) {
        vmxnet_transmit(vs);
    }
    if (vs->s2.vmxnet2) {
        if (size == 1) {
            vmxnet_ioport_writeb(vs, addr, data);
        } else if (size == 2) {
            vmxnet_ioport_writew(vs, addr, data);
        } else if (size == 4) {
            vmxnet_ioport_writel(vs, addr, data);
        }
    } else if (addr < PCNET_IOPORT_SIZE) {
        if (addr < 0x10 || size == 1) {
            pcnet_ioport_write(opaque, addr, data, size);
        } else if (size == 2) {
            vlance_ioport_writew(vs, addr, data);
        } else if (size == 4) {
            vlance_ioport_writel(vs, addr, data);
        }
    } else if (addr < PCNET_IOPORT_SIZE + MORPH_PORT_SIZE)  {
        hwaddr addr1 = addr - PCNET_IOPORT_SIZE;

        if (size == 1) {
            vlance_morph_ioport_writeb(vs, addr1, data);
        } else if (size == 2) {
            vlance_morph_ioport_writew(vs, addr1, data);
        } else if (size == 4) {
            vlance_morph_ioport_writel(vs, addr1, data);
        }
    } else if (addr < PCNET_IOPORT_SIZE + MORPH_PORT_SIZE + VMXNET_CHIP_IO_RESV_SIZE)  {
        hwaddr addr1 = addr - PCNET_IOPORT_SIZE - MORPH_PORT_SIZE;

        if (size == 1) {
            vmxnet_ioport_writeb(vs, addr1, data);
        } else if (size == 2) {
            vmxnet_ioport_writew(vs, addr1, data);
        } else if (size == 4) {
            vmxnet_ioport_writel(vs, addr1, data);
        }
    } else {
        fprintf(stderr, "%s: Bad write @ %llx of %llx,%d\n",
               __func__,
               (long long unsigned int)addr,
               (long long unsigned int)data,
               size);
    }
}

static const MemoryRegionOps vlance_io_ops = {
    .read = vlance_ioport_read,
    .write = vlance_ioport_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static uint64_t vmxnet_ioport_read(void *opaque, hwaddr addr,
                                  unsigned size)
{
    PCNetVmxState *vs = opaque;

    trace_vmxnet_ioport_read(opaque, addr, size);
    if (vs->s2.vmxdata_addr) {
        vmxnet_transmit(vs);
    }
    if (size == 1) {
        return vmxnet_ioport_readb(vs, addr);
    } else if (size == 2) {
        return vmxnet_ioport_readw(vs, addr);
    } else if (size == 4) {
        return vmxnet_ioport_readl(vs, addr);
    } else {
        fprintf(stderr, "%s: Bad read @ %llx,%d\n",
               __func__, (long long unsigned int)addr, size);
    }
    return ((uint64_t)1 << (size * 8)) - 1;
}

static void vmxnet_ioport_write(void *opaque, hwaddr addr,
                               uint64_t data, unsigned size)
{
    PCNetVmxState *vs = opaque;

    trace_vmxnet_ioport_write(opaque, addr, data, size);
    if (vs->s2.vmxdata_addr) {
        vmxnet_transmit(vs);
    }
    if (size == 1) {
        vmxnet_ioport_writeb(vs, addr, data);
    } else if (size == 2) {
        vmxnet_ioport_writew(vs, addr, data);
    } else if (size == 4) {
        vmxnet_ioport_writel(vs, addr, data);
    } else {
        fprintf(stderr, "%s: Bad write @ %llx of %llx,%d\n",
               __func__,
               (long long unsigned int)addr,
               (long long unsigned int)data,
               size);
    }
}

static const MemoryRegionOps vmxnet_io_ops = {
    .read = vmxnet_ioport_read,
    .write = vmxnet_ioport_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void pcnet_mmio_writeb(void *opaque, hwaddr addr, uint32_t val)
{
    PCNetState *d = opaque;

    trace_pcnet_mmio_writeb(opaque, addr, val);
    if (!(addr & 0x10))
        pcnet_aprom_writeb(d, addr & 0x0f, val);
}

static uint32_t pcnet_mmio_readb(void *opaque, hwaddr addr)
{
    PCNetState *d = opaque;
    uint32_t val = -1;

    if (!(addr & 0x10))
        val = pcnet_aprom_readb(d, addr & 0x0f);
    trace_pcnet_mmio_readb(opaque, addr, val);
    return val;
}

static void pcnet_mmio_writew(void *opaque, hwaddr addr, uint32_t val)
{
    PCNetState *d = opaque;

    trace_pcnet_mmio_writew(opaque, addr, val);
    if (addr & 0x10)
        pcnet_ioport_writew(d, addr & 0x0f, val);
    else {
        addr &= 0x0f;
        pcnet_aprom_writeb(d, addr, val & 0xff);
        pcnet_aprom_writeb(d, addr+1, (val & 0xff00) >> 8);
    }
}

static uint32_t pcnet_mmio_readw(void *opaque, hwaddr addr)
{
    PCNetState *d = opaque;
    uint32_t val = -1;

    if (addr & 0x10)
        val = pcnet_ioport_readw(d, addr & 0x0f);
    else {
        addr &= 0x0f;
        val = pcnet_aprom_readb(d, addr+1);
        val <<= 8;
        val |= pcnet_aprom_readb(d, addr);
    }
    trace_pcnet_mmio_readw(opaque, addr, val);
    return val;
}

static void pcnet_mmio_writel(void *opaque, hwaddr addr, uint32_t val)
{
    PCNetState *d = opaque;

    trace_pcnet_mmio_writel(opaque, addr, val);
    if (addr & 0x10)
        pcnet_ioport_writel(d, addr & 0x0f, val);
    else {
        addr &= 0x0f;
        pcnet_aprom_writeb(d, addr, val & 0xff);
        pcnet_aprom_writeb(d, addr+1, (val & 0xff00) >> 8);
        pcnet_aprom_writeb(d, addr+2, (val & 0xff0000) >> 16);
        pcnet_aprom_writeb(d, addr+3, (val & 0xff000000) >> 24);
    }
}

static uint32_t pcnet_mmio_readl(void *opaque, hwaddr addr)
{
    PCNetState *d = opaque;
    uint32_t val;

    if (addr & 0x10)
        val = pcnet_ioport_readl(d, addr & 0x0f);
    else {
        addr &= 0x0f;
        val = pcnet_aprom_readb(d, addr+3);
        val <<= 8;
        val |= pcnet_aprom_readb(d, addr+2);
        val <<= 8;
        val |= pcnet_aprom_readb(d, addr+1);
        val <<= 8;
        val |= pcnet_aprom_readb(d, addr);
    }
    trace_pcnet_mmio_readl(opaque, addr, val);
    return val;
}

static const VMStateDescription vmstate_pci_pcnet = {
    .name = "pcnet",
    .version_id = 3,
    .minimum_version_id = 2,
    .minimum_version_id_old = 2,
    .fields      = (VMStateField []) {
        VMSTATE_PCI_DEVICE(pci_dev, PCIPCNetState),
        VMSTATE_STRUCT(state, PCIPCNetState, 0, vmstate_pcnet, PCNetState),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_pci_vlance = {
    .name = "vlance",
    .version_id = 0,
    .minimum_version_id = 0,
    .minimum_version_id_old = 0,
    .fields      = (VMStateField []) {
        VMSTATE_PCI_DEVICE(pci_dev, PCIPCNetVmxState),
        VMSTATE_STRUCT(state.s1, PCIPCNetVmxState, 0, vmstate_pcnet, PCNetState),
        VMSTATE_STRUCT(state.s2, PCIPCNetVmxState, 0, vmstate_vlance, PCNetStateVmx),
        VMSTATE_END_OF_LIST()
    }
};

/* PCI interface */

static const MemoryRegionOps pcnet_mmio_ops = {
    .old_mmio = {
        .read = { pcnet_mmio_readb, pcnet_mmio_readw, pcnet_mmio_readl },
        .write = { pcnet_mmio_writeb, pcnet_mmio_writew, pcnet_mmio_writel },
    },
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void pci_physical_memory_write(void *dma_opaque, hwaddr addr,
                                      uint8_t *buf, int len, int do_bswap)
{
    pci_dma_write(dma_opaque, addr, buf, len);
}

static void pci_physical_memory_read(void *dma_opaque, hwaddr addr,
                                     uint8_t *buf, int len, int do_bswap)
{
    pci_dma_read(dma_opaque, addr, buf, len);
}

static void pci_pcnet_cleanup(NetClientState *nc)
{
    PCNetState *d = DO_UPCAST(NICState, nc, nc)->opaque;

    pcnet_common_cleanup(d);
}

static void pci_pcnet_uninit(PCIDevice *dev)
{
    PCIPCNetState *d = DO_UPCAST(PCIPCNetState, pci_dev, dev);

    memory_region_destroy(&d->state.mmio);
    memory_region_destroy(&d->io_bar);
    qemu_del_timer(d->state.poll_timer);
    qemu_free_timer(d->state.poll_timer);
    qemu_del_net_client(&d->state.nic->nc);
}

static void pci_vlance_uninit(PCIDevice *dev)
{
    PCIPCNetVmxState *d = DO_UPCAST(PCIPCNetVmxState, pci_dev, dev);

    memory_region_destroy(&d->io_bar);
    qemu_del_timer(d->state.s1.poll_timer);
    qemu_free_timer(d->state.s1.poll_timer);
    qemu_del_net_client(&d->state.s1.nic->nc);
}

static NetClientInfo net_pci_pcnet_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NIC,
    .size = sizeof(NICState),
    .can_receive = pcnet_can_receive,
    .receive = pcnet_receive,
    .link_status_changed = pcnet_set_link_status,
    .cleanup = pci_pcnet_cleanup,
};

static NetClientInfo net_pci_vlance_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NIC,
    .size = sizeof(NICState),
    .can_receive = vlance_can_receive,
    .receive = vlance_receive,
    .link_status_changed = vlance_set_link_status,
    .cleanup = pci_pcnet_cleanup,
};

static int pci_pcnet_init(PCIDevice *pci_dev)
{
    PCIPCNetState *d = DO_UPCAST(PCIPCNetState, pci_dev, pci_dev);
    PCNetState *s = &d->state;
    uint8_t *pci_conf;

#if 0
    fprintf(stderr, "sizeof(RMD)=%d, sizeof(TMD)=%d\n",
            sizeof(struct pcnet_RMD), sizeof(struct pcnet_TMD));
#endif

    pci_conf = pci_dev->config;

    pci_set_word(pci_conf + PCI_STATUS,
                 PCI_STATUS_FAST_BACK | PCI_STATUS_DEVSEL_MEDIUM);

    pci_set_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID, 0x0);
    pci_set_word(pci_conf + PCI_SUBSYSTEM_ID, 0x0);

    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */
    pci_conf[PCI_MIN_GNT] = 0x06;
    pci_conf[PCI_MAX_LAT] = 0xff;

    /* Handler for memory-mapped I/O */
    memory_region_init_io(&d->state.mmio, &pcnet_mmio_ops, s, "pcnet-mmio",
                          PCNET_PNPMMIO_SIZE);

    memory_region_init_io(&d->io_bar, &pcnet_io_ops, s, "pcnet-io",
                          PCNET_IOPORT_SIZE);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_IO, &d->io_bar);

    pci_register_bar(pci_dev, 1, 0, &s->mmio);

    s->irq = pci_dev->irq[0];
    s->phys_mem_read = pci_physical_memory_read;
    s->phys_mem_write = pci_physical_memory_write;
    s->dma_opaque = pci_dev;

    return pcnet_common_init(&pci_dev->qdev, s, &net_pci_pcnet_info);
}

static void vlance_common_init(PCNetStateVmx *s2)
{
    memset(s2, 0, sizeof(s2));
}

static int pci_vmxnet_init(PCIDevice *pci_dev)
{
    PCIPCNetVmxState *d = DO_UPCAST(PCIPCNetVmxState, pci_dev, pci_dev);
    PCNetVmxState *vs = &d->state;
    PCNetState *s = &vs->s1;
    uint8_t *pci_conf;

    pci_conf = pci_dev->config;

    pci_conf[PCI_COMMAND] = PCI_COMMAND_MASTER;
    pci_set_word(pci_conf + PCI_STATUS,
                 PCI_STATUS_FAST_BACK | PCI_STATUS_DEVSEL_MEDIUM);
    pci_conf[PCI_LATENCY_TIMER] = 0x40;
    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */
    pci_conf[PCI_MIN_GNT] = 0x06;
    pci_conf[PCI_MAX_LAT] = 0xff;

    memset(&s->mmio, 0, sizeof (s->mmio));

    memory_region_init_io(&d->io_bar, &vlance_io_ops, s, "vmxnet-io",
                          VMXNET_CHIP_IO_RESV_SIZE);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_IO, &d->io_bar);

    s->irq = pci_dev->irq[0];
    s->phys_mem_read = pci_physical_memory_read;
    s->phys_mem_write = pci_physical_memory_write;
    s->dma_opaque = pci_dev;

    vlance_common_init(&vs->s2);
    vs->s2.vmxnet2 = true;
    return pcnet_common_init(&pci_dev->qdev, s, &net_pci_vlance_info);
}

static int pci_vlance_init(PCIDevice *pci_dev)
{
    PCIPCNetVmxState *d = DO_UPCAST(PCIPCNetVmxState, pci_dev, pci_dev);
    PCNetVmxState *vs = &d->state;
    PCNetState *s = &vs->s1;
    uint8_t *pci_conf;

    pci_conf = pci_dev->config;

    pci_set_word(pci_conf + PCI_STATUS,
                 PCI_STATUS_FAST_BACK | PCI_STATUS_DEVSEL_MEDIUM);
    pci_conf[PCI_LATENCY_TIMER] = 0x40;
    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */
    pci_conf[PCI_MIN_GNT] = 0x06;
    pci_conf[PCI_MAX_LAT] = 0xff;

    memset(&s->mmio, 0, sizeof (s->mmio));

    memory_region_init_io(&d->io_bar, &vlance_io_ops, s, "vlance-io",
                          PCNET_IOPORT_SIZE + MORPH_PORT_SIZE + VMXNET_CHIP_IO_RESV_SIZE + 28);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_IO, &d->io_bar);

    s->irq = pci_dev->irq[0];
    s->phys_mem_read = pci_physical_memory_read;
    s->phys_mem_write = pci_physical_memory_write;
    s->dma_opaque = pci_dev;

    vlance_common_init(&vs->s2);
    return pcnet_common_init(&pci_dev->qdev, s, &net_pci_vlance_info);
}

static void pcnet_pci_reset(DeviceState *dev)
{
    PCIPCNetState *d = DO_UPCAST(PCIPCNetState, pci_dev.qdev, dev);

    pcnet_h_reset(&d->state);
}

static void vlance_pci_reset(DeviceState *dev)
{
    PCIPCNetVmxState *d = DO_UPCAST(PCIPCNetVmxState, pci_dev.qdev, dev);
    PCNetVmxState *vs = &d->state;
    PCIDevice *pci_dev = vs->s1.dma_opaque;
    PCIDeviceClass *pc = PCI_DEVICE_GET_CLASS(pci_dev);

    vlance_h_reset(vs, pc->vendor_id, pc->subsystem_id, pc->subsystem_vendor_id);
}

static Property pcnet_properties[] = {
    DEFINE_NIC_PROPERTIES(PCIPCNetState, state.conf),
    DEFINE_PROP_END_OF_LIST(),
};

static Property vlance_properties[] = {
    DEFINE_NIC_PROPERTIES(PCIPCNetVmxState, state.s1.conf),
    DEFINE_PROP_END_OF_LIST(),
};

static void pcnet_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = pci_pcnet_init;
    k->exit = pci_pcnet_uninit;
    k->romfile = "pxe-pcnet.rom",
    k->vendor_id = PCI_VENDOR_ID_AMD;
    k->device_id = PCI_DEVICE_ID_AMD_LANCE;
    k->revision = 0x10;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    dc->reset = pcnet_pci_reset;
    dc->vmsd = &vmstate_pci_pcnet;
    dc->props = pcnet_properties;
}

static void vmxnet_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = pci_vmxnet_init;
    k->exit = pci_vlance_uninit;
    k->romfile = "pxe-pcnet.rom",
    k->vendor_id = PCI_VENDOR_ID_VMWARE;
    k->device_id = PCI_DEVICE_ID_VMWARE_NET;
    k->revision = 0x10;
    k->subsystem_vendor_id = PCI_VENDOR_ID_VMWARE;
    k->subsystem_id = PCI_DEVICE_ID_VMWARE_NET;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    dc->reset = vlance_pci_reset;
    dc->vmsd = &vmstate_pci_vlance;
    dc->props = vlance_properties;
}

static void vlance_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = pci_vlance_init;
    k->exit = pci_vlance_uninit;
    k->romfile = "pxe-pcnet.rom",
    k->vendor_id = PCI_VENDOR_ID_AMD;
    k->device_id = PCI_DEVICE_ID_AMD_LANCE;
    k->revision = 0x10;
    k->subsystem_vendor_id = PCI_VENDOR_ID_AMD;
    k->subsystem_id = PCI_DEVICE_ID_AMD_LANCE;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    dc->reset = vlance_pci_reset;
    dc->vmsd = &vmstate_pci_vlance;
    dc->props = vlance_properties;
}

static TypeInfo pcnet_info = {
    .name          = "pcnet",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PCIPCNetState),
    .class_init    = pcnet_class_init,
};

static TypeInfo vmxnet_info = {
    .name          = "vmxnet",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PCIPCNetVmxState),
    .class_init    = vmxnet_class_init,
};

static TypeInfo vlance_info = {
    .name          = "vlance",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PCIPCNetVmxState),
    .class_init    = vlance_class_init,
};

static void pci_pcnet_register_types(void)
{
    type_register_static(&pcnet_info);
    type_register_static(&vmxnet_info);
    type_register_static(&vlance_info);
}

type_init(pci_pcnet_register_types)
