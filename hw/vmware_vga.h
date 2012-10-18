#ifndef QEMU_VMWARE_VGA_H
#define QEMU_VMWARE_VGA_H

#include "qemu-common.h"

#ifndef VMARE_MODE_DEF
#define VMARE_MODE_DEF
extern int vmware_mode;
#endif

/* vmware_vga.c */
static inline DeviceState *pci_vmsvga_init(PCIBus *bus)
{
    PCIDevice *dev;
    
    dev = pci_create_simple(bus, vmware_mode ? PCI_DEVFN(0xf, 0) : -1, "vmware-svga");
    return &dev->qdev;
}

#endif
