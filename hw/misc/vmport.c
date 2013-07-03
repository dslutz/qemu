/*
 * QEMU VMPort emulation
 *
 * Copyright (C) 2007 Hervé Poussineau
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
#include "hw/hw.h"
#include "hw/isa/isa.h"
#include "hw/i386/pc.h"
#include "sysemu/kvm.h"
#include "sysemu/sysemu.h"
#include "hw/xen/xen.h"
#include "hw/qdev.h"
#include "trace.h"

//#define VMPORT_DEBUG

#define VMPORT_CMD_GETVERSION 0x0a
#define VMPORT_CMD_GETRAMSIZE 0x14

#define VMPORT_ENTRIES 0x2c
#define VMPORT_MAGIC   0x564D5868

#define TYPE_VMPORT "vmport"
#define VMPORT(obj) OBJECT_CHECK(VMPortState, (obj), TYPE_VMPORT)

#define VM1004_SUSPEND_OFF (1 << 13)

typedef struct VMPortState
{
    ISADevice parent_obj;

    MemoryRegion io;
    MemoryRegion io1004;
    MemoryRegion io1005;
    IOPortReadFunc *func[VMPORT_ENTRIES];
    void *opaque[VMPORT_ENTRIES];
    uint64_t p1004;
} VMPortState;

static VMPortState *port_state;

void vmport_register(unsigned char command, IOPortReadFunc *func, void *opaque)
{
    if (command >= VMPORT_ENTRIES) {
        trace_vmport_register_bad(command, func, opaque);
        return;
    }

    trace_vmport_register(command, func, opaque);
    port_state->func[command] = func;
    port_state->opaque[command] = opaque;
}

static uint64_t vmport_ioport_read(void *opaque, hwaddr addr,
                                   unsigned size)
{
    VMPortState *s = opaque;
    CPUX86State *env = cpu_single_env;
    unsigned char command;
    uint32_t eax;

    trace_vmport_ioport_read(opaque, addr, size);
    cpu_synchronize_state(env);

    eax = env->regs[R_EAX];
    if (eax != VMPORT_MAGIC) {
        trace_vmport_ioport_read_bad(opaque, addr, size, eax);
        return eax;
    }

    command = env->regs[R_ECX];
    if (command >= VMPORT_ENTRIES) {
        trace_vmport_ioport_read_big(opaque, addr, size, command);
        return eax;
    }
    if (!s->func[command]) {
        trace_vmport_ioport_read_unknown(opaque, addr, size, command);
#ifdef VMPORT_DEBUG
        fprintf(stderr, "vmport: unknown command %x\n", command);
#endif
        return eax;
    }

    return s->func[command](s->opaque[command], addr);
}

static void vmport_ioport_write(void *opaque, hwaddr addr,
                                uint64_t val, unsigned size)
{
    CPUX86State *env = cpu_single_env;

    trace_vmport_ioport_write(opaque, addr, val, size);
    env->regs[R_EAX] = vmport_ioport_read(opaque, addr, 4);
}

static void vmport_ioport_1004_write(void *opaque, hwaddr addr,
                                uint64_t val, unsigned size)
{
    VMPortState *s = opaque;

    if (val == VM1004_SUSPEND_OFF)
	s->p1004 = val;
}

static void vmport_ioport_1005_write(void *opaque, hwaddr addr,
                                uint64_t val, unsigned size)
{
    VMPortState *s = opaque;

    if (val == VM1004_SUSPEND_OFF && s->p1004 == VM1004_SUSPEND_OFF)
	qemu_system_shutdown_request();
    else
	s->p1004 = 0;
}

static uint32_t vmport_cmd_get_version(void *opaque, uint32_t addr)
{
    CPUX86State *env = cpu_single_env;
    env->regs[R_EBX] = VMPORT_MAGIC;
    return 6;
}

static uint32_t vmport_cmd_ram_size(void *opaque, uint32_t addr)
{
    CPUX86State *env = cpu_single_env;
    env->regs[R_EBX] = 0x1177;
    return ram_size;
}

/* vmmouse helpers */
void vmmouse_get_data(uint32_t *data)
{
    CPUX86State *env = cpu_single_env;

    data[0] = env->regs[R_EAX]; data[1] = env->regs[R_EBX];
    data[2] = env->regs[R_ECX]; data[3] = env->regs[R_EDX];
    data[4] = env->regs[R_ESI]; data[5] = env->regs[R_EDI];
}

void vmmouse_set_data(const uint32_t *data)
{
    CPUX86State *env = cpu_single_env;

    env->regs[R_EAX] = data[0]; env->regs[R_EBX] = data[1];
    env->regs[R_ECX] = data[2]; env->regs[R_EDX] = data[3];
    env->regs[R_ESI] = data[4]; env->regs[R_EDI] = data[5];
}

static const MemoryRegionOps vmport_ops = {
    .read = vmport_ioport_read,
    .write = vmport_ioport_write,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static const MemoryRegionOps vmport_ops_4 = {
    //.read = vmport_ioport_1004_read,
    .write = vmport_ioport_1004_write,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static const MemoryRegionOps vmport_ops_5 = {
    //.read = vmport_ioport_1005_read,
    .write = vmport_ioport_1005_write,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static int vmport_initfn(ISADevice *dev)
{
    VMPortState *s = VMPORT(dev);

    memory_region_init_io(&s->io, &vmport_ops, s, "vmport", 1);
    isa_register_ioport(dev, &s->io, 0x5658);

    if (vmware_hw >= 7) {
	memory_region_init_io(&s->io1004, &vmport_ops_4, s, "vmport-1004", 1);
	isa_register_ioport(dev, &s->io1004, 0x1004);

	memory_region_init_io(&s->io1005, &vmport_ops_5, s, "vmport-1005", 1);
	isa_register_ioport(dev, &s->io1005, 0x1005);
	s->p1004 = 0;
    }

    port_state = s;
    /* Register some generic port commands */
    vmport_register(VMPORT_CMD_GETVERSION, vmport_cmd_get_version, NULL);
    vmport_register(VMPORT_CMD_GETRAMSIZE, vmport_cmd_ram_size, NULL);
    return 0;
}

static void vmport_class_initfn(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ISADeviceClass *ic = ISA_DEVICE_CLASS(klass);
    ic->init = vmport_initfn;
    dc->no_user = 1;
}

static const TypeInfo vmport_info = {
    .name          = TYPE_VMPORT,
    .parent        = TYPE_ISA_DEVICE,
    .instance_size = sizeof(VMPortState),
    .class_init    = vmport_class_initfn,
};

static void vmport_register_types(void)
{
    type_register_static(&vmport_info);
}

type_init(vmport_register_types)
