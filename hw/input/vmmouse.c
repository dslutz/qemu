/*
 * QEMU VMMouse emulation
 *
 * Copyright (C) 2007 Anthony Liguori <anthony@codemonkey.ws>
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
#include "ui/console.h"
#include "hw/input/ps2.h"
#include "hw/i386/pc.h"
#include "hw/qdev.h"
#include "trace.h"

/* debug only vmmouse */
//#define DEBUG_VMMOUSE

/* VMMouse Commands */
#define VMMOUSE_GETPTRLOCATION  4
#define VMMOUSE_SETPTRLOCATION  5
#define VMMOUSE_GETVERSION      10
#define VMMOUSE_DATA            39
#define VMMOUSE_STATUS          40
#define VMMOUSE_COMMAND         41

#define VMMOUSE_READ_ID			0x45414552
#define VMMOUSE_DISABLE			0x000000f5
#define VMMOUSE_REQUEST_RELATIVE	0x4c455252
#define VMMOUSE_REQUEST_ABSOLUTE	0x53424152

#define VMMOUSE_QUEUE_SIZE	1024

#define VMMOUSE_VERSION		0x3442554a

#ifdef DEBUG_VMMOUSE
#define DPRINTF(fmt, ...) printf(fmt, ## __VA_ARGS__)
#else
#define DPRINTF(fmt, ...) do { } while (0)
#endif

#define TYPE_VMMOUSE "vmmouse"
#define VMMOUSE(obj) OBJECT_CHECK(VMMouseState, (obj), TYPE_VMMOUSE)

typedef struct VMMouseState
{
    ISADevice parent_obj;

    uint32_t queue[VMMOUSE_QUEUE_SIZE];
    int32_t queue_size;
    uint16_t nb_queue;
    uint16_t in_queue;
    uint16_t out_queue;
    uint16_t status;
    uint8_t absolute;
    QEMUPutMouseEntry *entry;
    void *ps2_mouse;
    int32_t set_x;
    int32_t set_y;
    int32_t set_buttons_state;
    int32_t div_x;
    int32_t div_y;
    int32_t div_x_down;
    int32_t div_y_down;
    int32_t gpl_lx;
    int32_t gpl_ly;
    int32_t gpl_dx;
    int32_t gpl_dy;
} VMMouseState;

static inline int32_t vmmouse_queue_size(VMMouseState *s)
{
    return s->nb_queue;
}

static uint32_t vmmouse_get_status(VMMouseState *s)
{
    trace_vmmouse_get_status(s, s->status, s->nb_queue);
    DPRINTF("vmmouse_get_status()\n");
    return (s->status << 16) | s->nb_queue;
}

static void vmmouse_mouse_event(void *opaque, int x, int y, int dz, int buttons_state)
{
    VMMouseState *s = opaque;
    int buttons = 0;

    if (s->nb_queue > (VMMOUSE_QUEUE_SIZE - 4)) {
        trace_vmmouse_mouse_event_full(opaque, x, y, dz, buttons_state, s->nb_queue);
        return;
    }

    trace_vmmouse_mouse_event(opaque, x, y, dz, buttons_state, s->nb_queue);
    DPRINTF("vmmouse_mouse_event(%d, %d, %d, %d)\n",
            x, y, dz, buttons_state);

    if ((buttons_state & MOUSE_EVENT_LBUTTON))
        buttons |= 0x20;
    if ((buttons_state & MOUSE_EVENT_RBUTTON))
        buttons |= 0x10;
    if ((buttons_state & MOUSE_EVENT_MBUTTON))
        buttons |= 0x08;

    if (s->absolute) {
        x <<= 1;
        y <<= 1;
    }

    s->queue[s->in_queue++] = buttons;
    s->in_queue = s->in_queue % VMMOUSE_QUEUE_SIZE;
    s->queue[s->in_queue++] = x;
    s->in_queue = s->in_queue % VMMOUSE_QUEUE_SIZE;
    s->queue[s->in_queue++] = y;
    s->in_queue = s->in_queue % VMMOUSE_QUEUE_SIZE;
    s->queue[s->in_queue++] = dz;
    s->in_queue = s->in_queue % VMMOUSE_QUEUE_SIZE;
    s->nb_queue += 4;

    /* need to still generate PS2 events to notify driver to
       read from queue */
    i8042_isa_mouse_fake_event(s->ps2_mouse);
}

static void vmmouse_mouse_abs_pos(void *opaque, int x, int y, int z, int buttons_state)
{
    VMMouseState *s = opaque;

    trace_vmmouse_mouse_abs_pos(opaque, x, y, z, buttons_state);
    DPRINTF("vmmouse_mouse_abs_pos(%d, %d, %d, %d)\n",
            x, y, z, buttons_state);

    s->set_x = x;
    s->set_y = y;
    s->set_buttons_state = buttons_state;
    s->div_x = 0;
    s->div_y = 0;
    s->div_x_down = 0;
    s->div_y_down = 0;
    s->gpl_lx = x;
    s->gpl_ly = y;
    s->gpl_dx = 0;
    s->gpl_dy = 0;
}

static void vmmouse_remove_handler(VMMouseState *s)
{
    if (s->entry) {
        trace_vmmouse_remove_handler_active(s, s->entry);
        qemu_remove_mouse_event_handler(s->entry);
        s->entry = NULL;
    } else {
        trace_vmmouse_remove_handler(s);
    }
}

static void vmmouse_update_handler(VMMouseState *s, int absolute)
{
    if (s->status != 0) {
        trace_vmmouse_update_handler_status(s, s->status);
        return;
    }
    if (s->absolute != absolute) {
        trace_vmmouse_update_handler_absolute(s, absolute, s->absolute);
        s->absolute = absolute;
        vmmouse_remove_handler(s);
    }
    if (s->entry == NULL) {
        trace_vmmouse_update_handler(s, absolute);
        s->entry = qemu_add_mouse_event_handler(vmmouse_mouse_event,
                                                s, s->absolute,
                                                "vmmouse");
        qemu_activate_mouse_event_handler(s->entry);
    }
}

static void vmmouse_read_id(VMMouseState *s)
{
    DPRINTF("vmmouse_read_id()\n");

    if (s->nb_queue == VMMOUSE_QUEUE_SIZE) {
        trace_vmmouse_read_id_full(s, s->nb_queue);
        return;
    }

    trace_vmmouse_read_id(s, s->nb_queue);
    s->queue[s->in_queue++] = VMMOUSE_VERSION;
    s->nb_queue++;
    s->status = 0;
}

static void vmmouse_request_relative(VMMouseState *s)
{
    trace_vmmouse_request_relative(s);
    DPRINTF("vmmouse_request_relative()\n");
    vmmouse_update_handler(s, 0);
}

static void vmmouse_request_absolute(VMMouseState *s)
{
    trace_vmmouse_request_absolute(s);
    DPRINTF("vmmouse_request_absolute()\n");
    vmmouse_update_handler(s, 1);
}

static void vmmouse_disable(VMMouseState *s)
{
    trace_vmmouse_disable(s);
    DPRINTF("vmmouse_disable()\n");
    s->status = 0xffff;
    vmmouse_remove_handler(s);
}

static void vmmouse_data(VMMouseState *s, uint32_t *data, uint32_t size)
{
    int i;

    trace_vmmouse_data(s, data, size);
    DPRINTF("vmmouse_data(%d)\n", size);

    if (size == 0 || size > 6 || size > s->nb_queue) {
        printf("vmmouse: driver requested too much data %d\n", size);
        s->status = 0xffff;
        vmmouse_remove_handler(s);
        return;
    }

    for (i = 0; i < size; i++) {
        data[i] = s->queue[s->out_queue++];
	s->out_queue = s->out_queue % VMMOUSE_QUEUE_SIZE;
    }

    s->nb_queue -= size;
}

static uint32_t vmmouse_ioport_read(void *opaque, uint32_t addr)
{
    VMMouseState *s = opaque;
    uint32_t data[6];
    uint16_t command;

    vmmouse_get_data(data);

    command = data[2] & 0xFFFF;
    trace_vmmouse_ioport_read(opaque, addr, command);

    switch (command) {
    case VMMOUSE_GETPTRLOCATION:
        data[0] = (s->set_x << 16) | s->set_y;
        trace_vmmouse_getptrlocation(opaque, data[0], s->set_x, s->set_y);
        break;
    case VMMOUSE_SETPTRLOCATION:
        trace_vmmouse_setptrlocation(opaque, s->set_x, s->set_y, data[1],
                                     (data[1] >> 16) & 0xFFFF, data[1] & 0xFFFF,
                                     kbd_mouse_is_absolute());
        if (kbd_mouse_is_absolute()) {
            trace_vmmouse_setptrlocation_4(opaque, s->status, s->nb_queue);
        } else {
            int dx, dy;
            int ldx = s->gpl_dx;
            int ldy = s->gpl_dy;

            dx = s->set_x - ((data[1] >> 16) & 0xFFFF);
            dy = s->set_y - (data[1] & 0xFFFF);
            trace_vmmouse_setptrlocation_1(opaque,
                                           s->gpl_lx, s->gpl_ly,
                                           dx, dy);
            if (!s->div_x_down) {
                if ((dx < 0 && ldx > 0) || (dx > 0 && ldx < 0)) {
                    s->div_x++;
                    if (!s->div_x) {
                        s->div_x = 2;
                    }
                } else {
                    s->div_x--;
                    if (!s->div_x) {
                        s->div_x = -1;
                    }
                }
                if ((dy < 0 && ldy > 0) || (dy > 0 && ldy < 0)) {
                    s->div_y++;
                    if (!s->div_y) {
                        s->div_y = 2;
                    }
                } else {
                    s->div_y--;
                    if (!s->div_y) {
                        s->div_y = -1;
                    }
                }
            }

            s->gpl_dx = dx;
            s->gpl_dy = dy;
            /* Prevent mouse bounce by limiting movement */
            if (s->div_x > 0) {
                dx /= s->div_x;
            } else if (s->div_x < -1) {
                dx *= -s->div_x - 1;
            }
            if (s->div_y > 0) {
                dy /= s->div_y;
            } else if (s->div_y < -1) {
                dy *= -s->div_y - 1;
            }
            trace_vmmouse_setptrlocation_2(opaque, ldx, ldy, dx, dy, s->div_x, s->div_y);
            s->gpl_lx = (data[1] >> 16) & 0xFFFF;
            s->gpl_ly = data[1] & 0xFFFF;
            if (dx || dy) {
                s->div_x_down = 0;
                s->div_y_down = 0;
                kbd_mouse_event(dx, dy, 0, s->set_buttons_state);
            } else {
                trace_vmmouse_setptrlocation_3(opaque, s->div_x, s->div_y,
                                               s->div_x_down, s->div_y_down);
                if (s->div_x) {
                    if (s->div_x_down++ >= 2) {
                        if (s->div_x > 0) {
                            s->div_x--;
                        } else if (s->div_x < 0) {
                            s->div_x++;
                        }
                        s->div_x_down = 0;
                    }
                }
                if (s->div_y) {
                    if (s->div_y_down++ >= 2) {
                        if (s->div_y > 0) {
                            s->div_y--;
                        } else if (s->div_y < 0) {
                            s->div_y++;
                        }
                        s->div_y_down = 0;
                    }
                }
            }
        }
        break;
    case VMMOUSE_STATUS:
        data[0] = vmmouse_get_status(s);
        trace_vmmouse_status(opaque, data[0]);
        break;
    case VMMOUSE_COMMAND:
        trace_vmmouse_command(opaque, data[1]);
        switch (data[1]) {
        case VMMOUSE_DISABLE:
            vmmouse_disable(s);
            break;
        case VMMOUSE_READ_ID:
            vmmouse_read_id(s);
            break;
        case VMMOUSE_REQUEST_RELATIVE:
            vmmouse_request_relative(s);
            break;
        case VMMOUSE_REQUEST_ABSOLUTE:
            vmmouse_request_absolute(s);
            break;
        default:
            trace_vmmouse_ioport_read_unknown_vmcommand(opaque, addr, data[1]);
            printf("vmmouse: unknown command %x\n", data[1]);
            break;
        }
        break;
    case VMMOUSE_DATA:
        vmmouse_data(s, data, data[1]);
        break;
    default:
        trace_vmmouse_ioport_read_unknown_command(opaque, addr, command);
        printf("vmmouse: unknown command %x\n", command);
        break;
    }

    vmmouse_set_data(data);
    return data[0];
}

static int vmmouse_post_load(void *opaque, int version_id)
{
    VMMouseState *s = opaque;

    trace_vmmouse_post_load(opaque, version_id);
    vmmouse_remove_handler(s);
    vmmouse_update_handler(s, s->absolute);
    if (version_id == 0) {
        s->set_x = 0;
        s->set_y = 0;
        s->set_buttons_state = 0;
        s->div_x = 0;
        s->div_y = 0;
        s->div_x_down = 0;
        s->div_y_down = 0;
        s->gpl_lx = 0;
        s->gpl_ly = 0;
        s->gpl_dx = 0;
        s->gpl_dy = 0;
    }
    return 0;
}

static const VMStateDescription vmstate_vmmouse = {
    .name = "vmmouse",
    .version_id = 1,
    .minimum_version_id = 0,
    .minimum_version_id_old = 0,
    .post_load = vmmouse_post_load,
    .fields      = (VMStateField []) {
        VMSTATE_INT32_EQUAL(queue_size, VMMouseState),
        VMSTATE_UINT32_ARRAY(queue, VMMouseState, VMMOUSE_QUEUE_SIZE),
        VMSTATE_UINT16(nb_queue, VMMouseState),
        VMSTATE_UINT16(in_queue, VMMouseState),
        VMSTATE_UINT16(out_queue, VMMouseState),
        VMSTATE_UINT16(status, VMMouseState),
        VMSTATE_UINT8(absolute, VMMouseState),
        VMSTATE_INT32_V(set_x, VMMouseState, 1),
        VMSTATE_INT32_V(set_y, VMMouseState, 1),
        VMSTATE_INT32_V(set_buttons_state, VMMouseState, 1),
        VMSTATE_INT32_V(div_x, VMMouseState, 1),
        VMSTATE_INT32_V(div_y, VMMouseState, 1),
        VMSTATE_INT32_V(div_x_down, VMMouseState, 1),
        VMSTATE_INT32_V(div_y_down, VMMouseState, 1),
        VMSTATE_INT32_V(gpl_lx, VMMouseState, 1),
        VMSTATE_INT32_V(gpl_ly, VMMouseState, 1),
        VMSTATE_INT32_V(gpl_dx, VMMouseState, 1),
        VMSTATE_INT32_V(gpl_dy, VMMouseState, 1),
        VMSTATE_END_OF_LIST()
    }
};

static void vmmouse_reset(DeviceState *d)
{
    VMMouseState *s = VMMOUSE(d);

    trace_vmmouse_reset(s);
    s->status = 0xffff;
    s->queue_size = VMMOUSE_QUEUE_SIZE;

    vmmouse_disable(s);
}

static void vmmouse_realizefn(DeviceState *dev, Error **errp)
{
    VMMouseState *s = VMMOUSE(dev);

    trace_vmmouse_initfn(s, dev);
    DPRINTF("vmmouse_init\n");

    qemu_add_mouse_abs_pos_handler(vmmouse_mouse_abs_pos,
                                   s, "vmmouse");

    vmport_register(VMMOUSE_GETPTRLOCATION, vmmouse_ioport_read, s);
    vmport_register(VMMOUSE_SETPTRLOCATION, vmmouse_ioport_read, s);
    vmport_register(VMMOUSE_STATUS, vmmouse_ioport_read, s);
    vmport_register(VMMOUSE_COMMAND, vmmouse_ioport_read, s);
    vmport_register(VMMOUSE_DATA, vmmouse_ioport_read, s);
}

static Property vmmouse_properties[] = {
    DEFINE_PROP_PTR("ps2_mouse", VMMouseState, ps2_mouse),
    DEFINE_PROP_END_OF_LIST(),
};

static void vmmouse_class_initfn(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = vmmouse_realizefn;
    dc->no_user = 1;
    dc->reset = vmmouse_reset;
    dc->vmsd = &vmstate_vmmouse;
    dc->props = vmmouse_properties;
}

static const TypeInfo vmmouse_info = {
    .name          = TYPE_VMMOUSE,
    .parent        = TYPE_ISA_DEVICE,
    .instance_size = sizeof(VMMouseState),
    .class_init    = vmmouse_class_initfn,
};

static void vmmouse_register_types(void)
{
    type_register_static(&vmmouse_info);
}

type_init(vmmouse_register_types)
