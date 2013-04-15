/*
 * Helpers for getting linearized buffers from iov / filling buffers into iovs
 *
 * Copyright IBM, Corp. 2007, 2008
 * Copyright (C) 2010 Red Hat, Inc.
 *
 * Author(s):
 *  Anthony Liguori <aliguori@us.ibm.com>
 *  Amit Shah <amit.shah@redhat.com>
 *  Michael Tokarev <mjt@tls.msk.ru>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/iov.h"
#include "net/checksum.h"

uint32_t
iov_net_csum_add(const struct iovec *iov, const unsigned int iov_cnt,
                 size_t iov_off, size_t size)
{
    size_t iovec_off, buf_off;
    unsigned int i;
    uint32_t res = 0;
    uint32_t seq = 0;

    iovec_off = 0;
    buf_off = 0;
    for (i = 0; i < iov_cnt && size; i++) {
        if (iov_off < (iovec_off + iov[i].iov_len)) {
            size_t len = MIN((iovec_off + iov[i].iov_len) - iov_off , size);
            void *chunk_buf = iov[i].iov_base + (iov_off - iovec_off);

            res += net_checksum_add_cont(len, chunk_buf, seq);
            seq += len;

            buf_off += len;
            iov_off += len;
            size -= len;
        }
        iovec_off += iov[i].iov_len;
    }
    return res;
}
