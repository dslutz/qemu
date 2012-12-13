#include "dma.h"

/* Get VMware header files to compile */
#ifdef PCI_VENDOR_ID_VMWARE
#undef PCI_VENDOR_ID_VMWARE
#endif
#define uint16 uint16_t
#define PA dma_addr_t
#ifdef INLINE
#undef INLINE
#endif
#define INLINE inline
#define UNLIKELY(expr) __builtin_expect(!!(expr), 0)

#include "net.h"
#include "vmxnet2_def.h"

#undef UNLIKELY
#undef INLINE
#undef PA
#undef uint16
/* End of VMware header files */
