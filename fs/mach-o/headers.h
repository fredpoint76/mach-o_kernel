#ifndef  _MACHO_HEADERS_H
# define _MACHO_HEADERS_H 1

# include <linux/types.h>
# include "cpus.h"

/* Mach-O universal binary header */
# define MACHO_FAT_MAGIC (__constant_cpu_to_be32(0xcafebabe))
struct macho_fat_header {
	__be32 magic;
	__be32 arch_count;
} __attribute__((__packed__));

struct macho_fat_arch {
	__be32 cpu_type;
	__be32 cpu_subtype;
	__be32 offset;
	__be32 size;
	__be32 align;
} __attribute__((__packed__));

/* Mach-O 32-bit arch-specific binary header */
# define MACHO_MACH32_MAGIC (0xfeedface)
# define MACHO_MACH32_CIGAM (___constant_swab32(MACHO_MACH32_MAGIC))
struct macho_mach32_header {
	__u32 magic;
	macho_cpu_type_t cpu_type;
	macho_cpu_subtype_t cpu_subtype;
	__u32 filetype;
	__u32 cmd_count;
	__u32 cmd_size;
	__u32 flags;
} __attribute__((__packed__));

/* Mach-O 64-bit arch-specific binary header */
# define MACHO_MACH64_MAGIC (0xfeedfacf)
# define MACHO_MACH64_CIGAM (___constant_swab32(MACHO_MACH64_MAGIC))
struct macho_mach64_header {
	__u32 magic;
	macho_cpu_type_t cpu_type;
	macho_cpu_subtype_t cpu_subtype;
	__u32 filetype;
	__u32 cmd_count;
	__u32 cmd_size;
	__u32 flags;
	__u32 reserved;
} __attribute__((__packed__));

#endif /* not _MACHO_HEADERS_H */
