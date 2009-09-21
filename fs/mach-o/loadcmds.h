#ifndef  _MACHO_LOADCMDS_H
# define _MACHO_LOADCMDS_H 1

# include <linux/types.h>

/*
 * Mach-O load-command types, borrowed from Darwin
 */
typedef __u32 __bitwise macho_loadcmd_num_t;
enum {
# define _ENTRY(type, num) \
	MACHO_LOADCMD_NUM_##type = ((__force macho_loadcmd_num_t)num)
	_ENTRY(SEGMENT32,	0x01), /* LC_SEGMENT		*/
	_ENTRY(SYMTAB_STAB,	0x02), /* LC_SYMTAB		*/
	_ENTRY(SYMTAB_GDB,	0x03), /* LC_SYMSEG		*/
	_ENTRY(THREAD_NOSTACK,	0x04), /* LC_THREAD		*/
	_ENTRY(THREAD,		0x05), /* LC_UNIXTHREAD		*/
	_ENTRY(REF_FVMLIB,	0x06), /* LC_LOADFVMLIB		*/
	_ENTRY(ID_FVMLIB,	0x07), /* LC_IDFVMLIB		*/
	_ENTRY(ID,		0x08), /* LC_IDENT		*/
	_ENTRY(FVMFILE,		0x09), /* LC_FVMFILE		*/
	_ENTRY(PREPAGE,		0x0a), /* LC_PREPAGE		*/
	_ENTRY(SYMTAB_DYLD,	0x0b), /* LC_DYSYMTAB		*/
	_ENTRY(REF_DYLIB,	0x0c), /* LC_LOAD_DYLIB		*/
	_ENTRY(ID_DYLIB,	0x0d), /* LC_ID_DYLIB		*/
	_ENTRY(REF_DYLD,	0x0e), /* LC_LOAD_DYLINKER	*/
	_ENTRY(ID_DYLD,		0x0f), /* LC_ID_DYLINKER	*/
	_ENTRY(PREBINDING,	0x10), /* LC_PREBOUND_DYLIB	*/
	_ENTRY(INITCODE32,	0x11), /* LC_ROUTINES		*/
	_ENTRY(SUB_FRAMEWORK,	0x12), /* LC_SUB_FRAMEWORK	*/
	_ENTRY(SUB_UMBRELLA,	0x13), /* LC_SUB_UMBRELLA	*/
	_ENTRY(SUB_CLIENT,	0x14), /* LC_SUB_CLIENT		*/
	_ENTRY(SUB_LIBRARY,	0x15), /* LC_SUB_LIBRARY	*/
	_ENTRY(HINTS_2LEVEL,	0x16), /* LC_TWOLEVEL_HINTS	*/
	_ENTRY(PREBIND_CKSUM,	0x17), /* LC_PREBIND_CKSUM	*/
	_ENTRY(WEAKREF_DYLIB,	0x18), /* LC_LOAD_DYLIB_WEAK	*/
	_ENTRY(SEGMENT64,	0x19), /* LC_SEGMENT_64		*/
	_ENTRY(INITCODE64,	0x1a), /* LC_ROUTINES_64	*/
	_ENTRY(UUID,		0x1b), /* LC_UUID		*/
# undef _ENTRY
};

/* Mach-O load command header */
struct macho_loadcmd_hdr {
	__u32 cmd;
	__u32 size;
} __attribute__((__packed__));

/* Variable-length string in a Mach-O load command */
struct macho_loadcmd_varstr {
	__u32 off;
} __attribute__((__packed__));

/* Mach-O section in a segment load command */
struct macho_loadcmd_section32 {
	char name[16];
	char seg_name[16];
	__u32 vm_addr;
	__u32 vm_size;
	__u32 file_off;
	__u32 align;
	__u32 rel_off;
	__u32 rel_count;
	__u32 flags;
	__u32 rsv1;
	__u32 rsv2;
} __attribute__((__packed__));


/* Generic large load command */
struct macho_loadcmd_unknown {
	struct macho_loadcmd_hdr hdr;
	__u8 data[2048 - sizeof(struct macho_loadcmd_hdr)];
} __attribute__((__packed__));

/* Mach-o segment permission (protection) */
#define MACHO_PERM_R 0x01
#define MACHO_PERM_W 0x02
#define MACHO_PERM_X 0x04

/* Mach-O memory-mapped file segment (32-bit) */
struct macho_loadcmd_segment32 {
	struct macho_loadcmd_hdr hdr;
	char name[16];
	__u32 vm_addr;
	__u32 vm_size;
	__u32 file_off;
	__u32 file_size;
	__u32 prot_max;
	__u32 prot_init;
	__u32 sect_count;
	__u32 flags;
} __attribute__((__packed__));

/* Mach-O symbol table (stab) */
struct macho_loadcmd_symtab_stab {
	struct macho_loadcmd_hdr hdr;
	__u32 sym_off;
	__u32 sym_count;
	__u32 str_off;
	__u32 str_size;
} __attribute__((__packed__));

/* Mach-O symbol table (gdb, obsolete) */
struct macho_loadcmd_symtab_gdb {
	struct macho_loadcmd_hdr hdr;
	__u32 symtab_off;
	__u32 symtab_size;
} __attribute__((__packed__));

/* Mach-O new thread (with or without stack) */
# define MACHO_LOADCMD_THREAD_MAX_PPC 144
# define MACHO_LOADCMD_THREAD_MAX_X86 144
struct macho_loadcmd_thread {
	struct macho_loadcmd_hdr hdr;
	__u32 threaddata[];
} __attribute__((__packed__));

/* Mach-O reference to or identity of a fixed-VM shared lib */
struct macho_loadcmd_fvmlib {
	struct macho_loadcmd_hdr hdr;
	struct macho_loadcmd_varstr path;
	__u32 vers;
	__u32 addr;
	__u8 data[];
} __attribute__((__packed__));

/* Mach-O identity of an object (obsolete) */
struct macho_loadcmd_id {
	struct macho_loadcmd_hdr hdr;
	__u8 iddata[];
} __attribute__((__packed__));

/* Mach-O reference to a fixed VM file */
struct macho_loadcmd_fvmfile {
	struct macho_loadcmd_hdr hdr;
	struct macho_loadcmd_varstr path;
	__u32 addr;
	__u8 data[];
} __attribute__((__packed__));

/* Mach-O unknown (LC_PREPAGE) */
struct macho_loadcmd_prepage {
	struct macho_loadcmd_hdr hdr;
	__u8 prepagedata[];
} __attribute__((__packed__));

/* Mach-O symbol table (dyld) */
struct macho_loadcmd_symtab_dyld {
	struct macho_loadcmd_hdr hdr;
	__u32 sym_local_off;
	__u32 sym_local_num;
	__u32 sym_extern_off;
	__u32 sym_extern_num;
	__u32 sym_undef_off;
	__u32 sym_undef_num;
	__u32 toc_off;
	__u32 toc_num;
	__u32 modtab_off;
	__u32 modtab_num;
	__u32 extref_off;
	__u32 extref_num;
	__u32 indirect_off;
	__u32 indirect_num;
	__u32 extrel_off;
	__u32 extrel_num;
	__u32 localrel_off;
	__u32 localrel_num;
} __attribute__((__packed__));

/* Mach-O reference to or identity of a dynamic shared lib */
struct macho_loadcmd_dylib {
	struct macho_loadcmd_hdr hdr;
	struct macho_loadcmd_varstr path;
	__u32 timestamp;
	__u32 vers_current;
	__u32 vers_compat;
	__u8 data[];
} __attribute__((__packed__));

/* Mach-O reference to or identity of a dynamic linker */
struct macho_loadcmd_dyld {
	struct macho_loadcmd_hdr hdr;
	struct macho_loadcmd_varstr path;
	__u8 data[];
} __attribute__((__packed__));

/* Mach-O prebinding against a dynamic shared lib */
struct macho_loadcmd_prebinding {
	struct macho_loadcmd_hdr hdr;
	struct macho_loadcmd_varstr path;
	__u32 modvec_num;
	__u32 modvec_off;
	__u8 data[];
} __attribute__((__packed__));

/* Mach-O shared library init routine (32-bit) */
struct macho_loadcmd_initcode32 {
	struct macho_loadcmd_hdr hdr;
	__u32 init_address;
	__u32 init_module;
	__u32 reserved[6];
} __attribute__((__packed__));

/* Mach-O sub-framework file */
struct macho_loadcmd_sub_framework {
	struct macho_loadcmd_hdr hdr;
	struct macho_loadcmd_varstr parent;
	__u8 data[];
} __attribute__((__packed__));

/* Mach-O sub-umbrella-framework file */
struct macho_loadcmd_sub_umbrella {
	struct macho_loadcmd_hdr hdr;
	struct macho_loadcmd_varstr parent;
	__u8 data[];
} __attribute__((__packed__));

/* Mach-O sub-framework client entry */
struct macho_loadcmd_sub_client {
	struct macho_loadcmd_hdr hdr;
	struct macho_loadcmd_varstr client;
	__u8 data[];
} __attribute__((__packed__));

/* Mach-O sub-framework library */
struct macho_loadcmd_sub_library {
	struct macho_loadcmd_hdr hdr;
	struct macho_loadcmd_varstr parent;
	__u8 data[];
} __attribute__((__packed__));

/* Mach-O two-level namespace hinting table */
struct macho_loadcmd_hints_2level {
	struct macho_loadcmd_hdr hdr;
	__u32 hinttable_offset;
	__u32 hinttable_count;
} __attribute__((__packed__));

/* Mach-O prebinding checksum */
struct macho_loadcmd_prebind_cksum {
	struct macho_loadcmd_hdr hdr;
	__u8 data[];
} __attribute__((__packed__));

/* Mach-O memory-mapped file segment (64-bit) */
struct macho_loadcmd_segment64 {
	struct macho_loadcmd_hdr hdr;
	char name[16];
	__u64 vm_addr;
	__u64 vm_size;
	__u32 file_off;
	__u32 file_size;
	__u32 prot_max;
	__u32 prot_init;
	__u32 sect_count;
	__u32 flags;
} __attribute__((__packed__));

/* Mach-O shared library init routine (64-bit) */
struct macho_loadcmd_initcode64 {
	struct macho_loadcmd_hdr hdr;
	__u64 init_address;
	__u64 init_module;
	__u64 reserved[6];
} __attribute__((__packed__));

/* Mach-O linked object UUID (LC_UUID) */
struct macho_loadcmd_uuid {
	struct macho_loadcmd_hdr hdr;
	__u8 uuid[16];
} __attribute__((__packed__));

/* A generic Mach-O load command */
union macho_loadcmd {
	struct macho_loadcmd_hdr		hdr;
	struct macho_loadcmd_unknown		unknown;
	struct macho_loadcmd_segment32		segment32;
	struct macho_loadcmd_symtab_stab	symtab_stab;
	struct macho_loadcmd_symtab_gdb		symtab_gdb;
	struct macho_loadcmd_thread		thread;
	struct macho_loadcmd_fvmlib		fvmlib;
	struct macho_loadcmd_id			id;
	struct macho_loadcmd_fvmfile		fvmfile;
	struct macho_loadcmd_prepage		prepage;
	struct macho_loadcmd_symtab_dyld	symtab_dyld;
	struct macho_loadcmd_dylib		dylib;
	struct macho_loadcmd_dyld		dyld;
	struct macho_loadcmd_prebinding		prebinding;
	struct macho_loadcmd_initcode32		initcode32;
	struct macho_loadcmd_sub_framework	sub_framework;
	struct macho_loadcmd_sub_umbrella	sub_umbrella;
	struct macho_loadcmd_sub_client		sub_client;
	struct macho_loadcmd_sub_library	sub_library;
	struct macho_loadcmd_hints_2level	hints_2level;
	struct macho_loadcmd_prebind_cksum	prebind_cksum;
	struct macho_loadcmd_segment64		segment64;
	struct macho_loadcmd_initcode64		initcode64;
	struct macho_loadcmd_uuid		uuid;
} __attribute__((__packed__));

/* Inernal function to check and return a load-command string */
static inline const __u8 *macho_loadcmd_varstr_get__(
		const struct macho_loadcmd_hdr *hdr,
		const struct macho_loadcmd_varstr *varstr,
		const __u8 *loadcmd_data)
{
	unsigned long data_offset = ((const void *)loadcmd_data) -
			((const void *)hdr);
	unsigned long str_offset, i;

	/* Make sure the varstr points into the data area */
	if (varstr->off < data_offset)
		return NULL;
	str_offset = varstr->off - data_offset;

	/*
	 * Iterate over all the characters in the variable-length string to
	 * ensure that there is a trailing 0 before the end of the data area.
	 */
	for (i = str_offset; i < hdr->size; i++)
		if (!loadcmd_data[i])
			break;

	/* If we quit before we hit end-of-data then it's a valid string */
	if (i < hdr->size)
		return &loadcmd_data[str_offset];

	/* Sadly no such luck, it's a bogus Mach-O file */
	return NULL;
}

/*
 * Wrapper around the macho_loadcmd_varstr_get__ function above to make the
 * calling-convention much easier.
 *
 * Example usage:
 *   macho_loadcmd_dyld *dyld = (...);
 *   const char *dyld_path = macho_loadcmd_varstr_get(dyld, path);
 *   if (!dyld_path)
 *           return -ENOEXEC;
 */
#define macho_loadcmd_varstr_get(LOADCMD, VARSTR) \
	(macho_loadcmd_varstr_get__(&((LOADCMD)->hdr), \
			&((LOADCMD)->VARSTR), (LOADCMD)->data))

/*
 * A Mach-O load-command mapping table with human-readable strings
 */
struct macho_loadcmd_entry {
	const char *name;
	macho_loadcmd_num_t cmd;
	int pass;
};

static const struct macho_loadcmd_entry macho_loadcmds[] = {
#define _ENTRY(TYPE, NAME) {			\
		.name = NAME,				\
		.cmd = MACHO_LOADCMD_NUM_ ## TYPE,	\
	}
	_ENTRY(SEGMENT32,	"memory-mapped file segment (32-bit)"),
	_ENTRY(SYMTAB_STAB,	"symbol table (stab)"),
	_ENTRY(SYMTAB_GDB,	"symbol table (gdb, obsolete)"),
	_ENTRY(THREAD_NOSTACK,	"new thread (without stack)"),
	_ENTRY(THREAD,		"new thread (with stack)"),
	_ENTRY(REF_FVMLIB,	"reference to a fixed-VM shared lib"),
	_ENTRY(ID_FVMLIB,	"identity of a fixed-VM shared lib"),
	_ENTRY(ID,		"identity of an object (obsolete)"),
	_ENTRY(FVMFILE,		"reference to a fixed VM file"),
	_ENTRY(PREPAGE,		"unknown (LC_PREPAGE)"),
	_ENTRY(SYMTAB_DYLD,	"symbol table (dyld)"),
	_ENTRY(REF_DYLIB,	"reference to a dynamic shared lib"),
	_ENTRY(ID_DYLIB,	"identity of a dynamic shared lib"),
	_ENTRY(REF_DYLD,	"reference to a dynamic linker"),
	_ENTRY(ID_DYLD,		"identity of a dynamic linker"),
	_ENTRY(PREBINDING,	"prebinding against a dynamic shared lib"),
	_ENTRY(INITCODE32,	"shared library init routine (32-bit)"),
	_ENTRY(SUB_FRAMEWORK,	"sub-framework file"),
	_ENTRY(SUB_UMBRELLA,	"sub-umbrella-framework file"),
	_ENTRY(SUB_CLIENT,	"sub-framework client entry"),
	_ENTRY(SUB_LIBRARY,	"sub-framework library"),
	_ENTRY(HINTS_2LEVEL,	"two-level namespace hinting table"),
	_ENTRY(PREBIND_CKSUM,	"prebinding checksum"),
	_ENTRY(WEAKREF_DYLIB,	"weak reference to a dynamic shared lib"),
	_ENTRY(SEGMENT64,	"memory-mapped file segment (64-bit)"),
	_ENTRY(INITCODE64,	"shared library init routine (64-bit)"),
	_ENTRY(UUID,		"linked object UUID"),
	{ .name = NULL, }
#undef _ENTRY
};

static void macho_check_loadcmd(macho_loadcmd_num_t cmd)
{
	unsigned long i;

	/* Iterate over the list of file types */
	for (i = 0; macho_loadcmds[i].name; i++)
		if (macho_loadcmds[i].cmd == cmd)
			break;

	/* If we didn't find the load command type then ignore it */
	if (!macho_loadcmds[i].name) {
		macho_dbg("  Mach-O load command: unknown (%u)\n", cmd);
		return;
	}

	macho_dbg("  Mach-O load command: %s\n", macho_loadcmds[i].name);
}

#endif /* not _MACHO_LOADCMDS_H */
