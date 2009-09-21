#ifndef  _MACHO_FILES_H
# define _MACHO_FILES_H 1

# include "debug.h"
# include <linux/types.h>	/* For __u32	*/

/*
 * Mach-O file types, borrowed from Darwin
 */
typedef __u32 __bitwise macho_file_type_t;
enum {
# define _ENTRY(type, num) \
	MACHO_FILE_TYPE_##type = ((__force macho_file_type_t)num)
	_ENTRY(OBJECT,		0x01), /* MH_OBJECT	*/
	_ENTRY(EXECUTE,		0x02), /* MH_EXECUTE	*/
	_ENTRY(FVMLIB,		0x03), /* MH_FVMLIB	*/
	_ENTRY(CORE,		0x04), /* MH_CORE	*/
	_ENTRY(PRELOAD,		0x05), /* MH_PRELOAD	*/
	_ENTRY(DYLIB,		0x06), /* MH_DYLIB	*/
	_ENTRY(DYLD,		0x07), /* MH_DYLINKER	*/
	_ENTRY(BUNDLE,		0x08), /* MH_BUNDLE	*/
	_ENTRY(DYLIB_STUB,	0x09), /* MH_DYLIB_STUB	*/
	_ENTRY(DEBUG_SYM,	0x0a), /* MY_DSYM	*/
#undef _ENTRY
};

/*
 * A file type mapping table with human-readable strings
 */
struct macho_file_type_entry {
	const char *name;
	macho_file_type_t type;
	unsigned int runnable;
};

static const struct macho_file_type_entry macho_file_types[] = {
#define _ENTRY(TYPE, NAME, RUNNABLE) {			\
		.name = NAME,				\
		.type = MACHO_FILE_TYPE_ ## TYPE,	\
		.runnable = RUNNABLE			\
	}
	_ENTRY(OBJECT,		"relocatable object",			1),
	_ENTRY(EXECUTE,		"demand-paged executable",		1),
	_ENTRY(FVMLIB,		"fixed-virtual-memory shared library",	0),
	_ENTRY(CORE,		"coredump",				0),
	_ENTRY(PRELOAD,		"preloaded executable",			1),
	_ENTRY(DYLIB,		"dynamically linked shared library",	0),
	_ENTRY(DYLD,		"dynamic link editor",			0),
	_ENTRY(BUNDLE,		"dynamically linked module",		0),
	_ENTRY(DYLIB_STUB,	"shared library stub for static link",	0),
	_ENTRY(DEBUG_SYM,	"debug symbol file",			0),
	{ .name = NULL, }
#undef _ENTRY
};

/*
 * Mach-O file flags, borrowed from Darwin
 */
enum macho_file_flag {
#define _ENTRY(type, num) MACHO_FILE_FLAG_##type = num
	_ENTRY(NO_UNDEF,	 0), /* MH_NOUNDEFS			*/
	_ENTRY(INCR_LINK,	 1), /* MH_INCRLINK			*/
	_ENTRY(DYN_LINK,	 2), /* MH_DYLDLINK			*/
	_ENTRY(BIND_AT_LOAD,	 3), /* MH_BINDATLOAD			*/
	_ENTRY(PREBOUND,	 4), /* MH_PREBOUND			*/
	_ENTRY(SPLIT_SEGS,	 5), /* MH_SPLIT_SEGS			*/
	_ENTRY(LAZY_INIT,	 6), /* MH_LAZY_INIT			*/
	_ENTRY(TWO_LEVEL,	 7), /* MH_TWOLEVEL			*/
	_ENTRY(FORCE_FLAT,	 8), /* MH_FORCE_FLAT			*/
	_ENTRY(NO_MULT_DEFS,	 9), /* MH_NOMULTIDEFS			*/
	_ENTRY(NO_FIX_PREBIND,	10), /* MH_NOFIXPREBINDING		*/
	_ENTRY(PREBINDABLE,	11), /* MH_PREBINDABLE			*/
	_ENTRY(ALL_MODS_BOUND,	12), /* MH_ALLMODSBOUND			*/
	_ENTRY(SUBSECT_VIA_SYM,	13), /* MH_SUBSECTIONS_VIA_SYMBOLS	*/
	_ENTRY(CANONICAL,	14), /* MH_CANONICAL			*/
	_ENTRY(WEAK_DEFINES,	15), /* MH_WEAK_DEFINES			*/
	_ENTRY(BINDS_TO_WEAK,	16), /* MH_BINDS_TO_WEAK		*/
	_ENTRY(EXECSTACK,	17), /* MH_ALLOW_STACK_EXECUTION	*/
#undef _ENTRY
};

/*
 * A file flag mapping table with human-readable strings
 */
static const char *macho_file_flags[] = {
#define _ENTRY(FLAG, NAME) [MACHO_FILE_FLAG_ ## FLAG] = NAME
	_ENTRY( NO_UNDEF,	"has no undefined references"		),
	_ENTRY( INCR_LINK,	"was incrementally linked"		),
	_ENTRY( DYN_LINK,	"was dynamically linked"		),
	_ENTRY( BIND_AT_LOAD,	"will bind undefined refs during load"	),
	_ENTRY( PREBOUND,	"is prebound"				),
	_ENTRY( SPLIT_SEGS,	"has split RO and R/W segments"		),
	_ENTRY( LAZY_INIT,	"is lazily initialized"			),
	_ENTRY( TWO_LEVEL,	"uses two-level namespace bindings"	),
	_ENTRY( FORCE_FLAT,	"forces flat namespace bindings"	),
	_ENTRY( NO_MULT_DEFS,	"doesn't have multiply defined symbols"	),
	_ENTRY( NO_FIX_PREBIND,	"won't notify the prebinding agent"	),
	_ENTRY( PREBINDABLE,	"can be prebound"			),
	_ENTRY( ALL_MODS_BOUND,	"is fully bound to two-level namespaces"),
	_ENTRY( SUBSECT_VIA_SYM,"can be divided via symbols"		),
	_ENTRY( CANONICAL,	"is canonicalized by un-prebinding"	),
	_ENTRY( WEAK_DEFINES,	"exports weak symbols"			),
	_ENTRY( BINDS_TO_WEAK,	"imports weak symbols"			),
	_ENTRY( EXECSTACK,	"requires executable stack"		),
	NULL,
#undef _ENTRY
};

static int macho_check_file(macho_file_type_t type, __u32 flags)
{
	enum macho_file_flag flag = /* 0 */ MACHO_FILE_FLAG_NO_UNDEF;
	unsigned long i;

	/* Iterate over the list of file types */
	for (i = 0; macho_file_types[i].name; i++)
		if (macho_file_types[i].type == type)
			break;

	/* If we didn't find the file type then it's not executable */
	if (!macho_file_types[i].name) {
		macho_dbg("Unknown filetype (%u)\n", type);
		return 0;
	}

	macho_dbg("Mach-O %s (%sexecutable):\n", macho_file_types[i].name,
			macho_file_types[i].runnable?"":"not ");

	/* Check every flag */
	while (flags && macho_file_flags[flag]) {
		if (flags & 1)
			macho_dbg("    %s\n", macho_file_flags[flag]);

		flag++;
		flags >>= 1;
	}

	if (flags)
		macho_dbg("Unknown file flag bits: 0x%08lx\n",
				(unsigned long)(flags << flag));

	return macho_file_types[i].runnable;
}

#endif /* not _MACHO_FILES_H */
