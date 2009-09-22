#ifndef  _MACHO_CPUS_H
# define _MACHO_CPUS_H 1

# include <linux/compiler.h>
# include <linux/types.h>
# include <linux/err.h>

/*
 * Mach-O CPU types, borrowed from Darwin
 */
typedef __u32 __bitwise macho_cpu_type_t;
#define _ENTRY(type, num) \
	MACHO_CPU_TYPE_##type = ((__force macho_cpu_type_t)num)
enum {
	/* Historical architecture codes */
	_ENTRY(ANY,	0xffffffff),	/* CPU_TYPE_ANY		*/
	_ENTRY(VAX,	0x00000001),	/* CPU_TYPE_VAX		*/
	_ENTRY(M68K,	0x00000006),	/* CPU_TYPE_MC680x0	*/
	_ENTRY(MIPS,	0x00000008),	/* CPU_TYPE_MIPS	*/
	_ENTRY(M98K,	0x0000000a),	/* CPU_TYPE_M98000	*/
	_ENTRY(PARISC,	0x0000000b),	/* CPU_TYPE_HPPA	*/
	_ENTRY(ARM,	0x0000000c),	/* CPU_TYPE_ARM		*/
	_ENTRY(M88K,	0x0000000d),	/* CPU_TYPE_M88000	*/
	_ENTRY(SPARC,	0x0000000e),	/* CPU_TYPE_SPARC	*/
	_ENTRY(I860,	0x0000000f),	/* CPU_TYPE_I860	*/
	_ENTRY(ALPHA,	0x00000010),	/* CPU_TYPE_ALPHA	*/

	/*
	 * Modern supported architectures. Note that a "CPU_TYPE_ABI64" flag
	 * is OR-ed into the architecture code for a 64-bit architecture
	 */
	_ENTRY(I386,	0x00000007),	/* CPU_TYPE_X86 / CPU_TYPE_I386	*/
	_ENTRY(X86_64,	0x01000007),	/* CPU_TYPE_X86_64		*/
	_ENTRY(PPC32,	0x00000012),	/* CPU_TYPE_POWERPC		*/
	_ENTRY(PPC64,	0x01000012),	/* CPU_TYPE_POWERPC64		*/
};
#undef _ENTRY

/*
 * Mach-O CPU subtypes, borrowed from Darwin
 */
typedef __u32 __bitwise macho_cpu_subtype_t;
#define _ENTRY(subtype, num) \
	MACHO_CPU_SUBTYPE_##subtype = ((__force macho_cpu_subtype_t)num)
enum {
	/* Generic CPU subtypes (unused?) */
	_ENTRY(MULTIPLE,		0xffffffff),
	_ENTRY(LITTLE_ENDIAN,		0x00000000),
	_ENTRY(BIG_ENDIAN,		0x00000001),

	/* VAX subtypes */
	_ENTRY(VAX_ALL,			0x00000000),
	_ENTRY(VAX_VAX780,		0x00000001),
	_ENTRY(VAX_VAX785,		0x00000002),
	_ENTRY(VAX_VAX750,		0x00000003),
	_ENTRY(VAX_VAX730,		0x00000004),
	_ENTRY(VAX_UVAXI,		0x00000005),
	_ENTRY(VAX_UVAXII,		0x00000006),
	_ENTRY(VAX_VAX8200,		0x00000007),
	_ENTRY(VAX_VAX8500,		0x00000008),
	_ENTRY(VAX_VAX8600,		0x00000009),
	_ENTRY(VAX_VAX8650,		0x0000000a),
	_ENTRY(VAX_VAX8800,		0x0000000b),
	_ENTRY(VAX_UVAXIII,		0x0000000c),

	/* Motorola 680x0 subtypes */
	_ENTRY(M68K_MC680X0,		0x00000001),
	_ENTRY(M68K_MC68040,		0x00000002),
	_ENTRY(M68K_MC68030,		0x00000003),

	/* Intel/AMD x86 subtypes */
	_ENTRY(I386_ALL,		0x00000003),
	_ENTRY(I386_386,		0x00000003),
	_ENTRY(I386_486,		0x00000004),
	_ENTRY(I386_486SX,		0x00000084),
	_ENTRY(I386_586,		0x00000005),
	_ENTRY(I386_PENTIUM,		0x00000005),
	_ENTRY(I386_PPRO,		0x00000016),
	_ENTRY(I386_PENTIUM2_M3,	0x00000036),
	_ENTRY(I386_PENTIUM2_M5,	0x00000056),
	_ENTRY(I386_CELERON,		0x00000067),
	_ENTRY(I386_CELERON_M,		0x00000077),
	_ENTRY(I386_PENTIUM3,		0x00000008),
	_ENTRY(I386_PENTIUM3_M,		0x00000018),
	_ENTRY(I386_PENTIUM3_XEON,	0x00000028),
	_ENTRY(I386_PENTIUM_M,		0x00000009),
	_ENTRY(I386_PENTIUM4,		0x0000000a),
	_ENTRY(I386_PENTIUM4_M,		0x0000001a),
	_ENTRY(I386_ITANIUM,		0x0000000b),
	_ENTRY(I386_ITANIUM2,		0x0000001b),
	_ENTRY(I386_XEON,		0x0000000c),
	_ENTRY(I386_XEON_MP,		0x0000001c),

	/* AMD 64-bit subtypes */
	_ENTRY(X86_64_ALL,		0x00000003),

	/* MIPS subtypes */
	_ENTRY(MIPS_ALL,		0x00000000),
	_ENTRY(MIPS_R2300,		0x00000001),
	_ENTRY(MIPS_R2600,		0x00000002),
	_ENTRY(MIPS_R2800,		0x00000003),
	_ENTRY(MIPS_R2000A,		0x00000004),
	_ENTRY(MIPS_R2000,		0x00000005),
	_ENTRY(MIPS_R3000A,		0x00000006),
	_ENTRY(MIPS_R3000,		0x00000007),

	/* Motorola 98xxx subtypes */
	_ENTRY(M98K_ALL,		0x00000000),
	_ENTRY(M98K_MC98601,		0x00000001),

	/* HPPA subtypes */
	_ENTRY(PARISC_ALL,		0x00000000),
	_ENTRY(PARISC_7100LC,		0x00000001),

	/* Motorola 88xxx subtypes */
	_ENTRY(M88K_ALL,		0x00000000),
	_ENTRY(M88K_MC88100,		0x00000001),
	_ENTRY(M88K_MC88110,		0x00000002),

	/* Sparc subtypes */
	_ENTRY(SPARC_ALL,		0x00000000),

	/* I860?? subtypes */
	_ENTRY(I860_ALL,		0x00000000),
	_ENTRY(I860_860,		0x00000001),

	/* Motorola/Freescale/IBM PowerPC subtypes */
	_ENTRY(PPC32_ALL,		0x00000000),
	_ENTRY(PPC32_601,		0x00000001),
	_ENTRY(PPC32_602,		0x00000002),
	_ENTRY(PPC32_603,		0x00000003),
	_ENTRY(PPC32_603E,		0x00000004),
	_ENTRY(PPC32_603EV,		0x00000005),
	_ENTRY(PPC32_604,		0x00000006),
	_ENTRY(PPC32_604E,		0x00000007),
	_ENTRY(PPC32_620,		0x00000008),
	_ENTRY(PPC32_750,		0x00000009),
	_ENTRY(PPC32_7400,		0x0000000a),
	_ENTRY(PPC32_7450,		0x0000000b),
	_ENTRY(PPC32_970,		0x00000064),

	/* Motorola/Freescale/IBM PowerPC64 subtypes */
	_ENTRY(PPC64_ALL,		0x00000000),
	_ENTRY(PPC64_970,		0x00000064),
};
#undef _ENTRY

/*
 * A CPU subtype mapping table with human-readable strings
 */
struct macho_cpu_subentry {
	const char *		name;
	macho_cpu_type_t	type;
	macho_cpu_subtype_t	subtype;
	unsigned int		preference;
};

#define _ENTRY(TYPE, SUBTYPE, NAME, PREFERENCE) {			\
		.name = NAME,						\
		.type = MACHO_CPU_TYPE_ ## TYPE,			\
		.subtype = MACHO_CPU_SUBTYPE_ ## TYPE ## _ ## SUBTYPE,	\
		.preference = (PREFERENCE)				\
	}

#define _PRF(pref) 0

static const struct macho_cpu_subentry macho_cpu_vax_subtypes[] = {
	_ENTRY(VAX,	ALL,		"all VAX",			 _PRF(1)),
	_ENTRY(VAX,	VAX780,		"VAX-780",			 _PRF(2)),
	_ENTRY(VAX,	VAX785,		"VAX-785",			 _PRF(3)),
	_ENTRY(VAX,	VAX750,		"VAX-750",			 _PRF(4)),
	_ENTRY(VAX,	VAX730,		"VAX-730",			 _PRF(5)),
	_ENTRY(VAX,	UVAXI,		"UVAX-I",			 _PRF(6)),
	_ENTRY(VAX,	UVAXII,		"UVAX-II",			 _PRF(7)),
	_ENTRY(VAX,	VAX8200,	"VAX-8200",			 _PRF(8)),
	_ENTRY(VAX,	VAX8500,	"VAX-8500",			 _PRF(9)),
	_ENTRY(VAX,	VAX8600,	"VAX-8600",			_PRF(10)),
	_ENTRY(VAX,	VAX8650,	"VAX-8650",			_PRF(11)),
	_ENTRY(VAX,	VAX8800,	"VAX-8800",			_PRF(12)),
	_ENTRY(VAX,	UVAXIII,	"UVAX-III",			_PRF(13)),
	{ .name = NULL },
};
static const struct macho_cpu_subentry macho_cpu_m68k_subtypes[] = {
	_ENTRY(M68K,	MC680X0,	"all Motorola 68xxx",		 _PRF(1)),
	_ENTRY(M68K,	MC68040,	"Motorola 68040",		 _PRF(2)),
	_ENTRY(M68K,	MC68030,	"Motorola 68030",		 _PRF(3)),
	{ .name = NULL },
};
#undef _PRF
#ifdef CONFIG_X86
#define _PRF(pref) pref
#else
#define _PRF(pref) 0
#endif
static const struct macho_cpu_subentry macho_cpu_i386_subtypes[] = {
	_ENTRY(I386,	ALL,		"all Intel/AMD",		_PRF(1)),
	_ENTRY(I386,	386,		"Intel 386",			_PRF(2)),
	_ENTRY(I386,	486,		"Intel 486",			_PRF(3)),
	_ENTRY(I386,	486SX,		"Intel 486SX",			_PRF(4)),
	_ENTRY(I386,	586,		"Intel 586",			_PRF(5)),
	_ENTRY(I386,	PENTIUM,	"Intel Pentium",		_PRF(6)),
	_ENTRY(I386,	PPRO,		"Intel Pentium Pro",		 _PRF(7)),
	_ENTRY(I386,	PENTIUM2_M3,	"Intel Pentium II M3",		 _PRF(8)),
	_ENTRY(I386,	PENTIUM2_M5,	"Intel Pentium II M5",		 _PRF(9)),
	_ENTRY(I386,	CELERON,	"Intel Celeron",		_PRF(10)),
	_ENTRY(I386,	CELERON_M,	"Intel Celeron/M",		_PRF(11)),
	_ENTRY(I386,	PENTIUM3,	"Intel Pentium III",		_PRF(12)),
	_ENTRY(I386,	PENTIUM3_M,	"Intel Pentium III M",		_PRF(13)),
	_ENTRY(I386,	PENTIUM3_XEON,	"Intel Pentium III Xeon",	_PRF(14)),
	_ENTRY(I386,	PENTIUM_M,	"Intel Pentium/M",		_PRF(15)),
	_ENTRY(I386,	PENTIUM4,	"Intel Pentium IV",		_PRF(16)),
	_ENTRY(I386,	PENTIUM4_M,	"Intel Pentium IV/M",		_PRF(17)),
	_ENTRY(I386,	ITANIUM,	"Intel Itanium",		_PRF(18)),
	_ENTRY(I386,	ITANIUM2,	"Intel Itanium 2",		_PRF(19)),
	_ENTRY(I386,	XEON,		"Intel Xeon",			_PRF(20)),
	_ENTRY(I386,	XEON_MP,	"Intel Xeon SMP",		_PRF(21)),
	{ .name = NULL },
};
#undef _PRF
#ifdef CONFIG_X86_64
#define _PRF(pref) pref
#else
#define _PRF(pref) 0
#endif
static const struct macho_cpu_subentry macho_cpu_x86_64_subtypes[] = {
	_ENTRY(X86_64,	ALL,		"all 64-bit AMD",		 _PRF(22)),
	{ .name = NULL },
};
#undef _PRF
#ifdef CONFIG_MIPS
#define _PRF(pref) pref
#else
#define _PRF(pref) 0
#endif
static const struct macho_cpu_subentry macho_cpu_mips_subtypes[] = {
	_ENTRY(MIPS,	ALL,		"all MIPS",			 _PRF(1)),
	_ENTRY(MIPS,	R2300,		"MIPS r2300",			 _PRF(2)),
	_ENTRY(MIPS,	R2600,		"MIPS r2600",			 _PRF(3)),
	_ENTRY(MIPS,	R2800,		"MIPS r2800",			 _PRF(4)),
	_ENTRY(MIPS,	R2000A,		"MIPS r2000a",			 _PRF(5)),
	_ENTRY(MIPS,	R2000,		"MIPS r2000",			 _PRF(6)),
	_ENTRY(MIPS,	R3000A,		"MIPS r3000a",			 _PRF(7)),
	_ENTRY(MIPS,	R3000,		"MIPS r3000",			 _PRF(8)),
	{ .name = NULL },
};
static const struct macho_cpu_subentry macho_cpu_m98k_subtypes[] = {
	_ENTRY(M98K,	ALL,		"all Motorola 98xxx",		 _PRF(1)),
	_ENTRY(M98K,	MC98601,	"Motorola 98601",		 _PRF(2)),
	{ .name = NULL },
};
static const struct macho_cpu_subentry macho_cpu_parisc_subtypes[] = {
	_ENTRY(PARISC,	ALL,		"all HPPA/PaRISC",		 _PRF(1)),
	_ENTRY(PARISC,	7100LC,		"HPPA 7100LC",			 _PRF(2)),
	{ .name = NULL },
};
static const struct macho_cpu_subentry macho_cpu_m88k_subtypes[] = {
	_ENTRY(M88K,	ALL,		"All Motorola 88xxx",		 _PRF(1)),
	_ENTRY(M88K,	MC88100,	"Motorola 88100",		 _PRF(2)),
	_ENTRY(M88K,	MC88110,	"Motorola 88110",		 _PRF(3)),
	{ .name = NULL },
};
#undef _PRF
#ifdef CONFIG_SPARC
#define _PRF(pref) pref
#else
#define _PRF(pref) 0
#endif
static const struct macho_cpu_subentry macho_cpu_sparc_subtypes[] = {
	_ENTRY(SPARC,	ALL,		"all Sparc",			 _PRF(1)),
	{ .name = NULL },
};
static const struct macho_cpu_subentry macho_cpu_i860_subtypes[] = {
	_ENTRY(I860,	ALL,		"all i860",			 _PRF(1)),
	_ENTRY(I860,	860,		"i860",				 _PRF(2)),
	{ .name = NULL },
};
#undef _PRF
#ifdef CONFIG_PPC
#define _PRF(pref) pref
#else
#define _PRF(pref) 0
#endif
static const struct macho_cpu_subentry macho_cpu_ppc32_subtypes[] = {
	_ENTRY(PPC32,	ALL,		"all PowerPC",			 _PRF(1)),
	_ENTRY(PPC32,	601,		"PowerPC 601",			 _PRF(2)),
	_ENTRY(PPC32,	602,		"PowerPC 602",			 _PRF(3)),
	_ENTRY(PPC32,	603,		"PowerPC 603",			 _PRF(4)),
	_ENTRY(PPC32,	603E,		"PowerPC 603e",			 _PRF(5)),
	_ENTRY(PPC32,	603EV,		"PowerPC 603ev",		 _PRF(6)),
	_ENTRY(PPC32,	604,		"PowerPC 604",			 _PRF(7)),
	_ENTRY(PPC32,	604E,		"PowerPC 604e",			 _PRF(8)),
	_ENTRY(PPC32,	620,		"PowerPC 620",			 _PRF(9)),
	_ENTRY(PPC32,	750,		"PowerPC 750",			_PRF(10)),
	_ENTRY(PPC32,	7400,		"PowerPC 7400",			_PRF(11)),
	_ENTRY(PPC32,	7450,		"PowerPC 7450",			_PRF(12)),
	_ENTRY(PPC32,	970,		"PowerPC 970",			_PRF(13)),
	{ .name = NULL },
};
#undef _PRF
#ifdef CONFIG_PPC64
#define _PRF(pref) pref
#else
#define _PRF(pref) 0
#endif
static const struct macho_cpu_subentry macho_cpu_ppc64_subtypes[] = {
	_ENTRY(PPC64,	ALL,		"all PowerPC64",		_PRF(14)),
	_ENTRY(PPC64,	970,		"PowerPC 970",			_PRF(15)),
	{ .name = NULL },
};
#undef _PRF
#undef _ENTRY

/*
 * A CPU type mapping table with human-readable strings
 */
struct macho_cpu_entry {
	const char *name;
	macho_cpu_type_t type;
	const struct macho_cpu_subentry *subtypes;
};
static const struct macho_cpu_entry macho_cpu_types[] = {
#define _ENTRY(TYPE, SUBTYPES, NAME) {				\
		.name = NAME,					\
		.type = MACHO_CPU_TYPE_ ## TYPE,		\
		.subtypes = SUBTYPES				\
	}
	_ENTRY(PPC32,	macho_cpu_ppc32_subtypes,	"PowerPC"	),
	_ENTRY(PPC64,	macho_cpu_ppc64_subtypes,	"PowerPC64"	),
	_ENTRY(I386,	macho_cpu_i386_subtypes,	"Intel/AMD x86"	),
	_ENTRY(X86_64,	macho_cpu_x86_64_subtypes,	"AMD 64-bit x86"),
	_ENTRY(VAX,	macho_cpu_vax_subtypes,		"VAX"		),
	_ENTRY(M68K,	macho_cpu_m68k_subtypes,	"Motorola 68xxx"),
	_ENTRY(MIPS,	macho_cpu_mips_subtypes,	"MIPS"		),
	_ENTRY(M98K,	macho_cpu_m98k_subtypes,	"Motorola 98xxx"),
	_ENTRY(PARISC,	macho_cpu_parisc_subtypes,	"HPPA/PaRISC"	),
	_ENTRY(ARM,	NULL,				"ARM"		),
	_ENTRY(M88K,	macho_cpu_m88k_subtypes,	"Motorola 88xxx"),
	_ENTRY(SPARC,	macho_cpu_sparc_subtypes,	"Sparc"		),
	_ENTRY(I860,	macho_cpu_i860_subtypes,	"i860"		),
	_ENTRY(ALPHA,	NULL,				"Alpha"		),
	_ENTRY(ANY,	NULL,				"unknown"	),
	{ .name = NULL },
#undef _ENTRY
};

static unsigned int macho_check_cpu(macho_cpu_type_t type,
					macho_cpu_subtype_t subtype)
{
	const struct macho_cpu_subentry *entry = NULL;
	unsigned long i;

	/* Iterate over all the CPU types */
	for (i = 0; macho_cpu_types[i].name; i++)
		if (type == macho_cpu_types[i].type)
			break;

	/* Invalid CPU if we didn't find a match */
	if (!macho_cpu_types[i].name) {
		macho_dbg("Unknown CPU type (%u)\n", type);
		return 0;
	}

	entry = macho_cpu_types[i].subtypes;

	/* Iterate over all the CPU subtypes (if any) */
	for (; entry && entry->name; entry++)
		if (type == entry->type && subtype == entry->subtype)
			break;

	/* Invalid CPU if we didn't find a match */
	if (!entry) {
		macho_dbg("Unknown %s subtype (%u)\n",
				macho_cpu_types[i].name, subtype);
		return 0;
	}

	macho_dbg("Found binary image for %s\n", entry->name);

	/* Return the preference level for this code */
	return entry->preference;
}

#endif /* not _MACHO_CPUS_H */
