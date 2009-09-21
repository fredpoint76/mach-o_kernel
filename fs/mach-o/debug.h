#ifndef  _MACHO_DEBUG_H
# define _MACHO_DEBUG_H 1

# include <linux/kernel.h>	/* For printk()	*/

# define macho_dbg(x, args...) \
	printk(KERN_DEBUG "binfmt_mach-o: " x,##args)

#endif /* not _MACHO_DEBUG_H */
