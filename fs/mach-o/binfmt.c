/*
 * linux/fs/mach-o/binfmt.c
 *
 * These are the functions used to load Mach-O format executables as used
 * on Mac OS X and Darwin machines.
 *
 * Copyright (C) 2006, Kyle Moffett <mrmacman_g4@mac.com>
 * Copyright (C) 2008, Frederic Point <fredpoint@gmail.com>
 *
 * Designed from public documentation and Darwin sources as well as the Linux
 * ELF loader by Eric Youngdale (ericy@cais.com).
 */

#include <linux/module.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/err.h>
#include <linux/personality.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/pagemap.h>

#include "debug.h"
#include "cpus.h"
#include "headers.h"
#include "files.h"
#include "loadcmds.h"

#if 0
#define MACHO_INTERPRETER
#endif

MODULE_LICENSE("GPL");

/* Function prototypes */
static unsigned long get_arch_offset(struct linux_binprm *bprm);
static int load_macho_binary(struct linux_binprm *bprm, struct pt_regs *regs);

/* Mach-O binary format */
static struct linux_binfmt binfmt_macho = {
	.module		= THIS_MODULE,
	.load_binary	= load_macho_binary,
	.load_shlib	= NULL,
	.core_dump	= NULL,
	.min_coredump	= PAGE_SIZE,
};

/* Module init and exit */
static int __init init_binfmt_macho(void)
{
	macho_dbg("INIT MACH-O:\n");
	return register_binfmt(&binfmt_macho);
}
core_initcall(init_binfmt_macho);

static void __exit exit_binfmt_macho(void)
{
	unregister_binfmt(&binfmt_macho);
}
module_exit(exit_binfmt_macho);

void show_vma (void)
{
	struct vm_area_struct *vma;
	vma = current->mm->mmap;
	macho_dbg("Mapping :\n");
	while (vma) {
		macho_dbg("      %08lx-%08lx %c%c%c%c %08lx\n",
			vma->vm_start,
			vma->vm_end,
			vma->vm_flags & VM_READ ? 'r' : '-',
			vma->vm_flags & VM_WRITE ? 'w' : '-',
			vma->vm_flags & VM_EXEC ? 'x' : '-',
			vma->vm_flags & VM_MAYSHARE ? 's' : 'p',
			vma->vm_pgoff << PAGE_SHIFT);
		vma = vma->vm_next;
	}
}


static unsigned long macho_segment_map(struct file *filep,
				       struct macho_loadcmd_segment32 *seg,
				       unsigned long arch_offset)
{
	unsigned long map_addr = 0; /* FIXME = 0 */
	struct macho_loadcmd_section32 *sect;
	int perm = 0;
	int flags = 0;
	int i;
	unsigned int vm_addr;
	unsigned int vm_size;

	/* Get specials sections addresses */
	macho_dbg("    => Segment %s:\n", seg->name);
	macho_dbg("         vm_addr    %d\n", seg->vm_addr);
	macho_dbg("         vm_size    %d\n", seg->vm_size);
	macho_dbg("         file_off   %d\n", seg->file_off);
	macho_dbg("         file_off + arch_offset   %d\n", (int) (seg->file_off
				+ arch_offset));
	macho_dbg("         file_size  %d\n", seg->file_size);
	macho_dbg("         prot_max   %d\n", seg->prot_max);
	macho_dbg("         prot_init  %d\n", seg->prot_init);
	macho_dbg("         vm_size    %d\n", seg->vm_size);
	macho_dbg("         sect_count %d\n", seg->sect_count);
	macho_dbg("         flags      %d\n", seg->flags);
	
	vm_addr = seg->vm_addr;
	vm_size = seg->vm_size;

	if (seg->prot_init & MACHO_PERM_R)
		perm = PROT_READ;
	if (seg->prot_init & MACHO_PERM_W)
		perm |= PROT_WRITE;
	if (seg->prot_init & MACHO_PERM_X)
		perm |= PROT_EXEC;

	flags = MAP_PRIVATE | MAP_DENYWRITE | MAP_FIXED;
	/* FIXME: type set to 0 */
	macho_dbg("           ALLOC:\n");
	macho_dbg("             addr: %016x\n", seg->vm_addr);
	macho_dbg("             size: %d\n", seg->vm_size);
	if (!strcmp(seg->name, "__PAGEZERO")) {
		macho_dbg("      PAGEZERO detected\n");
		filep = NULL;
		flags |= MAP_FIXED;
	}

	sect = (void *)seg + sizeof(*seg);
	for ( i = 0;  i < seg->sect_count;i++, sect++) {
		macho_dbg("      - Section %d: %s\n", i+1, sect->name);
		macho_dbg("           vm_addr   %d\n", sect->vm_addr);
		macho_dbg("           vm_size   %d\n", sect->vm_size);
		macho_dbg("           file_off  %d\n", sect->file_off);
		macho_dbg("           file_off + arch_offset   %d\n", 
					(int)(sect->file_off + arch_offset));
		macho_dbg("           align     %d\n", sect->align);
		macho_dbg("           rel_off   %d\n", sect->rel_off);
		macho_dbg("           rel_count %d\n", sect->rel_count);
		macho_dbg("           flags     %d\n", sect->flags);
		macho_dbg("           rsv1      %d\n", sect->rsv1);
		macho_dbg("           rsv2      %d\n", sect->rsv2);
		

		if (!strcmp(sect->seg_name, "__DATA") &&
				   !strcmp(sect->name, "__bss")) {
			macho_dbg("      BSS detected\n");
			
		}
		if (!strcmp(sect->seg_name, "__TEXT") && 
				   !strcmp(sect->name, "__text")) {
			macho_dbg("      Start code detected\n");
			flags |= MAP_EXECUTABLE;
			current->mm->start_code = sect->vm_addr;
			current->mm->end_code	= sect->vm_addr + sect->vm_size;
		}

	}

	down_write(&current->mm->mmap_sem);
	/* XXX FIXME XXX: type set to 0 */

	map_addr = do_mmap(filep, vm_addr, vm_size,
	perm, flags, seg->file_off + arch_offset);
	macho_dbg("           MAP AT 0x%08lx - 0x%08lx\n", map_addr,
				map_addr + vm_size);
	up_write(&current->mm->mmap_sem);

	return(map_addr);
}

/*
 * Read Mach-O file headers to find out where our architecture-specific
 * portion is.
 */
#define MAX_ARCH_COUNT (PAGE_SIZE/sizeof(struct macho_fat_arch))
static unsigned long get_arch_offset(struct linux_binprm *bprm)
{
	struct macho_fat_header *header;
	struct macho_fat_arch *archs;
	unsigned long arch_count, arch_data, i, offset = 0;
	long retval;
	unsigned int best_pref, best_arch;

	//macho_dbg("get_arch_offset: BEGIN\n");

	/* Without a FAT (multi-arch binary) header just assume no offset */
	header = (struct macho_fat_header *)bprm->buf;
	if (header->magic != MACHO_FAT_MAGIC)
		goto out;

	macho_dbg("Found a Mach-O FAT header!\n");

	/* Figure out how many archs to read (no more than a page worth) */
	arch_count = __be32_to_cpu(header->arch_count);
	if (arch_count > MAX_ARCH_COUNT) {
		macho_dbg("Too many archs (%lu) in Mach-O binary.  Only using"
				" %lu!\n", arch_count, MAX_ARCH_COUNT);
		arch_count = MAX_ARCH_COUNT;
	}

	/* Size of the architecture data (for kmalloc and read) */
	arch_data = arch_count * sizeof(struct macho_fat_arch);

	/* Allocate memory for the architecture list */
	archs = kmalloc(arch_data, GFP_KERNEL);
	if (!archs) {
		offset = (unsigned long)(-ENOMEM);
		goto out;
	}

	/* Read in the architecture list */
	retval = kernel_read(bprm->file, sizeof(struct macho_fat_header),
			(void *)archs, arch_data);
	if (retval != arch_data) {
		if (retval < 0) {
			macho_dbg("Error while reading Mach-O architecture"
					" list: %li\n", retval);
			offset = (unsigned long)retval;
		} else {
			macho_dbg("Truncated arch list (got %lub, wanted"
					" %lub)\n", retval, arch_data);
			offset = (unsigned long)(-ENOEXEC);
		}
		goto out;
	}

	/*
	 * Iterate over the architecture list looking for the most-preferred
	 * arch.  NOTE:  An architecture with a preference of 0 is not
	 * compatible with the current CPU.
	 */
	best_pref = 0;
	best_arch = 0;
	for (i = 0; i < arch_count; i++) {
		unsigned int pref = macho_check_cpu(
				__be32_to_cpu(archs[i].cpu_type),
				__be32_to_cpu(archs[i].cpu_subtype));
		if (best_pref < pref) {
			best_pref = pref;
			best_arch = i;
		}
	}

	/* If we didn't find any useable architectures then give up */
	if (best_pref == 0) {
		macho_dbg("No compatible binaries in Mach-O FAT binary\n");
		offset = (unsigned long)(-ENOEXEC);
		goto out;
	}

	/* Pick up the offset of the best available architecture */
	offset = __be32_to_cpu(archs[best_arch].offset);

	/*
	 * If the offset would be confused with an error value then
	 * it's too big (4GB program binary?!?!?) and we should just
	 * return ENOEXEC instead
	 */
	if (IS_ERR_VALUE(offset))
		offset = (unsigned long)(-ENOEXEC);

out:
	//kfree(archs);
	return offset;
}


/* Let's use some macros to make this stack manipulation a little clearer */
#ifdef CONFIG_STACK_GROWSUP
#define STACK_ADD(sp, items) ((int __user *)(sp) + (items))
#define STACK_ROUND(sp, items) \
	((15 + (unsigned long) ((sp) + (items))) &~ 15UL)
#define STACK_ALLOC(sp, len) ({ \
	elf_addr_t __user *old_sp = (int __user *)sp; sp += len; \
	old_sp; })
#else
#define STACK_ADD(sp, items) ((int __user *)(sp) - (items))
#define STACK_ROUND(sp, items) \
	(((unsigned long) (sp - items)) &~ 15UL)
#define STACK_ALLOC(sp, len) ({ sp -= len ; sp; })
#endif

/*
 * Load argv and env
 */
static int
setup_stack(struct linux_binprm *bprm)
{
	unsigned long p = bprm->p;
	int argc = bprm->argc;
	int envc = bprm->envc;
	int __user *argv;
	int __user *envp;
	int __user *sp;
	int items;
	//struct vm_area_struct *vma;

	macho_dbg("setup_stack\n");


	macho_dbg("exec_path: %s (%d)\n", bprm->interp, strlen(bprm->interp));
	sp = (int __user *)bprm->p;
	macho_dbg("sp: %016x\n", (unsigned int)sp);
	items = (argc + 1) + (envc + 1) + ( (strlen(bprm->interp))/4 + 2) + 1;
	macho_dbg("items: %d\n", (unsigned int)items);
	bprm->p = STACK_ROUND(sp, items);
	macho_dbg("sp: %016x\n", (unsigned int)bprm->p);
	
	/* Point sp at the lowest address on the stack */
#ifdef CONFIG_STACK_GROWSUP
	sp = (int __user *)bprm->p - items - ei_index;
	bprm->exec = (unsigned long)sp; /* XXX: PARISC HACK */
#else
	sp = (int __user *)bprm->p;
#endif
	macho_dbg("sp: %016x\n", (unsigned int)sp);


	/*
	 * Grow the stack manually; some architectures have a limit on how
	 * far ahead a user-space access may be in order to grow the stack.
	 */
//	vma = find_extend_vma(current->mm, bprm->p);
//	if (!vma)
//		return -EFAULT;

	/* Now, let's put argc (and argv, envp if appropriate) on the stack */
	if (__put_user(argc, sp++))
		return -EFAULT;
	argv = sp;
	envp = argv + argc + 1;

	macho_dbg("argv: %08x\n", (unsigned int)argv);
	macho_dbg("argc: %d\n", argc);
	macho_dbg("envc: %d\n", envc);
	macho_dbg("MAX_ARG_STRLEN: %lu\n", MAX_ARG_STRLEN);
	
	/* Populate argv and envp */
	p = current->mm->arg_end = current->mm->arg_start;
	macho_dbg("arg_start: %08x\n", (unsigned int)p);

	while (argc-- > 0) {
		size_t len;
		macho_dbg("argv[%d]: %016x\n", argc, (unsigned int)p);
		if (__put_user(p, argv++))
			return -EFAULT;
		len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		macho_dbg("len: %d\n",len);
		if (!len || len > MAX_ARG_STRLEN)
			return -EINVAL;
		p += len;
	}
	macho_dbg("------------------------\n");
	if (__put_user(0, argv))
		return -EFAULT;
	current->mm->arg_end = current->mm->env_start = p;
	while (envc-- > 0) {
		size_t len;
		macho_dbg("envv[%d]: %016x\n",envc,(unsigned int)p);
		if (__put_user(p, envp++))
			return -EFAULT;
		len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
			return -EINVAL;
		p += len;
	}
	if (__put_user(0, envp))
		return -EFAULT;
	current->mm->env_end = p;

	/*
	 * Put the exec_path pointer and the exec_path
	 */
	macho_dbg("---- envp: %016x\n",(unsigned int)envp);
	sp = (int __user *)envp + 1;
	macho_dbg("---- sp: %016x\n",(unsigned int)sp);
	macho_dbg("---- sp + 8: %016x\n",(unsigned int)(sp+8));
	if (__put_user(sp + 8, sp))
		return -EFAULT; 
	/* Put the elf_info on the stack in the right place.  */
//	if (copy_to_user(sp, elf_info, ei_index * sizeof(elf_addr_t)))
//		return -EFAULT;
	return 0;
}

/*
 * Load a Mach-O binary
 */
static int load_macho_binary(struct linux_binprm *bprm, struct pt_regs *regs)
{
	struct {
		union {
			/* The first 4 bytes of either header are the magic */
			__u32 magic;
			struct macho_mach32_header mach32;
			struct macho_mach64_header mach64;
		} header;
		union macho_loadcmd loadcmd;
	} *data = NULL;
#ifdef MACHO_INTERPRETER
	struct file *interpreter = NULL;
#endif
	unsigned long hdr_cmd_count, hdr_cmd_size;
	unsigned long cur_offset, loadcmd_size, i;
	unsigned long arch_offset;
	long retval;
	char * mach_interpreter = NULL;
	int err = -ENOEXEC;
	unsigned long stack_size;

	//macho_dbg("load_macho_binary: BEGIN\n");
	/* Make sure the file has appropriate ops */
	if (!bprm->file->f_op || !bprm->file->f_op->mmap)
		goto out;

	/*
	 * Read the Mach-O file headers to find the offset of our
	 * architecture-specific portion
	 */
	arch_offset = get_arch_offset(bprm);
	if (IS_ERR_VALUE(arch_offset)) {
		err = (long)arch_offset;
		goto out;
	}

	/* Allocate space for the file headers and a load command */
	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		err = -ENOMEM;
		goto out;
	}

	/* Read the header data and check the magic */
	retval = kernel_read(bprm->file, arch_offset,
			(void *)&data->header, sizeof(data->header));
	if (retval != sizeof(data->header)) {
		/*
		 * If we didn't see an arch table then it must not really be
		 * a Mach-O file so just return as not executable.
		 */
		if (!arch_offset)
			err = -ENOEXEC;

		/* If kernel_read() returned an error, handle it */
		else if (retval < 0) {
			macho_dbg("Error while reading Mach-O object"
					" header: %li\n", retval);
			err = retval;
		} else {
			macho_dbg("Truncated Mach-O object header: "
					"(got %lub, wanted %ub)\n", retval,
					sizeof(data->header));
			err = -ENOEXEC;
		}
		goto out;
	}

	/* Check for backwards-endian files */
	if (data->header.magic == MACHO_MACH32_CIGAM ||
			data->header.magic == MACHO_MACH64_CIGAM) {
		macho_dbg("Wrong endianness in Mach-O file\n");
		err = -ENOEXEC;
		goto out;
	}

	/*
	 * It's not a valid Mach-O file then return, but print an error
	 * message first if it was embedded in a Mach-O FAT wrapper.
	 */
	if (data->header.magic != MACHO_MACH32_MAGIC &&
			data->header.magic != MACHO_MACH64_MAGIC) {
		if (arch_offset)
			macho_dbg("Corrupt embedded Mach-O object!\n");
		err = -ENOEXEC;
		goto out;
	}

	/* CPU type (lines up between 32-bit and 64-bit Mach-O files) */
	if (!macho_check_cpu(data->header.mach32.cpu_type,
			data->header.mach32.cpu_subtype)) {
		/*
		 * The CPU didn't match, so either this is Mach-O file is for
		 * a different platform (arch_offset == 0) or the FAT Mach-O
		 * has been corrupted.
		 */
		if (arch_offset)
			macho_dbg("FAT Mach-O wrapper has mismatched CPU"
					" types:  Mach-O file corrupt?\n");
		else
			macho_dbg("Wrong architecture in Mach-O file\n");
		err = -ENOEXEC;
		goto out;
	}

	/* File type (also lines up between 32-bit and 64-bit) */
	if (!macho_check_file(data->header.mach32.filetype,
			data->header.mach32.flags)) {
		macho_dbg("Attempted to execute nonexecutable Mach-O file\n");
		err = -ENOEXEC;
		goto out;
	}

	/*
	 * Get some load-command info out of the header (NOTE: Lines up
	 * between 32-bit and 64-bit Mach-O files
	 */
	hdr_cmd_count = data->header.mach32.cmd_count;
	hdr_cmd_size  = data->header.mach32.cmd_size;

	/* 
	 * FIXME:  Limits the total space for load commands to 1MB, but this
	 * should be made configurable somehow for embedded systems with
	 * minimal available resources.  Is there an rlimit or some page
	 * accounting we can hook into?  I don't think this is that critical
	 * of an issue since for the most part we only store one load-command
	 * in kernel memory at a time, however some things like unixthread
	 * and thread load-commands need to be kept around until after we've
	 * loaded the dynamic linker.
	 */
	if (hdr_cmd_size > (1 << 20)) {
		macho_dbg("Mach-O file has more than 1MB worth of "
				"load-commands (%lu bytes)\n", hdr_cmd_size);
		err = -ENOMEM;
		goto out;
	}

	/* Move past the Mach-O header to find the first load_command */
	cur_offset = arch_offset +
		((data->header.magic == MACHO_MACH32_MAGIC)
			? sizeof(struct macho_mach32_header)
			: sizeof(struct macho_mach64_header));


	/*
	 * Just to avoid allocating gobs of kernel memory while we parse the
	 * load-command table, we're going to go past the point of no return
	 * nice and early, so we can just start mapping things into memory
	 */
	err = flush_old_exec(bprm);
	if (err)
		goto out;

	/* FIXME: This needs to actually switch to the darwin personality
	 * OSX syscall: /usr/include/sys/syscall.h
	 * Look here also: /usr/include/bsm/audit_kevents.h
	 */
	install_exec_creds(bprm);
	set_personality(PER_LINUX32);
	set_binfmt(&binfmt_macho);

	/* FIXME: Set up ugly stack/brk/etc for testing, need to fix later */
	current->mm->start_code = 0;
	current->mm->end_code = 0;
	current->mm->start_stack = 0;
	current->mm->start_brk = 0;
	current->mm->start_data = 0;
	current->mm->end_data = 0;
// 	current->mm->mmap	= NULL;
	current->mm->def_flags	= 0;

	/* Make sure to clear the fork-but-not-exec bit on this process */
	current->flags &= ~PF_FORKNOEXEC;

	/*
	 * FIXME: Figure out how to do MMAP, may need to be changed to be
	 * darwinish
	 */
	//current->mm->mmap_base = TASK_UNMAPPED_BASE;
	//current->mm->get_unmapped_area = arch_get_unmapped_area;
	//current->mm->unmap_area = arch_unmap_area;
	//current->mm->free_area_cache = current->mm->mmap_base;
	//current->mm->cached_hole_size = 0;

	/*
	 * Setup the args before populate the stack
	 */

	retval = setup_arg_pages(bprm, STACK_TOP, 1);
	if (retval < 0) {
		goto out_noreturn;
	}	 


	/* Iterate over reading the load commands */
	loadcmd_size = 0;
	for (i = 0; i < hdr_cmd_count; i++) {
		unsigned long size;

		/* Check that we have room for another load command */
		if (loadcmd_size + sizeof(data->loadcmd.hdr) > hdr_cmd_size) {
			macho_dbg("Mach-O header doesn't allocate enough "
					"space for load-commands %lu-%lu!\n",
					i, hdr_cmd_count-1);
			err = -ENOEXEC;
			goto out_noreturn;
		}

		/* First read the itty-bitty command num and size fields */
		retval = kernel_read(bprm->file, cur_offset,
				(void *)&data->loadcmd.hdr,
				sizeof(data->loadcmd.hdr));
		if (retval != sizeof(data->loadcmd.hdr)) {
			/* If kernel_read() returned an error, handle it */
			if (retval < 0) {
				macho_dbg("Error while reading Mach-O load"
					" command %lu: %li\n", i, retval);
				err = retval;
			} else {
				macho_dbg("Truncated Mach-O load command "
					"%lu: (got %lib, wanted %ub)\n", i,
					retval, sizeof(data->loadcmd.hdr));
				err = -ENOEXEC;
			}
			goto out_noreturn;
		}

		/* Check/display the load command number */
		macho_check_loadcmd(data->loadcmd.hdr.cmd);
		size = data->loadcmd.hdr.size;

		/* 
		 * Ensure the load-command size is a multiple of 4 bytes and
		 * large enough to contain the load-command header.
		 */
		if (size & 0x3 || size < sizeof(data->loadcmd.hdr)) {
			macho_dbg("Invalid size for load command %lu: %lu\n",
				i, (unsigned long)data->loadcmd.hdr.size);
			err = -ENOEXEC;
			goto out_noreturn;
		}

		/* Check that we have room for another load command */
		if (loadcmd_size + size > hdr_cmd_size) {
			macho_dbg("Mach-O header doesn't allocate enough "
					"space for load-commands %lu-%lu!\n",
					i, hdr_cmd_count-1);
			err = -ENOEXEC;
			goto out_noreturn;
		}

		/* Check that it isn't too big */
		if (size > sizeof(data->loadcmd)) {
			macho_dbg("Load command %lu is too big (%lu > %u): "
				"skipped!\n", i, size, sizeof(data->loadcmd));
			loadcmd_size += size;
			cur_offset   += size;
			continue;
		}

		/* Read in the rest of the load-command and move past it */
		retval = kernel_read(bprm->file, cur_offset,
				(void *)&data->loadcmd, size);
		if (retval != size) {
			/* If kernel_read() returned an error, handle it */
			if (retval < 0) {
				macho_dbg("Error while reading Mach-O load"
					" command %lu: %li\n", i, retval);
				err = retval;
			} else {
				macho_dbg("Truncated Mach-O load command "
					"%lu: (got %lib, wanted %lub)\n", i,
					retval, size);
				err = -ENOEXEC;
			}
			goto out_noreturn;
		}
		loadcmd_size += size;
		cur_offset   += size;

		switch (data->loadcmd.hdr.cmd) {
			case MACHO_LOADCMD_NUM_SEGMENT64:
				macho_dbg("    Load command: "
					"MACHO_LOADCMD_NUM_SEGMENT64\n");
				set_personality(PER_LINUX);
				break;
			case MACHO_LOADCMD_NUM_SEGMENT32:
				macho_dbg("    Load command: "
					"MACHO_LOADCMD_NUM_SEGMENT32\n");
				set_personality(PER_LINUX32);
				retval = macho_segment_map(bprm->file,
						&(data->loadcmd.segment32), arch_offset);
				if (retval == -EINVAL) {
					goto out_noreturn;
				}
				break;
			case MACHO_LOADCMD_NUM_THREAD_NOSTACK:
				macho_dbg("    Load command: "
				"MACHO_LOADCMD_NUM_THREAD_NOSTACK\n");
				break;
			case MACHO_LOADCMD_NUM_THREAD:
				macho_dbg("    Load command: "
					"MACHO_LOADCMD_NUM_THREAD\n");
				/* XXX FIXME XXX: static should be dynamic */ 

				stack_size = PAGE_SIZE;
				/* Setup envv and argv */
				setup_stack(bprm);
				if (retval = -EINVAL) {
					macho_dbg("Houston weve got a problem\n");
				}
				
				current->mm->start_stack = bprm->p;
				/* XXX FIXME XXX: Setup register */
#ifdef MACHO_PLAT_INIT
				MACHO_PLAT_INIT_32(regs);
#endif
				

				break;
			case MACHO_LOADCMD_NUM_REF_DYLD:
				macho_dbg("    Load command: "
					"MACHO_LOADCMD_NUM_REF_DYLD\n");
				/* Get the name of the dynamic linker for
				 * further use
				 */
				mach_interpreter = kmalloc(30,
						  GFP_KERNEL);
#ifdef MACHO_INTERPRETER
				if (!mach_interpreter)
					goto out_free_interp;
#endif
				mach_interpreter =
					(char *)(&(data->loadcmd.dyld.data[0]));
				mach_interpreter[data->loadcmd.hdr.size 
							- data->loadcmd.dyld.path.off] = '\0';
				macho_dbg("    Dynamic Linker found: %s"
						" at %d\n", mach_interpreter,
						data->loadcmd.dyld.path.off);
				break;
		}
		/* XXX FIXME XXX: Process the load-command => in progress :) */
	}

#ifdef MACHO_INTERPRETER
	/* XXX FIXME XXX: Load the interpreter */
	if (mach_interpreter) {
		macho_dbg("Loading dynamic Linker: %s\n", mach_interpreter);
		interpreter = open_exec(mach_interpreter);
		retval = PTR_ERR(interpreter);
		if (IS_ERR(interpreter))
			goto out_free_interp;
		macho_dbg("                       => OK\n");
	}
#endif



#ifdef CONFIG_X86
	set_thread_flag(TIF_IA32);
	set_thread_flag(TIF_BSD);
#endif
	macho_dbg("    Start thread !!!!!\n");
	macho_dbg("- start_code  0x%08lx\n", current->mm->start_code);
	macho_dbg("- end_code    0x%08lx\n", current->mm->end_code);
	macho_dbg("- start_data  0x%08lx\n", current->mm->start_data);
	macho_dbg("- end_data    0x%08lx\n", current->mm->end_data);
	macho_dbg("- start_brk   0x%08lx\n", current->mm->start_brk);
	macho_dbg("- brk         0x%08lx\n", current->mm->brk);
	macho_dbg("- start_stack 0x%08lx\n", current->mm->start_stack);
	macho_dbg("- stack_size  0x%08lx\n", stack_size);
	//macho_dbg("- TASK_SIZE:  0x%08lx\n", TASK_SIZE);

	show_vma();

	start_thread(regs, current->mm->start_code, current->mm->start_stack);
	retval = 0;
	return retval;


	err = -EINVAL;
	goto out_noreturn;
#ifdef MACHO_INTERPRETER
out_free_interp:
	kfree(mach_interpreter);
#endif
out_noreturn:
	send_sig(SIGKILL, current, 0);
out:
	kfree(data);
	return err;
}
