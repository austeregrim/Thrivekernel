/*
 * seandroid_lime.c
 *
 * SEAndroid LIME:
 * Security Enhanced Android
 *   Light-weight Integrity measurement and Mandatory access control subsystem
 *   for Embedded devices
 *
 * Jun Kanai <jun4.kanai@toshiba.co.jp>
 * Ryuichi Koike <ryuichi.koike@toshiba.co.jp> 
 *
 * based on root_plug.c
 * Copyright (C) 2002 Greg Kroah-Hartman <greg@kroah.com>
 *
 * _xx_is_valid(), _xx_encode(), _xx_realpath_from_path()
 * is ported from security/tomoyo/realpath.c in linux-2.6.32 
 *
 * calc_hmac() is ported from drivers/staging/p9auth/p9auth.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
*/

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#include <linux/ptrace.h>
#include <linux/magic.h>

#define CONFIG_SECURITY_SEALIME_HASH_ALGORITHM "sha1"
#define TOSLSM_DIGEST_SIZE 20

//#define HOOKNAME_PTRACE_ACCESS_CHECK	/* 2.6.32 */
//#define SEALIME_UNLOADABLE

struct security_operations *lkm_secops = NULL;

static inline bool _xx_is_valid(const unsigned char c)
{
	return c > ' ' && c < 127;
}

static int _xx_encode(char *buffer, int buflen, const char *str)
{
	while (1) {
		const unsigned char c = *(unsigned char *)str++;

		if (_xx_is_valid(c)) {
			if (--buflen <= 0)
				break;
			*buffer++ = (char)c;
			if (c != '\\')
				continue;
			if (--buflen <= 0)
				break;
			*buffer++ = (char)c;
			continue;
		}
		if (!c) {
			if (--buflen <= 0)
				break;
			*buffer = '\0';
			return 0;
		}
		buflen -= 4;
		if (buflen <= 0)
			break;
		*buffer++ = '\\';
		*buffer++ = (c >> 6) + '0';
		*buffer++ = ((c >> 3) & 7) + '0';
		*buffer++ = (c & 7) + '0';
	}
	return -ENOMEM;
}

#ifdef CONFIG_SECURITY_SEALIME_NATIVE_HONEYCOMB_SUPPORT
int _xx_realpath_from_path(struct path *path, char *newname,
                           int newname_len)
{
	int error = -ENOMEM;
	struct dentry *dentry = path->dentry;
	char *sp;

	if (!dentry || !path->mnt || !newname || newname_len <= 2048)
		return -EINVAL;
	if (dentry->d_op && dentry->d_op->d_dname) {
		/* For "socket:[\$]" and "pipe:[\$]". */
		static const int offset = 1536;
		sp = dentry->d_op->d_dname(dentry, newname + offset,
		                           newname_len - offset);
	} else {
		struct path ns_root = {.mnt = NULL, .dentry = NULL};

		spin_lock(&dcache_lock);
		/* go to whatever namespace root we are under */
		sp = __d_path(path, &ns_root, newname, newname_len);
		spin_unlock(&dcache_lock);
		/* Prepend "/proc" prefix if using internal proc vfs mount. */
		if (!IS_ERR(sp) && (path->mnt->mnt_flags & MNT_INTERNAL) &&
		    (path->mnt->mnt_sb->s_magic == PROC_SUPER_MAGIC)) {
			sp -= 5;
			if (sp >= newname)
				memcpy(sp, "/proc", 5);
			else
			
	sp = ERR_PTR(-ENOMEM);
		}
	}
	if (IS_ERR(sp))
		error = PTR_ERR(sp);
	else
		error = _xx_encode(newname, sp - newname, sp);
	/* Append trailing '/' if dentry is a directory. */
	if (!error && dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode)
	    && *newname) {
		sp = newname + strlen(newname);
		if (*(sp - 1) != '/') {
			if (sp < newname + newname_len - 4) {
				*sp++ = '/';
				*sp = '\0';
			} else {
				error = -ENOMEM;
			}
		}
	}
	return error;
}
#else
static int _xx_realpath_from_path(struct path *path, char *newname,
				  int newname_len)
{
	struct dentry *dentry = path->dentry;
	int error = -ENOMEM;
	char *sp;

	if (!dentry || !path->mnt || !newname || newname_len <= 2048)
		return -EINVAL;
	if (dentry->d_op && dentry->d_op->d_dname) {
		/* For "socket:[\$]" and "pipe:[\$]". */
		static const int offset = 1536;
		sp = dentry->d_op->d_dname(dentry, newname + offset,
					   newname_len - offset);
	} else {
		/* Taken from d_namespace_path(). */
		struct path ns_root = { };
		struct path root;
		struct path tmp;

		read_lock(&current->fs->lock);
		root = current->fs->root;
		path_get(&root);
		read_unlock(&current->fs->lock);
		spin_lock(&vfsmount_lock);
		if (root.mnt && root.mnt->mnt_ns)
			ns_root.mnt = mntget(root.mnt->mnt_ns->root);
		if (ns_root.mnt)
			ns_root.dentry = dget(ns_root.mnt->mnt_root);
		spin_unlock(&vfsmount_lock);
		spin_lock(&dcache_lock);
		tmp = ns_root;
		sp = __d_path(path, &tmp, newname, newname_len);
		spin_unlock(&dcache_lock);
		path_put(&root);
		path_put(&ns_root);
	}
	if (IS_ERR(sp)) {
		error = PTR_ERR(sp);
	} else {
		error = _xx_encode(newname, sp - newname, sp);
	}
#if 1
	/* Append trailing '/' if dentry is a directory. */
	if (!error && dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode)
	    && *newname) {
		sp = newname + strlen(newname);
		if (*(sp - 1) != '/') {
			if (sp < newname + newname_len - 4) {
				*sp++ = '/';
				*sp = '\0';
			} else {
				error = -ENOMEM;
			}
		}
	}
#endif
	return error;
}
#endif /* 2.6.36 or later support */
EXPORT_SYMBOL(_xx_realpath_from_path);

static char *calc_hmac(char *plain_text, unsigned int plain_text_size,
		      char *key, unsigned int key_size)
{
	struct scatterlist sg;
	char *result;
	struct crypto_hash *tfm;
	struct hash_desc desc;
	int ret;

	tfm = crypto_alloc_hash("hmac(sha1)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR
		       "failed to load transform for hmac(sha1): %ld\n",
		       PTR_ERR(tfm));
		return NULL;
	}

	desc.tfm = tfm;
	desc.flags = 0;

	result = kzalloc(TOSLSM_DIGEST_SIZE, GFP_KERNEL);
	if (!result) {
		printk(KERN_ERR "out of memory!\n");
		goto out;
	}

	sg_set_buf(&sg, plain_text, plain_text_size);

	ret = crypto_hash_setkey(tfm, key, key_size);
	if (ret) {
		printk(KERN_ERR "setkey() failed ret=%d\n", ret);
		kfree(result);
		result = NULL;
		goto out;
	}

	ret = crypto_hash_digest(&desc, &sg, plain_text_size, result);
	if (ret) {
		printk(KERN_ERR "digest() failed ret=%d\n", ret);
		kfree(result);
		result = NULL;
		goto out;
	}

out:
	crypto_free_hash(tfm);
	return result;
}
EXPORT_SYMBOL(calc_hmac);

static int sealime_ptrace_access_check(struct task_struct *child,
				       unsigned int mode)
{
#ifdef CONFIG_SECURITY_SEALIME_HOOKNAME_PTRACE_ACCESS_CHECK
	if (lkm_secops) return lkm_secops->ptrace_access_check(child, mode);
#else
	if (lkm_secops) return lkm_secops->ptrace_may_access(child, mode);
#endif
	return 0;
}

static int sealime_ptrace_traceme(struct task_struct *parent)
{
	if (lkm_secops) return lkm_secops->ptrace_traceme(parent);
	return 0;
}

static int sealime_sb_mount(char *dev_name, struct path *path,
			    char *type, unsigned long flags, void *data)
{
	if (lkm_secops) return lkm_secops->sb_mount(dev_name, path, type, flags, data);
	return 0;
}

static int sealime_sb_umount(struct vfsmount *mnt, int flags)
{
	return 0;
}

static int sealime_sb_pivotroot(struct path *old_path, struct path *new_path)
{
	if (lkm_secops) return lkm_secops->sb_pivotroot(old_path, new_path);
	return 0;
}

static int sealime_path_chroot(struct path *path)
{
	if (lkm_secops) return lkm_secops->path_chroot(path);
	return 0;
}

static int sealime_file_permission(struct file *file, int mask)
{
	if (lkm_secops) return lkm_secops->file_permission(file, mask);
	return 0;
}

static int sealime_bprm_secureexec(struct linux_binprm *bprm)
{
	if (lkm_secops) return lkm_secops->bprm_secureexec(bprm);
	return 0;
}

static int sealime_path_mknod(struct path *path, struct dentry *dentry,
			      int mode, unsigned int dev)
{
	if (lkm_secops) return lkm_secops->path_mknod(path, dentry, mode, dev);
	return 0;
}

static int sealime_path_unlink(struct path *path, struct dentry *dentry)
{
	if (lkm_secops) return lkm_secops->path_unlink(path, dentry);
	return 0;
}

static int sealime_path_rename(struct path *old_dir, struct dentry *old_dentry,
			       struct path *new_dir, struct dentry *new_dentry)
{
	if (lkm_secops) return lkm_secops->path_rename(old_dir, old_dentry, new_dir, new_dentry);
	return 0;
}

static int sealime_task_create(unsigned long clone_flags)
{
	if (lkm_secops) return lkm_secops->task_create(clone_flags);
	return 0;
}

static int sealime_init_module(const char *image, unsigned long len)
{
	if (lkm_secops) return lkm_secops->init_module(image, len);
	return 0;
}

static int sealime_task_prctl(int option, unsigned long arg2,
			      unsigned long arg3, unsigned long arg4,
			      unsigned long arg5)
{

	if (lkm_secops) return lkm_secops->task_prctl(option, arg2, arg3, arg4, arg5);
	return cap_task_prctl(option, arg2, arg3, arg3, arg5);
}

static int sealime_dentry_open(struct file *file, const struct cred *cred)
{
	if (lkm_secops) return lkm_secops->dentry_open(file, cred);
	return 0;
}

static struct security_operations sealime_security_ops = {
#ifndef CONFIG_SECURITY_SEALIME_HOOKNAME_PTRACE_ACCESS_CHECK
	.ptrace_may_access = sealime_ptrace_access_check,
#else
	.ptrace_access_check = sealime_ptrace_access_check,
#endif
	.ptrace_traceme = sealime_ptrace_traceme,
	.sb_mount = sealime_sb_mount,
	.sb_umount = sealime_sb_umount,
	.sb_pivotroot = sealime_sb_pivotroot,
	.file_permission = sealime_file_permission,
	.bprm_secureexec = sealime_bprm_secureexec,
	.path_mknod = sealime_path_mknod,
	.path_unlink = sealime_path_unlink,
	.path_rename = sealime_path_rename,
	.task_create = sealime_task_create,
	.path_chroot = sealime_path_chroot,
	.task_prctl = sealime_task_prctl,
	.dentry_open = sealime_dentry_open,
	.init_module = sealime_init_module,
};

static int __init sealime_init(void)
{
	if (register_security(&sealime_security_ops)) {
		printk(KERN_INFO "[SEAndroid_Lime] Failure registering LSM\n");
		return -EINVAL;
	}
	printk(KERN_INFO "[SEAndroid_Lime] LSM module initialized\n");

	return 0;
}

static int register_sealime(struct security_operations *sec_ops) {
#ifndef SEALIME_UNLOADABLE
	if (lkm_secops == NULL) {
#endif
		lkm_secops = sec_ops;
		printk(KERN_INFO "[SEAndroid_LIME] allow: Sealime LKM is registered!\n");
#ifndef SEALIME_UNLOADABLE
	} else {
		printk(KERN_INFO "[SEAndroid_LIME] reject: Sealime LKM is already registered!\n");
	}
#endif
	return 0;
}
EXPORT_SYMBOL(register_sealime);
EXPORT_SYMBOL(__ptrace_unlink);
EXPORT_SYMBOL(cap_task_prctl);

security_initcall(sealime_init);

