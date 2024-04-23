#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xcd6bb128, "module_layout" },
	{ 0x22408f99, "param_ops_charp" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0xdd4253c7, "unregister_kretprobe" },
	{ 0x41b7e8e2, "register_kretprobe" },
	{ 0x791d537b, "__register_chrdev" },
	{ 0x85df9b6c, "strsep" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x9166fada, "strncpy" },
	{ 0x24be54ff, "kern_path" },
	{ 0x754d539c, "strlen" },
	{ 0x50b69ef6, "dentry_path_raw" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x37a0cba, "kfree" },
	{ 0x8bf3d5bd, "get_task_cred" },
	{ 0x2fd729f4, "filp_close" },
	{ 0x5d9e4a50, "kernel_read" },
	{ 0xc22521c7, "filp_open" },
	{ 0xa935440, "__mmap_lock_do_trace_released" },
	{ 0xe050e3ca, "__mmap_lock_do_trace_acquire_returned" },
	{ 0x7dd4cb8, "__mmap_lock_do_trace_start_locking" },
	{ 0x69684a81, "fput" },
	{ 0x15114814, "path_put" },
	{ 0xa04d73e3, "d_path" },
	{ 0x30d37442, "mmput" },
	{ 0x53b954a2, "up_read" },
	{ 0x13d8b453, "__tracepoint_mmap_lock_released" },
	{ 0x759bf280, "path_get" },
	{ 0x80c2b44a, "__tracepoint_mmap_lock_acquire_returned" },
	{ 0x668b19a1, "down_read" },
	{ 0xee993901, "__tracepoint_mmap_lock_start_locking" },
	{ 0xbbf95e78, "get_task_mm" },
	{ 0x6b5cacf5, "current_task" },
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0x5a921311, "strncmp" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xa916b694, "strnlen" },
	{ 0x3480d929, "kmem_cache_alloc_trace" },
	{ 0x6f029675, "kmalloc_caches" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x356d8995, "crypto_destroy_tfm" },
	{ 0x2782e7c5, "crypto_shash_digest" },
	{ 0x3e358609, "crypto_alloc_shash" },
	{ 0x92997ed8, "_printk" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x905fbf70, "pv_ops" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "01DD4E95D38FA1AF2AA4201");
