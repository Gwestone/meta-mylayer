#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/hw_breakpoint.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/miscdevice.h>
#include <linux/kprobes.h>

//module param
static int watch_addr = 0xABCDEF;
module_param(watch_addr, int, 0644);

//sysfs
static struct kobject *watch_addr_kobj;

int parse_hex(const char *hex_str) {
    int result;
    sscanf(hex_str, "%x", &result);
    return result;
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    pr_info(KERN_INFO "memset accessed at address 0x%X\n", watch_addr);
    // dump_stack();
    return 0;
}

/**************************************/
//Handling loading variables from sysfs start
/**************************************/
static ssize_t read_sysfs_callback(struct kobject *kobj, struct kobj_attribute *attr, char *buffer){
	return sprintf(buffer, "Current watch_addr: 0x%X\n", watch_addr);
}

static ssize_t store_sysfs_callback(struct kobject *kobj, struct kobj_attribute *attr, const char *buffer, size_t count){
	pr_info("Sysfs WRITE - '%s' to /sys/kernel/%s%s\n", buffer, kobj->name, attr->attr.name);
	watch_addr = parse_hex(buffer);
	return count;
}
/**************************************/
//Handling loading variables from sysfs end
/**************************************/

static struct kobj_attribute addr_attribute = __ATTR(watch_addr_kobj, 0644, read_sysfs_callback, store_sysfs_callback);

static struct kprobe kp = {
	.symbol_name = "memset",
	.pre_handler = handler_pre,
};

static int __init hello_init(void)
{
	pr_info("Module initialized, Now watching memory address: 0x%X\n", watch_addr);
	pr_info("Creating sysfs link \n");

	/***********************************/
	// Start init sysfs files
	/***********************************/

	watch_addr_kobj = kobject_create_and_add("hello", kernel_kobj);

	if(!watch_addr_kobj){
		pr_info("Failed to create sysfs directory \n");
		return 1;
	}

	if(sysfs_create_file(watch_addr_kobj, &addr_attribute.attr)){
		pr_info("Failed to create sysfs file \n");
		kobject_put(watch_addr_kobj);
		return 1;
	}

	/***********************************/
	// End sysfs files
	/***********************************/

	/***********************************/
	// Start Watchpoint
	/***********************************/

	pr_info("KProbe Module: Initializing...\n");

    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_info(KERN_ERR "Failed to register kprobe\n");
        return ret;
    }

	pr_info("KProbe Module: Initialized\n");

	/***********************************/
	// End Watchpoint
	/***********************************/
	
	pr_info("Successfully created sysfs link \n");

	return 0;
}

static void __exit hello_exit(void)
{
	pr_info("Module detached, Now unwaching memory address: 0x%X\n", watch_addr);

	/***********************************/
	// Remove sysfs files
	/***********************************/

	sysfs_remove_file(watch_addr_kobj, &addr_attribute.attr);
	kobject_put(watch_addr_kobj);

	/***********************************/
	// Remove sysfs files
	/***********************************/

	pr_info("Unregistering kprobes...\n");

	unregister_kprobe(&kp);
	
	pr_info("Kprobes unregistered.\n");

	pr_info("Goodbye Cruel World!\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
