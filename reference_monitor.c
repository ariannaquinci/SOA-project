#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/scatterlist.h>
#include <linux/fs_struct.h>
#include <linux/mm_types.h>


#include <linux/namei.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>

//#include "reference_monitor_errors.h"

#define target_func0 "do_filp_open"
#define target_func1 "vfs_mkdir"
#define target_func2 "do_rmdir"
#define target_func3 "do_unlinkat"
#define target_func4 "vfs_create"

#define AUDIT if(1)open

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("see the README file");

#define MODNAME "Reference monitor"

#define MAX_LEN 1024
#define MAX_PATHS 128
#define PASS_LEN 20
#define MAX_PARENTS 10
static ssize_t RM_write(struct file *, const char *, size_t, loff_t *);

#define DEVICE_NAME "/dev/reference_monitor"  /* Device file name in /dev/ */

static int Major;            /* Major number assigned to reference monitor device driver */



typedef enum reference_monitor_state{
	ON,
	OFF,
	REC_ON,
	REC_OFF,
}ref_monitor_state;

typedef struct reference_monitor_info{
	ref_monitor_state state;
	char passwd[PASS_LEN]; 
	char blacklist[MAX_PATHS][MAX_LEN];
	int pos;
	spinlock_t spinlock; 
}RM_info;

static RM_info info;


#define LINE_SIZE 256


int RM_change_pw(char*new){
	spin_lock(&info.spinlock);
	if(strlen(new)> PASS_LEN-1){spin_unlock(&info.spinlock); return -1;}
	strncpy(info.passwd,strcat(new,"\0"), strlen(new)+1);
	printk("password changed to: %s", info.passwd);
	spin_unlock(&info.spinlock);
	return 0;
}

/*
char *get_absolute_path(struct file *f) {
    struct path path;
    char *absolute_path = NULL;

    
    path = f->f_path;

//absolute path of the directory containing the file
    char *dir_path;
    dir_path = d_path(&path, (char *)__get_free_page(GFP_KERNEL), PAGE_SIZE);
    if (!dir_path){        return NULL;}
    printk("absolute path retrieved: %s", dir_path);

    return dir_path;
}
*/



char * get_absolute_path_by_name(char *name) {
	printk("into get absolute path by name");

	struct path path;
	int err = kern_path(name, LOOKUP_FOLLOW, &path);
	if(err<0){
	printk("file doesn't exist");
	return NULL;
	}
	char *result= (char*)kmalloc(sizeof(char)*MAX_LEN,GFP_KERNEL);
	char* abs_path;
	if (!result) {
	printk("Error allocating memory for result");
	return NULL;
	}
	memset(result,0, MAX_LEN);
	if (!err) {
		// Ottieni il percorso assoluto utilizzando d_path()
		abs_path=d_path(&path, result, MAX_LEN);
		if (!result) {
			printk("error in d_path: cannot retrieve absolute path");
			kfree(result);
			return NULL;
		}
	} else {
		printk("error in kern_path");
		kfree(result);
		return NULL;
	}
    
	printk("absolute path retrieved correctly: %s", abs_path);
	kfree(result);
	return abs_path;
}
int RM_add_path(char *new_path){
	spin_lock(&info.spinlock);
	//check if status is reconfigurable, otherwise exit without applying changes
	if(info.state==ON || info.state==OFF){
		spin_unlock(&info.spinlock);
		printk("impossible to change blacklist because monitor status is not reconfigurable");
		return -1;
	}
	
	
    	
    	char * abs_path;
    	abs_path=get_absolute_path_by_name(new_path);
    	if(abs_path==NULL){
    		printk("file doesn't exist");
    		spin_unlock(&info.spinlock);
    		return -1;
    	}
    	printk("add_path: path retrieved: %s",abs_path);
    	
	//check if path is already present in blacklist
	int i;
    	for(i=1; i<=info.pos; i++){
    		printk("Element %d is %s",i, info.blacklist[i]);
		if(strcmp(info.blacklist[i], abs_path)==0){
			printk("element already in blacklist");
			spin_unlock(&info.spinlock);
			return -1;
		}
	}
	printk("position to write: %d", info.pos+1);
	if(strlen(abs_path)+1> MAX_LEN){printk("path is too long"); spin_unlock(&info.spinlock); return -1;}
	strncpy(info.blacklist[++info.pos],strcat(abs_path,"\0"), strlen(abs_path)+1);	
	printk("blacklist has a new element:%s", info.blacklist[info.pos]);
	
	
	spin_unlock(&info.spinlock);
	return 0;
		
}
int RM_remove_path(char * path){
	spin_lock(&info.spinlock);
	struct file *f;
	/*f=filp_open(path, O_RDONLY, 0);
    	if (IS_ERR(f)) {
		printk(KERN_ERR " file %s not existent \n", path);
		return -1;
    	}*/
    	
    	printk("removing path %s", path);
	char* abs_path=get_absolute_path_by_name(path);
	if(abs_path==NULL){
    		printk("file doesn't exist");
    		spin_unlock(&info.spinlock);
    		return -1;
    	}
	int i;
	for(i=1; i<=info.pos; i++){
		printk("element %d in blacklist is: %s and pos is: %d",i, info.blacklist[i], info.pos);
		if(strcmp(info.blacklist[i], abs_path)==0){
			if(i!=info.pos){
				memset(info.blacklist[i],0,MAX_LEN);
				strncpy(info.blacklist[i],info.blacklist[info.pos], strlen(info.blacklist[info.pos]));
				
				info.pos--;
			}else{
				
				memset(info.blacklist[i],0,MAX_LEN);
				info.pos--;
				
				
			}
			printk("element removed");
			printk("pos is: %d", info.pos);
			spin_unlock(&info.spinlock);
			return 0;
		}
	}
	printk("No such file in blacklist");
	spin_unlock(&info.spinlock);
	return 0;
}
char *custom_dirname(char *path) {
    static char parent[PATH_MAX];
    int len = strlen(path);

    // Copia il percorso originale in parent
    strncpy(parent, path, PATH_MAX);
	int i ;
    // Cerca l'ultimo slash nel percorso
    for (i= len - 1; i >= 0; i--) {
        if (parent[i] == '/') {
            // Termina la stringa dopo l'ultimo slash per ottenere la directory padre
            parent[i] = '\0';
            break;
        }
    }
	printk("parent is: %s", parent);
    return parent;
}

int checkBlacklist(char* open_path){
	//checking blacklist
	
	if (open_path==NULL){
	
		return -1;
	}
	printk("checking blacklist for the file %s", open_path);
	int i;
	printk("pos is %d", info.pos);
	for(i=1; i<=info.pos; i++){
		printk("Element %d is %s", i, info.blacklist[i]);
		if(strcmp(info.blacklist[i], open_path)==0){
			return -EPERM;
		}
	}
	
	return 0;
}
struct my_data{
	unsigned long dfd;
};

static int vfs_mkdir_wrapper(struct kretprobe_instance *ri, struct pt_regs *the_regs){	
	return 0;
}

static int vfs_create_wrapper(struct kretprobe_instance *ri, struct pt_regs *the_regs){	
	return 0;
}


static int do_rmdir_wrapper(struct kretprobe_instance *ri, struct pt_regs *regs){
	
switch(info.state){	
		char result[MAX_LEN];
		char *name;
		struct file *file ;
		int open_mode ;
		
		char *abs_path;
		
		memset(abs_path,0,MAX_LEN);
		
		
		case(OFF):
		case(REC_OFF):
			//if RM is OFF or REC_OFF return immediately
			
			break;
		case(ON):
		case(REC_ON):
		
				memset(result, 0, MAX_LEN);
			//things to do when RM is ON or REC_ON
			//check if path has been opened in write mode
			
			name= ((struct filename *)(regs->si))->name;
			 if (IS_ERR(name)) {
				pr_err("Error getting filename\n");
				return 0;
	    		}
	    		
				 
			abs_path=get_absolute_path_by_name(name);
			printk("Absolute path returned %s",abs_path );
	
	
			
			 char *directory = abs_path;
        		while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0 ){
        		
			   if (checkBlacklist(directory) == -EPERM ) {
			        printk(KERN_ERR "Error: path or its parent directory is in blacklist: %s",directory);
			        struct my_data *data;
			        data = (struct my_data *)ri->data;
			        data->dfd = regs->di;
			        break;
			    }
			    // Get the parent directory
			    directory = custom_dirname(directory);
			   
			   
			     
        		}
			
			break;
			
		default:
			break;
		
	}
		
	return 0;


}

static int do_unlinkat_wrapper(struct kretprobe_instance *ri, struct pt_regs *regs){	
	switch(info.state){	
		char result[MAX_LEN];
		char *name;
		struct file *file ;
		int open_mode ;
		
		char *abs_path;
		
		memset(abs_path,0,MAX_LEN);
		
		
		case(OFF):
		case(REC_OFF):
			//if RM is OFF or REC_OFF return immediately
			
			break;
		case(ON):
		case(REC_ON):
		
				memset(result, 0, MAX_LEN);
			//things to do when RM is ON or REC_ON
			//check if path has been opened in write mode
			
			name= ((struct filename *)(regs->si))->name;
			printk("do unlink called on file %s",name );
			 if (IS_ERR(name)) {
				pr_err("Error getting filename\n");
				return 0;
	    		}
	    		
				 
			abs_path=get_absolute_path_by_name(name);
			printk("Absolute path returned %s",abs_path );
	
	
			
			 char *directory = abs_path;
        		while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0 ){
        		
			   if (checkBlacklist(directory) == -EPERM ) {
			        printk(KERN_ERR "Error: path or its parent directory is in blacklist: %s",directory);
			        struct my_data *data;
			        data = (struct my_data *)ri->data;
			        data->dfd = regs->di;
			        regs->di=-1000;
			        break;
			    }
			    // Get the parent directory
			    directory = custom_dirname(directory);
			   
			   
			     
        		}
			
			break;
			
		default:
			break;
		
	}
		
	return 0;

}


/*
segnatura della do_filp_open: 

	extern struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op)
	
La struct open_flags è un parametro della funzione do_filp_open ed è fatta come segue:

	struct open_flags {
		int open_flag;
		umode_t mode;
		int acc_mode;
		int intent;
		int lookup_flags;
	};
	Dato che questa struct non è visibile dall'esterno la ridichiaro (non è marcata come extern)
*/

/*
La struct filename è fatta come segue:
struct filename {
	const char		*name;	pointer to actual string 
	const __user char	*uptr;	original userland pointer 
	atomic_t		refcnt;
	struct audit_names	*aname;
	const char		iname[];
};*/

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};



static int do_filp_open_wrapper(struct kretprobe_instance *ri, struct pt_regs *regs){
	switch(info.state){

		char result[MAX_LEN];
		struct open_flags *flags; 
		char *name;
		struct file *file ;
		int open_mode ;

		char *abs_path;
		
		memset(abs_path,0,MAX_LEN);


		case(OFF):
		case(REC_OFF):
			//if RM is OFF or REC_OFF return immediately

			break;
		case(ON):
		case(REC_ON):
			memset(result, 0, MAX_LEN);
			//things to do when RM is ON or REC_ON
			//check if path has been opened in write mode

			name= ((struct filename *)(regs->si))->name;
			if (IS_ERR(name)) {
				pr_err("Error getting filename\n");
				return 0;
			}
			//se file sono temporanei ritorno subito idem se il file è il dispositivo reference_monitor
			if (((strncmp(name, "/run", strlen("/run"))) == 0)
			||((strncmp(name, "/tmp", strlen("/tmp"))) == 0) 
			||((strncmp(name, "/var/tmp", strlen("/var/tmp"))) == 0)
			||((strncmp(name, "/dev/reference_monitor", strlen("/dev/reference_monitor"))) == 0) ){

				break;
			}

			flags= (struct open_flags *)(regs->dx); //access to dx that is the thirth argument

			open_mode =flags->open_flag;
			
			if(open_mode & O_CREAT || open_mode & O_RDWR || open_mode & O_WRONLY) {
				printk("file opened in write mode");

				abs_path=get_absolute_path_by_name(name);
				
				printk("Absolute path returned %s",abs_path );
				
				 char *directory = abs_path;
                		while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0 ){
                		
				   if (checkBlacklist(directory) == -EPERM ) {
				        printk(KERN_ERR "Error: path or its parent directory is in blacklist: %s",directory);
				        struct my_data *data;
				        data = (struct my_data *)ri->data;
				        data->dfd = regs->di;
				        break;
				    }
				    // Get the parent directory
				    directory = custom_dirname(directory);
				   
				   
				     
                		}
			
        		
				

			}

			break;

		default:
			break;

	}

	return 0;

	
}

//post handlers

static int post_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
	
	struct my_data *data = (struct my_data *)ri->data;
	
		
	if(data->dfd>0){
	
		printk("data->dfd %ld",data->dfd);
		regs->ax=-EPERM;
		data->dfd=0;
	}
	return 0;
}

static int post_vfs_mkdir(struct kretprobe_instance *ri, struct pt_regs *regs){
	return 0;
}

static int post_vfs_create(struct kretprobe_instance *ri, struct pt_regs *regs){
	return 0;	
}
	
	
	
static int RM_open(struct inode *inode, struct file *file) {

//device opened by a default nop
   return 0;
}



//struct file operations containing mapping between actual driver's operations and standard operations
static struct file_operations fops = {
  .owner = THIS_MODULE,	//macro "THIS_MODULE" return pointer to the module struct
  .write = RM_write,
  .open=RM_open,
  
 
};



static struct kretprobe kp_open = {
	 .handler = post_handler,
	.entry_handler=do_filp_open_wrapper,
	.data_size=sizeof(struct my_data),
	
};

static struct kretprobe kp_mkdir = {
	 .handler = post_vfs_mkdir,
        .entry_handler = vfs_mkdir_wrapper,
};
static struct kretprobe kp_vfs_create = {
	 .handler = post_vfs_create,
        .entry_handler = vfs_create_wrapper,
};

static struct kretprobe kp_rmdir = {
 
       .handler = post_handler,
        .entry_handler = do_rmdir_wrapper,
};


static struct kretprobe kp_unlink = {
        .handler = post_handler,
        .entry_handler = do_unlinkat_wrapper,
        .data_size=sizeof(struct my_data),
};

int reference_monitor_on(void){
	
	printk("into reference_monitor_on");
	printk("RM was %d\n", info.state);
	
	info.state=ON;
	printk("RM is %d\n", info.state);

	return 0;
}
int reference_monitor_off(void){
		printk("into reference_monitor_off");
		
		info.state=OFF;
		printk("RM is %d\n", info.state);
		return 0;
	
}

int reference_monitor_rec_off(void){
		printk("into reference_monitor_rec_off");
		
		info.state=REC_OFF;
		printk("RM is %d\n", info.state);
		return 0;
	
}

int reference_monitor_rec_on(void){

	printk("into reference_monitor_rec_on");
	
		info.state=REC_ON;
		printk("RM is %d\n", info.state);
		return 0;
	}


static ssize_t RM_write(struct file *f, const char *buff, size_t len, loff_t *off){
	int j,ret=0;
	char* args[3];
	char *token;
	
	char *buffer = kmalloc(LINE_SIZE, GFP_KERNEL);
	
	if (!buffer) {
	    printk(KERN_ERR "Errore: impossibile allocare memoria per buffer\n");
	    return -ENOMEM;
	}
	if(len >= LINE_SIZE) return -1;
  	ret = copy_from_user(buffer,buff,len);

  	j = 0;
  	token = strsep(&buffer, " ");
	while (token != NULL && j < 3) {
	    args[j++] = token;
	    token = strsep(&buffer, " ");
	}
  	
	kfree(buffer);
  	
	if(strcmp(args[2],info.passwd)==0){
		printk("password is correct");
		if(strcmp(args[0],"new_state")==0){
			if(strcmp(args[1],"ON")==0){
					
					reference_monitor_on();
			}
			if(strcmp(args[1],"OFF")==0){
				
					reference_monitor_off();
			}
			if(strcmp(args[1],"REC_OFF")==0){
				
					reference_monitor_rec_off();
			}
			if(strcmp(args[1],"REC_ON")==0){
					printk("asked to change state to REC_ON");
					reference_monitor_rec_on();
			}else{
				printk("Invalid argument");
			}
		}
		if(strcmp(args[0],"change_pw")==0){
			RM_change_pw(args[1]);
		}
		if (strcmp(args[0],"add_path")==0){
			
			RM_add_path(args[1]);
		}
		if(strcmp(args[0],"remove_path")==0){
		
			RM_remove_path(args[1]);
		}
		
		return len;
		
	
	}
	printk("wrong password passed: %s", args[2]);

	return -1;
}




int init_module(void) {

	int ret;
	
	printk("%s: initializing\n",MODNAME);
	
	//registration of the RM as a char device driver
	Major = register_chrdev(0, DEVICE_NAME, &fops);

	if (Major < 0) {
		printk ("Registering the character device failed with %d\n", Major);
		return Major;
	}
	printk("major number is: %d", Major);
	
	//init info 
	info.state=OFF;
	strncpy(info.passwd, "changeme\0", strlen("changeme\0") );
	strncpy(	info.blacklist[0],"This is the blacklist\0",strlen("This is the blacklist\0"));
	kp_open.kp.symbol_name = target_func0;
	ret = register_kretprobe(&kp_open);
     if (ret < 0) {
                printk("%s: kretprobe filp open registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
            kp_mkdir.kp.symbol_name=target_func1;
      ret = register_kretprobe(&kp_mkdir);
     
        if (ret < 0) {
                printk("%s: kretprobe mkdir registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
         kp_rmdir.kp.symbol_name=target_func2;
       ret = register_kretprobe(&kp_rmdir);
       
        if (ret < 0) {
                printk("%s: kretprobe rmdir registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
         kp_unlink.kp.symbol_name=target_func3;
        
       ret = register_kretprobe(&kp_unlink);
	 if (ret < 0) {
                printk("%s: kretprobe unlink registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
        
	return 0;
}


void cleanup_module(void) {
        printk("%s: shutting down\n",MODNAME);
   
       
        //unregistering kretprobes
        unregister_kretprobe(&kp_open);
     
       unregister_kretprobe(&kp_mkdir);
        
        unregister_kretprobe(&kp_rmdir);
        
        unregister_kretprobe(&kp_unlink);
        printk("%s: kretprobes unregistered\n", MODNAME);
        unregister_chrdev(Major, DEVICE_NAME);
        printk(KERN_INFO "%s: device unregistered, it was assigned major number %d\n",DEVICE_NAME,Major);
        printk("%s: Module correctly removed\n", MODNAME);
            
}




