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

#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>

//#include "reference_monitor_errors.h"

#define target_func0 "do_filp_open"
#define target_func1 "vfs_mkdir"
#define target_func2 "do_rmdir"
#define target_func3 "do_unlinkat"

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
	
}RM_info;

static RM_info info;


#define LINE_SIZE 256


int RM_change_pw(char*new){
	if(strlen(new)> PASS_LEN-1){return -1;}
	strncpy(info.passwd,strcat(new,"\0"), strlen(new)+1);
	printk("password changed to: %s", info.passwd);
	return 0;
}


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

char * get_absolute_path_by_name(char *name) {
    printk("into get absolute path from name");
    
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

	//check if status is reconfigurable, otherwise exit without applying changes
	if(info.state==ON || info.state==OFF){
		printk("impossible to change blacklist because monitor status is not reconfigurable");
		return -1;
	}
	
	
    	
    	char * abs_path;
    	abs_path=get_absolute_path_by_name(new_path);
    	if(abs_path==NULL){
    		printk("file doesn't exist");
    		return -1;
    	}
    	printk("add_path: path retrieved: %s",abs_path);
    	
	//check if path is already present in blacklist
	int i;
    	for(i=1; i<=info.pos; i++){
    		printk("Element %d is %s",i, info.blacklist[i]);
		if(strcmp(info.blacklist[i], abs_path)==0){
			printk("element already in blacklist");
			return -1;
		}
	}
	printk("position to write: %d", info.pos+1);
	if(strlen(abs_path)+1> MAX_LEN){printk("path is too long"); return -1;}
	strncpy(info.blacklist[++info.pos],strcat(abs_path,"\0"), strlen(abs_path)+1);	
	printk("blacklist has a new element:%s", info.blacklist[info.pos]);
	
	
	
	return 0;
		
}
int RM_remove_path(char * path){
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
			return 0;
		}
	}
	printk("No such file in blacklist");
	return 0;
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
			
			printk(KERN_ERR "Error: cannot open file in write mode because path is in the blacklist");
			return -EPERM ;
		}
	}
	
	return 0;
}


static int vfs_mkdir_wrapper(struct kprobe *ri, struct pt_regs *the_regs){	return 0;}

static int do_rmdir_wrapper(struct kprobe *ri, struct pt_regs *the_regs){
	return 0;
}

static int do_unlinkat_wrapper(struct kprobe *ri, struct pt_regs *regs){	
	

	switch(info.state){
			
		 char result[MAX_LEN];
		struct open_flags *flags; 
		char *name;
		struct file *file ;
		int open_mode ;
		
		char *abs_path;
		 if (!abs_path) {
			printk("Error allocating memory for result");
			return NULL;
	    	}
			memset(abs_path,0,MAX_LEN);
			
			
			case(OFF):
			case(REC_OFF):
				//if RM is OFF or REC_OFF return immediately
				
				break;
			case(ON):
			case(REC_ON):
			
	printk("Into do_unlinkat");
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
				checkBlacklist(abs_path);
					
				
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

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};
/*
La struct filename è fatta come segue:
struct filename {
	const char		*name;	pointer to actual string 
	const __user char	*uptr;	original userland pointer 
	atomic_t		refcnt;
	struct audit_names	*aname;
	const char		iname[];
};*/
static int do_filp_open_wrapper(struct kprobe *ri, struct pt_regs *regs){
  
	

	switch(info.state){
		
		 char result[MAX_LEN];
		struct open_flags *flags; 
		char *name;
		struct file *file ;
		int open_mode ;
		
		char *abs_path;
		 if (!abs_path) {
        printk("Error allocating memory for result");
        return NULL;
    }
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
	    		//se file sono temporanei ritorno subito
	    		 if (((strncmp(name, "/run", strlen("/run"))) == 0)
	    		 ||((strncmp(name, "/tmp", strlen("/tmp"))) == 0) 
	    		 ||((strncmp(name, "/var/tmp", strlen("/var/tmp"))) == 0)) {
				
				break;
			 }
			 
			flags= (struct open_flags *)(regs->dx); //access to dx that is the thirth argument
			
			open_mode =flags->open_flag;
			
			if( open_mode & O_RDWR || open_mode & O_WRONLY){
				printk("file opened in write mode");
				 
				abs_path=get_absolute_path_by_name(name);
				printk("Absolute path returned %s",abs_path );
				
				checkBlacklist(abs_path);
				
			}
				
				
			
			break;
			
		default:
			break;
		
	
}

	
	
ret:	return 0;

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



static struct kprobe kp_open = {
        .symbol_name =  target_func0,
        .pre_handler = do_filp_open_wrapper,
};


static struct kprobe kp_mkdir = {
        .symbol_name =  target_func1,
        .pre_handler = vfs_mkdir_wrapper,
};


static struct kprobe kp_rmdir = {
        .symbol_name =  target_func2,
        .pre_handler = do_rmdir_wrapper,
};


static struct kprobe kp_unlink = {
        .symbol_name =  target_func3,
        .pre_handler = do_unlinkat_wrapper,
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
	
	ret = register_kprobe(&kp_open);
     if (ret < 0) {
                printk("%s: kprobe filp open registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
           
      ret = register_kprobe(&kp_mkdir);
        if (ret < 0) {
                printk("%s: kprobe mkdir registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
        
       ret = register_kprobe(&kp_rmdir);
        if (ret < 0) {
                printk("%s: kprobe rmdir registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
        
        
       ret = register_kprobe(&kp_unlink);
	 if (ret < 0) {
                printk("%s: kprobe unlink registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
        
	return 0;
}


void cleanup_module(void) {
        printk("%s: shutting down\n",MODNAME);
   
       
        //unregistering kprobes
        unregister_kprobe(&kp_open);
     
       unregister_kprobe(&kp_mkdir);
        
        unregister_kprobe(&kp_rmdir);
        
        unregister_kprobe(&kp_unlink);
        printk("%s: kprobes unregistered\n", MODNAME);
        unregister_chrdev(Major, DEVICE_NAME);
        printk(KERN_INFO "%s: device unregistered, it was assigned major number %d\n",DEVICE_NAME,Major);
        printk("%s: Module correctly removed\n", MODNAME);
            
}


