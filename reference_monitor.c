#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/scatterlist.h>
#include <linux/fs_struct.h>
#include <linux/mm_types.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/stat.h>
#include <linux/kprobes.h>
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
#include "my_crypto.c"
#include "RM_utils.c"

//#define target_func0 "do_filp_open"
#define target_func0 "do_sys_openat2"
#define target_func1 "vfs_mkdir"
#define target_func3 "vfs_unlink"
#define target_func2 "vfs_rmdir"
#define HASH_SIZE 32


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("see the README file");

static char *the_file = NULL;
module_param(the_file, charp, 0660);
MODULE_PARM_DESC(the_file, "Path to the file");

#define DEVICE_NAME "/dev/reference_monitor"  /* Device file name in /dev/ */

#define BUFFER_SIZE (16 * 1024) // 16 KB

static ssize_t RM_write(struct file *, const char *, size_t, loff_t *);


static int Major;            /* Major number assigned to reference monitor device driver */

static char *the_file;

static struct workqueue_struct *queue;




typedef enum reference_monitor_state{
	ON,
	OFF,
	REC_ON,
	REC_OFF,
}ref_monitor_state;

typedef struct reference_monitor_info{
	ref_monitor_state state;
	char passwd[33]; 
	char blacklist[MAX_PATHS][MAX_LEN];
	int pos;
	
}RM_info;

static RM_info info;

struct modified_inode {
    struct inode *inode;
    unsigned long original_flags;
    unsigned int original_mode;
    struct list_head list;
     char blacklisted[MAX_LEN];
};
static LIST_HEAD(modified_inodes_list);
static spinlock_t RM_lock;

static void restore_inodes_flags(void) {
    struct modified_inode *entry, *tmp;
  
    list_for_each_entry_safe(entry, tmp, &modified_inodes_list, list) {
        entry->inode->i_flags = entry->original_flags;
        entry->inode->i_mode=entry->original_mode;
        list_del(&entry->list);
        kfree(entry);
    }
}


static void restore_inode_flags_by_path(const char *path) {
    struct modified_inode *entry, *tmp;
    char buf[MAX_LEN];
	printk("restoring flags for path %s", path);
    list_for_each_entry_safe(entry, tmp, &modified_inodes_list, list) {
    	char *black_path=entry->blacklisted;
         printk("inode_path is: %s, while abs path is: %s", black_path, path);
        if (strcmp(black_path, path) == 0) {
           printk("equals");
            entry->inode->i_flags = entry->original_flags;
            entry->inode->i_mode=entry->original_mode;
            list_del(&entry->list);
            kfree(entry);
        }
    }
}

bool check_passwd(char* pw){
	printk("checking pw");
	
	unsigned char *pw_digest;
	unsigned char pw_var[33];
	pw_digest=kmalloc(33,GFP_KERNEL);
	memset(pw_digest,0,33);
	int ret=0;
	bool res=false;
	
	ret=do_sha256(pw, pw_digest,strlen(pw));
	if(ret!=0){
		printk(KERN_ERR "error in calculating sha256 of the password");
		kfree(pw_digest);
		
		return res;
	}
	spin_lock(&RM_lock);
	strncpy(pw_var, info.passwd,  strlen(info.passwd));
	spin_unlock(&RM_lock);
	if(strncmp(pw_digest, pw_var, my_min(pw_digest, strlen(pw_var)))==0){
		
		res= true;
	}else{
		
	
		res= false;
	}
	
	kfree(pw_digest);
	return res;
}


int RM_change_pw(char *new){
	
	
	if(strlen(new)> PASS_LEN-1){ 
		printk(KERN_ERR "too long password");
		
		return -1;
	}
	spin_lock(&RM_lock);
	do_sha256(new, info.passwd, strlen(new));
	
	spin_unlock(&RM_lock);
	return 0;
}
struct record{
	pid_t tgid;	//group identifier
	pid_t pid;	//thread identifier
	uid_t current_uid;
	uid_t current_euid; 
	char program_path[MAX_LEN];
	char content_hash[MAX_BUFFER_SIZE];
	
};



typedef struct {
    struct work_struct work;
    struct record deferred_record;
} deferred_work_data;


bool concatenate_record_to_buffer(deferred_work_data *data, char *buffer) {
    // Formatta ogni campo della struttura record come stringa e concatenali nel buffer
	
    if(snprintf(buffer, RECORD_SIZE, "%d %d %d %d %s %s\n",
             data->deferred_record.tgid, data->deferred_record.pid, data->deferred_record.current_uid, data->deferred_record.current_euid,
             data->deferred_record.program_path,data->deferred_record.content_hash)>0){
	return true;}
	return false;
}
bool write_append_only(char* line) {
   printk("write append only");

    loff_t pos=0;
    int ret = 0;
    struct file *file;
 
    
    file = filp_open(the_file, O_WRONLY | O_APPEND, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open the_file\n");
        
        return false;
    }

	   ret = kernel_write(file,line, strlen(line),&pos);
	 
	    if (ret < strlen(line)) {
	    	/*printk(KERN_ERR "wrote only %d bytes", ret);
		printk(KERN_ERR "Failed to write the file\n");
		filp_close(file, NULL);
		
		return false;*/
		printk(KERN_INFO "wrote only %d bytes", ret);
		kernel_write(file,line+ret, strlen(line)-ret,&pos);
	    }

    printk("\n%s: File \"the_file\" written with line: %s\n", MODNAME,line );
    filp_close(file, NULL);
  
    return true;
}


void do_deferred_work(struct work_struct *work) {
	deferred_work_data *data = container_of(work, deferred_work_data, work);
	unsigned char *prev_hash;// Inizializza a zero
	unsigned char *curr_hash;  // Hash corrente
	unsigned char *buffer;  // Buffer per leggere i blocchi

	struct file *filp;
	ssize_t bytes_read;
	int ret;
	char *line;
	prev_hash=kzalloc(HASH_SIZE, GFP_KERNEL);
	if(!prev_hash){
		printk(KERN_ERR "Failed to allocate memory\n");
		return;
	}

	curr_hash=kzalloc(HASH_SIZE, GFP_KERNEL);
	if(!prev_hash){
		printk(KERN_ERR "Failed to allocate memory\n");
		kfree(prev_hash);
		return;
	}
	buffer=kzalloc(BUFFER_SIZE, GFP_KERNEL);
	if(!buffer){
		printk(KERN_ERR "Failed to allocate memory\n");
		kfree(prev_hash);
		kfree(curr_hash);
	return;
	}
	line=kzalloc(RECORD_SIZE, GFP_KERNEL);
	if(!buffer){
		printk(KERN_ERR "Failed to allocate memory\n");
		kfree(prev_hash);
		kfree(curr_hash);
		kfree(buffer);
		return;
	}
	// Apri il file eseguibile in modalità di sola lettura
	filp = filp_open(data->deferred_record.program_path, O_RDONLY, 0);
	if (IS_ERR(filp)) {
		printk(KERN_ERR "Failed to open executable file\n");
		kfree(prev_hash);
		kfree(curr_hash);
		kfree(buffer);
		kfree(line);
		return;
	}

	// Leggi i dati blocco per blocco fino alla fine del file
	loff_t offset = 0;
	while ((bytes_read = kernel_read(filp, buffer, BLOCK_SIZE, &offset)) > 0) {
	// Calcola l'hash del blocco corrente
	 
	ret = do_sha256(buffer, curr_hash, bytes_read);
	if (ret < 0) {
		printk(KERN_ERR "Failed to calculate hash\n");
		filp_close(filp, NULL);
		kfree(prev_hash);
		kfree(curr_hash);
		kfree(buffer);
		kfree(line);
		return;
	}

	// Fai lo XOR tra l'hash del blocco corrente e l'hash accumulato precedentemente
	int i;
	for (i = 0; i < HASH_SIZE; i++) {
	    prev_hash[i] ^= curr_hash[i];
	}

	}

	// Chiudi il file
	filp_close(filp, NULL);

	// Converti l'hash finale in una stringa
	hash_to_string(prev_hash, data->deferred_record.content_hash);


	// Scrivi su file
	if (concatenate_record_to_buffer(data, line)) {
		if (!write_append_only(line)) {
		    printk(KERN_ERR "Impossible to write append only\n");
		}
	}
	kfree(prev_hash);
	kfree(curr_hash);
	kfree(buffer);
	kfree(line);
}


void schedule_deferred_work(void) {
   
    deferred_work_data *data;

    
    // Alloca memoria per i dati
    data = kzalloc(sizeof(deferred_work_data), GFP_KERNEL);
    if (!data) {
        printk(KERN_ERR "Failed to allocate memory for deferred work\n");
        
        return;
    }

    struct cred *cred = get_task_cred(current);

    data->deferred_record.tgid = current->tgid;
    data->deferred_record.pid = current->pid;
    data->deferred_record.current_uid = cred->uid.val;
    data->deferred_record.current_euid = cred->euid.val;
    

    char *path = get_current_proc_path();
    if (IS_ERR(path)) {
    	printk("error in retrieving path");
        printk(KERN_ERR "Failed to retrieve process path\n");
        kfree(data); // Libera la memoria allocata per i dati
       
        return;
    }

    // Copia il percorso nel campo program_path dei dati differiti
    strncpy(data->deferred_record.program_path, path, MAX_LEN);


    printk("schedule_deferred_work: pid %d, tgid %d, uid %d, euid %d, path %s\n",
           data->deferred_record.pid, data->deferred_record.tgid,
           data->deferred_record.current_uid, data->deferred_record.current_euid,
           data->deferred_record.program_path);

    // Inizializza il lavoro differito
    INIT_WORK(&(data->work), do_deferred_work);

    // Accoda il lavoro alla coda di lavoro
    queue_work(queue, &(data->work));

}


int RM_add_path(char *new_path){
	spin_lock(&RM_lock);
	//check if status is reconfigurable, otherwise exit without applying changes
	if(info.state==ON || info.state==OFF){
		spin_unlock(&RM_lock);
		printk(KERN_ERR "impossible to change blacklist because monitor status is not reconfigurable");
		return -1;
	}
	
	
    	
    	char * abs_path;
    	abs_path=get_absolute_path_by_name(new_path);
    	if(abs_path==NULL){
    		printk(KERN_ERR "file doesn't exist");
    		spin_unlock(&RM_lock);
    		return -1;
    	}
    	
	//check if path is already present in blacklist
	int i;
    	for(i=1; i<=info.pos; i++){
    		
		if(strcmp(info.blacklist[i], abs_path)==0){
			printk("element already in blacklist");
			spin_unlock(&RM_lock);
			return -1;
		}
	}
	
	if(strlen(abs_path)+1> MAX_LEN){
		printk(KERN_ERR "path is too long"); 
		spin_unlock(&RM_lock); 
		return -1;
	}
	strncpy(info.blacklist[++info.pos],strcat(abs_path,"\0"), strlen(abs_path)+1);	
	
	spin_unlock(&RM_lock);
	return 0;
		
}
int RM_remove_path(char * path){
	spin_lock(&RM_lock);
	
	char* abs_path=get_absolute_path_by_name(path);
	if(abs_path==NULL){
    		printk(KERN_ERR "file doesn't exist");
    		spin_unlock(&RM_lock);
    		return -1;
    	}
	int i;
	for(i=1; i<=info.pos; i++){
		
		if(strcmp(info.blacklist[i], abs_path)==0){
			if(i!=info.pos){
				memset(info.blacklist[i],0,MAX_LEN);
				strncpy(info.blacklist[i],info.blacklist[info.pos], strlen(info.blacklist[info.pos]));
				
				info.pos--;
			}else{
				
				memset(info.blacklist[i],0,MAX_LEN);
				info.pos--;
				
				
			}
			
			restore_inode_flags_by_path(abs_path);
			
			spin_unlock(&RM_lock);
			return 0;
		}
	}
	printk(KERN_ERR "No such file in blacklist");
	spin_unlock(&RM_lock);
	return 0;
}


int checkBlacklist(char* open_path){
	//checking blacklist
	
	if (open_path==NULL){
	
		return -1;
	}
	
	int i;
	
	for(i=1; i<=info.pos; i++){
		if(strcmp(info.blacklist[i], open_path)==0){
			
			return -EPERM;
		}
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





void set_inode_read_only(struct inode *inode) {
    unsigned int mask = S_IWUSR | S_IWGRP | S_IWOTH;
    inode->i_mode &= ~mask;
    //to avoid sudo to change permissions set immutable
    inode->i_flags |= S_IMMUTABLE;
    inode->i_ctime = inode->i_mtime = inode->i_atime = current_time(inode);
}


int save_original_flags(struct inode *inode, char *directory){
	printk("saving flags");
		
		// Save the original flags and add the inode to the list of modified inodes
		struct modified_inode *mod_inode = kmalloc(sizeof(*mod_inode), GFP_KERNEL);
		if (!mod_inode) {
			printk(KERN_ERR "Failed to allocate space for modified_inode");
			
			return -ENOMEM;
		}
		
		
		 int ret = strscpy(mod_inode->blacklisted, directory, sizeof(mod_inode->blacklisted));
		    if (ret < 0) {
			printk(KERN_ERR "Failed to copy directory path to blacklisted");
			kfree(mod_inode);
			
			return ret;
		    }
				printk("blacklisted set to %s", mod_inode->blacklisted);
		mod_inode->original_flags = inode->i_flags;
		mod_inode->original_mode = inode->i_mode;
		mod_inode->inode = inode;
		list_add(&mod_inode->list, &modified_inodes_list);
		
		return 0;
			
}


static int vfs_mkdir_wrapper(struct kprobe *p, struct pt_regs *regs){
    printk("into vfs_mkdir wrapper");
    struct dentry *dentry = (struct dentry *)regs->dx;
    struct inode *inode = (struct inode *)regs->si;
    char *directory;
    char *name;
    char *abs_path;
    char *buf;
    char *full_path;

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf) {
        printk(KERN_ERR "Failed to allocate space for buffer");
        return -ENOMEM;
    }

    // Get the full path of the dentry
    name = dentry_path_raw(dentry, buf, PATH_MAX);
    if (IS_ERR(name)) {
        printk(KERN_ERR "Failed to get dentry path");
        kfree(buf);
        return PTR_ERR(name);
    }

    // Allocate buffer for full path
    full_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!full_path) {
        printk(KERN_ERR "Failed to allocate space for full path");
        kfree(buf);
        return -ENOMEM;
    }

    if (strncmp(name, "/", 1) == 0) {
        snprintf(full_path, MAX_LEN, "%s", name);
    }else{
    // Combine the current directory path with the new directory name
    snprintf(full_path, MAX_LEN, "%s/%s", name, dentry->d_name.name);
}
    printk("dentry->d_name.name is %s", dentry->d_name.name);
    printk("abs path is %s", full_path);

    if (full_path == NULL) {
        printk("abs path null");
        kfree(buf);
        kfree(full_path);
        return -ENOMEM;
    }

    directory = full_path;
    spin_lock(&RM_lock);
    while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0) {
    	
        if (checkBlacklist(directory) == -EPERM) {
            printk(KERN_ERR "Error path or its parent directory is in blacklist: %s", directory);
	 
            schedule_deferred_work();
            struct modified_inode *entry, *tmp;
          	
            list_for_each_entry_safe(entry, tmp, &modified_inodes_list, list) {
                char *black_path = entry->blacklisted;
                printk("inode_path is: %s, while abs path is: %s", black_path, directory);
                if (strcmp(black_path, directory) == 0) {
                    set_inode_read_only(inode);
                    
                    // Se i flag sono già stati salvati da altre chiamate setto semplicemente il nuovo flag
                    kfree(buf);
                    kfree(full_path);
                    spin_unlock(&RM_lock);
                    return 0;
                }
            }

            save_original_flags(inode, directory);
 		
            set_inode_read_only(inode);
            

            kfree(buf);
            kfree(full_path);
           spin_unlock(&RM_lock);
            return 0;
        }
        directory = custom_dirname(directory);
    }

    kfree(buf);
    kfree(full_path);
    spin_unlock(&RM_lock);
    return 0;
}

static int vfs_rm_wrapper(struct kprobe *p, struct pt_regs *regs){


	char result[MAX_LEN];
    char *name;

    char *abs_path;

	char *buf;
	struct dentry *dentry;
	dentry = (struct dentry *)regs->dx; 
	 buf = kmalloc(PATH_MAX, GFP_KERNEL);
	 if(!buf){
	 	printk(KERN_ERR "Failed to allocate space for buffer");
        return -ENOMEM;
	 }
    // Get the full path of the dentry
    name =dentry_path_raw(regs->dx, buf, MAX_LEN);
    kfree(buf);
    printk("name is %s", name);
    if (!name) {
        printk(KERN_ALERT "Failed to get dentry path\n");
        
        return -ENOMEM;
    }

    if (IS_ERR(name)) {
        pr_err(KERN_ERR "Errore nell'ottenere il nome del file\n");
        return 0;
    }

    if (temporal_file(name)) {
        return 0;
    }

    abs_path = get_absolute_path_by_name(name);

    char *directory = abs_path;
    spin_lock(&RM_lock);
    while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0) {

        if (checkBlacklist(directory) == -EPERM) {
        
        struct inode *dir =(struct inode*)(regs->si);
        printk(KERN_ERR "Error path or its parent directory is in blacklist: %s", directory);
		    
		    schedule_deferred_work();
		    
		    
		      struct modified_inode *entry, *tmp;
		
		    list_for_each_entry_safe(entry, tmp, &modified_inodes_list, list) {
		    //    char *inode_path = dentry_path_raw(entry->dentry, buf, MAX_LEN); 
		    	char *black_path=entry->blacklisted;
			printk("inode_path is: %s, while abs path is: %s", black_path, directory);
			if (strcmp(black_path, directory) == 0) {
			 	 dir->i_flags |= S_APPEND;
			 	 //se i flag sono già stati salvati da altre chiamate setto semplicemente il nuovo flag 
			 	spin_unlock(&RM_lock);
			 	 return 0; 
			}
		    }
		    
			save_original_flags(dir, directory);
			spin_unlock(&RM_lock);
			
			dir->i_flags |= S_APPEND;
	
		return 0;
        }
        // Ottieni la directory principale
        directory = custom_dirname(directory);
    }
 spin_unlock(&RM_lock);

    return 0;
	
}


struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

static int do_sys_openat_wrapper(struct kprobe *p, struct pt_regs *regs){
		struct open_how *flags; 
		char *name;
		
		int open_mode ;
		char *abs_path;
		
		
		name= (const char*)(regs->si);
		if (IS_ERR(name)) {
			pr_err(KERN_ERR "Error getting filename\n");
			return 0;
		}
		
		
		flags= (struct open_how *)(regs->dx); //access to dx that is the thirth argument
		open_mode =flags->flags;
		if(!(open_mode & O_CREAT || open_mode & O_RDWR || open_mode & O_WRONLY || open_mode & O_TRUNC)){
			return 0;
		}
		unsigned long fd;
		fd= regs->di;
		char *directory;
		
		abs_path=get_absolute_path_by_name(name);
		
		//two cases: file exists or not
		if(open_mode & O_CREAT && abs_path==NULL){
			char* path;
			directory=get_cwd();
			path=custom_dirname(name);
			
			path=get_absolute_path_by_name(path);
			if(path!=NULL){
				directory=path;}
			
			   
			   
			     
        	}		
		
		else if(open_mode & O_CREAT || open_mode & O_RDWR || open_mode & O_WRONLY || open_mode & O_TRUNC && abs_path!=NULL) {
			
			abs_path=get_absolute_path_by_name(name);
			
			directory = abs_path;
			
		}
		spin_lock(&RM_lock);
		while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0 ){
        		
			   if (checkBlacklist(directory) == -EPERM ) {
			        printk(KERN_ERR "Error: path or its parent directory is in blacklist: %s",directory);
			        //calling the function that permits to write to the append-only file
		       	
			        schedule_deferred_work();
			        printk("changing flags to a negative value");
			       
			        flags->flags=-1000;
				spin_unlock(&RM_lock);
			        return 0;
			    }
			   
			    directory = custom_dirname(directory);
		}
		spin_unlock(&RM_lock);
		return 0;
}

static int RM_open(struct inode *inode, struct file *file) {

//device opened by a default nop
   return 0;
}



//struct file operations containing mapping between actual driver's operations and standard operations
static struct file_operations fops = {
  .owner = THIS_MODULE,	
  .write = RM_write,
  .open=RM_open,
  
 
};


static struct kprobe kp_open = {
    .symbol_name = target_func0,
  //  .pre_handler = do_filp_open_wrapper,
    .pre_handler=do_sys_openat_wrapper,
};

static struct kprobe kp_vfs_unlink = {
    .symbol_name = target_func3,
	.pre_handler=vfs_rm_wrapper,
};


static struct kprobe kp_vfs_rmdir={
	.symbol_name=target_func2,
	.pre_handler=vfs_rm_wrapper,
};
static struct kprobe kp_mkdir = {
	.symbol_name = target_func1,
       .pre_handler = vfs_mkdir_wrapper,
};

void modify_state(enum reference_monitor_state state){
	printk("into modify state");
	spin_lock(&RM_lock);
	printk("state is %d", info.state);
	if((info.state==OFF||info.state==REC_OFF) && (state==REC_ON ||state==ON )){
		
		enable_kprobe(&kp_open);
	 	enable_kprobe(&kp_vfs_unlink);
	 	enable_kprobe(&kp_mkdir);
	 	enable_kprobe(&kp_vfs_rmdir);
		
		
	}
	else if((info.state==ON||info.state==REC_ON) && (state==REC_OFF ||state==OFF)){
		restore_inodes_flags();
		disable_kprobe(&kp_open);
		disable_kprobe(&kp_vfs_unlink);
		disable_kprobe(&kp_vfs_rmdir);
		disable_kprobe(&kp_mkdir);
	}
	info.state=state;
	
	printk("state is %d", info.state);
	spin_unlock(&RM_lock);
	
}

int reference_monitor_on(void){
	modify_state(ON);
	return 0;
}
int reference_monitor_off(void){
	
	modify_state(OFF);
	
	return 0;
	
}

int reference_monitor_rec_off(void){
	modify_state(REC_OFF);
	
		
	return 0;
	
}

int reference_monitor_rec_on(void){
	modify_state(REC_ON);
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
  	if(check_passwd(args[2])){	
		if(strcmp(args[0],"new_state")==0){
			if(strcmp(args[1],"ON")==0){
					
					reference_monitor_on();
			}
			else if(strcmp(args[1],"OFF")==0){
				
					reference_monitor_off();
			}
			else if(strcmp(args[1],"REC_OFF")==0){
				
					reference_monitor_rec_off();
			}
			else if(strcmp(args[1],"REC_ON")==0){
					
					reference_monitor_rec_on();
			}else{
				
				printk(KERN_ERR "Invalid argument");
			}
		}
		else if(strcmp(args[0],"change_pw")==0){
			
			RM_change_pw(args[1]);
		}
		else if (strcmp(args[0],"add_path")==0){
			
			RM_add_path(args[1]);
		}
		else if(strcmp(args[0],"remove_path")==0){
		
			RM_remove_path(args[1]);
		}else{
		
				printk(KERN_ERR "Invalid argument");
			}
		
		return len;
	
	}
	printk(KERN_ERR "wrong password passed: %s", args[2]);

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
	
	do_sha256("changeme", info.passwd,strlen("changeme"));
	strncpy(info.blacklist[0],"This is the blacklist\0",strlen("This is the blacklist\0"));
	
	ret = register_kprobe(&kp_open);
	if (ret < 0) {
                printk(KERN_ERR "%s: kprobe filp open registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
        ret = register_kprobe(&kp_vfs_unlink);
        if (ret < 0) {
                printk(KERN_ERR "%s: kprobe unlinkat registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
        
        ret=register_kprobe(&kp_mkdir);
        if (ret < 0) {
                printk(KERN_ERR "%s: kprobe mkdir registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
        
  
        register_kprobe(&kp_vfs_rmdir);
        if (ret < 0) {
                printk(KERN_ERR "%s: kprobe rmdir registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
        
       
        reference_monitor_off();
        
	
        queue = create_singlethread_workqueue("recording_queue");
	if (!queue) {
		printk(KERN_ERR "Failed to create work queue\n");
		return -1;
	}
        
	return 0;
}


void cleanup_module(void) {
	printk("%s: shutting down\n",MODNAME);
	reference_monitor_off();

	//unregistering kprobes

	unregister_kprobe(&kp_open);

	unregister_kprobe(&kp_vfs_unlink);
	unregister_kprobe(&kp_mkdir);

	unregister_kprobe(&kp_vfs_rmdir);

	printk("%s: kprobes unregistered\n", MODNAME);
	unregister_chrdev(Major, DEVICE_NAME);
	printk(KERN_INFO "%s: device unregistered, it was assigned major number %d\n",DEVICE_NAME,Major);
	printk("%s: Module correctly removed\n", MODNAME);
	destroy_workqueue(queue); 
	printk("workqueue destroyed");    
}



