#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/scatterlist.h>
#include <linux/fs_struct.h>
#include <linux/mm_types.h>

#include <linux/dcache.h>


#include "my_crypto.h"
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
#include <linux/syscalls.h> i
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>

#include "RM_utils.h"

#define target_func0 "do_filp_open"
#define target_func1 "do_mkdirat"
#define target_func2 "do_rmdir"
#define target_func3 "do_unlinkat"

#define AUDIT if(1)open

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("see the README file");



#define DEVICE_NAME "/dev/reference_monitor"  /* Device file name in /dev/ */

#define BUFFER_SIZE (16 * 1024) // 16 KB

static ssize_t RM_write(struct file *, const char *, size_t, loff_t *);


static int Major;            /* Major number assigned to reference monitor device driver */

static char *the_file;

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
	spinlock_t spinlock; 
}RM_info;

static RM_info info;



bool check_passwd(char* pw){
	printk("checking pw");
	spin_lock(&info.spinlock);
	unsigned char *pw_digest;
	pw_digest=kmalloc(33,GFP_KERNEL);
	memset(pw_digest,0,33);
	int ret=0;
	printk("len is %d",strlen(pw));
	ret=do_sha256(pw, pw_digest,strlen(pw));
	if(ret!=0){
		printk(KERN_ERR "error in calculating sha256 of the password");
		spin_unlock(&info.spinlock);
		return false;
	}
	if(strncmp(pw_digest, info.passwd, my_min(pw_digest, strlen(info.passwd)))==0){
	spin_unlock(&info.spinlock);
		return true;
	}else{spin_unlock(&info.spinlock);
		return false;
	}
}


int RM_change_pw(char *new){
	printk("into change password");
	spin_lock(&info.spinlock);
	if(strlen(new)> PASS_LEN-1){ printk(KERN_ERR "too long password"); spin_unlock(&info.spinlock); return -1;}
	printk("len is %d", strlen(new));
	do_sha256(new, info.passwd, strlen(new));
	
	spin_unlock(&info.spinlock);
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

	   
	    printk("strlen is: %d", strlen(line));
	   ret = kernel_write(file,line, strlen(line),&pos);
	  printk("returned from write_iter: %d", ret); 
	    if (ret < strlen(line)) {
	    	printk("wrote only %d bytes", ret);
		printk(KERN_ERR "Failed to write the file\n");
		filp_close(file, NULL);
		
		return false;
	    }

    printk("\n%s: File \"the_file\" written with line: %s\n", MODNAME,line );
    filp_close(file, NULL);
  
    return true;
}
void do_deferred_work(struct work_struct *work) {
    deferred_work_data *data = container_of(work, deferred_work_data, work);
    char hash_result[66];
    
    char buffer[4096];
    char line[RECORD_SIZE];
    int res = 0;
   printk("do_deferred_work: pid data->deferred_record: %d,tgid data->deferred_record: %d, uid data->deferred_record: %d , euid data->deferred_record: %dpath in data->deferred_record is %s",  
   data->deferred_record.pid,data->deferred_record.tgid,data->deferred_record.current_uid, data->deferred_record.current_euid, data->deferred_record.program_path); 
    res = read_content(data->deferred_record.program_path, buffer, 4096);
    if (res < 0) {
        printk(KERN_ERR "Impossible to read content");
        return;
    }
    // Esegui il calcolo dell'hash
    do_sha256(buffer, hash_result, 4096);
    hash_to_string(hash_result, data->deferred_record.content_hash);
    //scrivo su file
    if (concatenate_record_to_buffer(data, line)) {
        if(!write_append_only(line)){printk(KERN_ERR "impossible to write append only");}
       
        return;
    }
}
void schedule_deferred_work(void) {
    struct workqueue_struct *queue;
    deferred_work_data *data;

    // Crea la coda di lavoro
    queue = create_singlethread_workqueue("recording_queue");
    if (!queue) {
        printk(KERN_ERR "Failed to create work queue\n");
        return;
    }

    // Alloca memoria per i dati
    data = kzalloc(sizeof(deferred_work_data), GFP_KERNEL);
    if (!data) {
        printk(KERN_ERR "Failed to allocate memory for deferred work\n");
        destroy_workqueue(queue); // Libera la coda di lavoro
        return;
    }

    struct cred *cred = get_task_cred(current);

    data->deferred_record.tgid = current->tgid;
    data->deferred_record.pid = current->pid;
    data->deferred_record.current_uid = cred->uid.val;
    data->deferred_record.current_euid = cred->euid.val;
    char *buf = kmalloc(MAX_LEN, GFP_KERNEL);
    if (!buf) {
        printk("Impossible to allocate space for buf");
        kfree(data); // Libera la memoria allocata per i dati
        destroy_workqueue(queue); // Libera la coda di lavoro
        return;
    }

    char *path = get_current_proc_path(buf, MAX_LEN);
    if (IS_ERR(path)) {
        printk(KERN_ERR "Failed to retrieve process path\n");
        kfree(data); // Libera la memoria allocata per i dati
        kfree(buf);
        destroy_workqueue(queue); // Libera la coda di lavoro
        return;
    }

    // Copia il percorso nel campo program_path dei dati differiti
    strncpy(data->deferred_record.program_path, path, MAX_LEN);
    kfree(buf); // Libera il buffer utilizzato per il percorso

    printk("schedule_deferred_work: pid %d, tgid %d, uid %d, euid %d, path %s\n",
           data->deferred_record.pid, data->deferred_record.tgid,
           data->deferred_record.current_uid, data->deferred_record.current_euid,
           data->deferred_record.program_path);

    // Inizializza il lavoro differito
    INIT_WORK(&(data->work), do_deferred_work);

    // Accoda il lavoro alla coda di lavoro
    queue_work(queue, &(data->work));

    // Libera la memoria allocata per i dati dopo che il lavoro è stato accodato
    // poiché i dati non sono più necessari dopo l'accodamento
    //kfree(data);
}


int RM_add_path(char *new_path){
	spin_lock(&info.spinlock);
	//check if status is reconfigurable, otherwise exit without applying changes
	if(info.state==ON || info.state==OFF){
		spin_unlock(&info.spinlock);
		printk(KERN_ERR "impossible to change blacklist because monitor status is not reconfigurable");
		return -1;
	}
	
	
    	
    	char * abs_path;
    	abs_path=get_absolute_path_by_name(new_path);
    	if(abs_path==NULL){
    		printk(KERN_ERR "file doesn't exist");
    		spin_unlock(&info.spinlock);
    		return -1;
    	}
    	
	//check if path is already present in blacklist
	int i;
    	for(i=1; i<=info.pos; i++){
    		
		if(strcmp(info.blacklist[i], abs_path)==0){
			printk("element already in blacklist");
			spin_unlock(&info.spinlock);
			return -1;
		}
	}
	
	if(strlen(abs_path)+1> MAX_LEN){
		printk(KERN_ERR "path is too long"); 
		spin_unlock(&info.spinlock); 
		return -1;
	}
	strncpy(info.blacklist[++info.pos],strcat(abs_path,"\0"), strlen(abs_path)+1);	
	
	spin_unlock(&info.spinlock);
	return 0;
		
}
int RM_remove_path(char * path){
	spin_lock(&info.spinlock);
	struct file *f;
	char* abs_path=get_absolute_path_by_name(path);
	if(abs_path==NULL){
    		printk(KERN_ERR "file doesn't exist");
    		spin_unlock(&info.spinlock);
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
			spin_unlock(&info.spinlock);
			return 0;
		}
	}
	printk(KERN_ERR "No such file in blacklist");
	spin_unlock(&info.spinlock);
	return 0;
}


int checkBlacklist(char* open_path){
	//checking blacklist
	spin_lock(&info.spinlock);
	if (open_path==NULL){
	
		return -1;
	}
	
	int i;
	for(i=1; i<=info.pos; i++){
		if(strcmp(info.blacklist[i], open_path)==0){
			spin_unlock(&info.spinlock);
			return -EPERM;
		}
	}
	spin_unlock(&info.spinlock);
	return 0;
}
struct my_data{
	unsigned long dfd;
};

static int do_mkdirat_wrapper(struct kretprobe_instance *ri, struct pt_regs *regs){
		
switch(info.state){	
		char *directory;
		char*name; 
		char* abs_path;
		memset(abs_path,0,MAX_LEN);
		
		
		case(OFF):
		case(REC_OFF):
			//if RM is OFF or REC_OFF return immediately
			
			break;
		case(ON):
		case(REC_ON):
			printk("into mkdir wrapper");	
			
			name=((struct filename *)(regs->si))->name;
			
			//retrieve the parent and get its absolute path
			name= custom_dirname(name);
			abs_path=get_absolute_path_by_name(name);
			if(abs_path==NULL){
				directory=get_cwd();
			}else{
				directory=abs_path;
			}
			while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0 ){
        			printk("directory is %s",directory);
			   if (checkBlacklist(directory) == -EPERM ) {
			        printk(KERN_ERR "Error: path or its parent directory is in blacklist: %s",directory);
			      
    				//retrieve_informations();
    				schedule_deferred_work();
			       
			      	struct my_data *data;
			        data = (struct my_data *)ri->data;
			        data->dfd = regs->di;
			        printk("dfd is %ld",regs->di );
			      regs->di=-1000;
			        return 0;
			    }
			    // Get the parent directory
			    directory = custom_dirname(directory);
			   
			   
			     
        		}
                default:
			
			break;
		}
	
	
	
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
		printk("Into rmdir wrapper");
				memset(result, 0, MAX_LEN);
			//things to do when RM is ON or REC_ON
			//check if path has been opened in write mode
			
			name= ((struct filename *)(regs->si))->name;
			 if (IS_ERR(name)) {
				pr_err("Error getting filename\n");
				return 0;
	    		}
	    		
				 
			abs_path=get_absolute_path_by_name(name);
	
	
			
			 char *directory = abs_path;
        		while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0 ){
        		
			printk("Into rmdir wrapper; path is: %s", directory);
			   if (checkBlacklist(directory) == -EPERM ) {
			        printk(KERN_ERR "Error: path or its parent directory is in blacklist: %s",directory);
			   //     retrieve_informations();
			     schedule_deferred_work();   
			        struct my_data *data;
			        data = (struct my_data *)ri->data;
			        data->dfd = regs->di;
			        regs->di=NULL;
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
			
			 if (IS_ERR(name)) {
				pr_err(KERN_ERR "Error getting filename\n");
				return 0;
	    		}
	    		if(temporal_file(name)){
	    			return 0;
	    		}
				 
			abs_path=get_absolute_path_by_name(name);
			
			 char *directory = abs_path;
        		while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0 ){
        		
			   if (checkBlacklist(directory) == -EPERM ) {
			        printk(KERN_ERR "Error: path or its parent directory is in blacklist: %s",directory);
			         //calling the function that permits to write to the append-only file
			       
			     // retrieve_informations();
			     schedule_deferred_work();
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
				pr_err(KERN_ERR "Error getting filename\n");
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
			unsigned long fd;
			fd= regs->di;
			char *directory;
			abs_path=get_absolute_path_by_name(name);
			if(open_mode & O_CREAT && abs_path==NULL){
				char* path;
				directory=get_cwd();
				//if file doesn't exist yet I take its parent directory and retrieve the absolute path
				path=custom_dirname(name);
				
				path=get_absolute_path_by_name(path);
				if(path!=NULL){
					directory=path;}
				while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0 ){
                		
				   if (checkBlacklist(directory) == -EPERM ) {
				        printk(KERN_ERR "Error: path or its parent directory is in blacklist: %s",directory);
				        //calling the function that permits to write to the append-only file
			       	//retrieve_informations();
				        schedule_deferred_work();
				        if(open_mode & O_CREAT){flags->open_flag&=~O_CREAT;}
				        if(open_mode & O_RDWR){flags->open_flag&=~O_RDWR;}
				        if(open_mode &O_WRONLY){flags->open_flag&=~O_WRONLY;}
				     	flags->open_flag&= O_RDONLY;
				        return 0;
				    }
				    // Get the parent directory
				    directory = custom_dirname(directory);
				   
				   
				     
                	}
					
			}
			else if(open_mode & O_CREAT || open_mode & O_RDWR || open_mode & O_WRONLY) {
				
				abs_path=get_absolute_path_by_name(name);
				
				directory = abs_path;
				while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0 ){
                		
				   if (checkBlacklist(directory) == -EPERM ) {
				        printk(KERN_ERR "Error: path or its parent directory is in blacklist: %s",directory);
				         //calling the function that permits to write to the append-only file
			 //      retrieve_informations();
			schedule_deferred_work();
				       struct my_data *data;
				        data = (struct my_data *)ri->data;
				        data->dfd = regs->di;
				        printk("dfd is %ld",regs->di );
				        return 0;
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
		printk("dfd is %ld", data->dfd);
		regs->ax=-EPERM;
		data->dfd=0;
	}
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
	 .maxactive = 10000,
	
};

static struct kretprobe kp_mkdir = {
	 .handler = post_handler,
        .entry_handler =do_mkdirat_wrapper,
         .maxactive =10000,
};


static struct kretprobe kp_rmdir = {
 
       .handler = post_handler,
        .entry_handler = do_rmdir_wrapper,
         .maxactive =10000,
};


static struct kretprobe kp_unlink = {
        .handler = post_handler,
        .entry_handler = do_unlinkat_wrapper,
        .data_size=sizeof(struct my_data),
         .maxactive =10000,
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
  	if(check_passwd(args[2])){
	//if(strcmp(args[2],info.passwd)==0){
		
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
					
					reference_monitor_rec_on();
			}else{
				printk("Invalid argument");
			}
		}
		if(strcmp(args[0],"change_pw")==0){
			printk("arg is change password");
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
	do_sha256("changeme", info.passwd,strlen("changeme"));
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

module_param(the_file, charp, 0660);


