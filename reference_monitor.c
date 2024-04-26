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
#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>

//#include "reference_monitor_errors.h"

#define target_func0 "do_filp_open"
#define target_func1 "do_mkdirat"
#define target_func2 "do_rmdir"
#define target_func3 "do_unlinkat"
#define RECORD_SIZE 2*sizeof(pid_t)+2*sizeof(uid_t)+MAX_LEN+66


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


size_t my_min(size_t a , size_t b){
	if(a>=b){
		return b;
	}
	return a;
}
#define LINE_SIZE 256



bool check_passwd(char* pw){
	printk("checking pw");
	unsigned char *pw_digest;
	pw_digest=kmalloc(33,GFP_KERNEL);
	memset(pw_digest,0,33);
	int ret=0;
	printk("len is %d",strlen(pw));
	ret=do_sha256(pw, pw_digest,strlen(pw));
	if(ret!=0){
		printk(KERN_ERR "error in calculating sha256 of the password");
		return false;
	}
	if(strncmp(pw_digest, info.passwd, my_min(pw_digest, strlen(info.passwd)))==0){
		return true;
	}else{
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
	spinlock_t spin; 
	pid_t tgid;	//group identifier
	pid_t pid;	//thread identifier
	uid_t current_uid;
	uid_t current_euid; 
	char *program_path;
	char  content_hash[65];
};

static struct record record;


char *get_current_proc_path(char *buf, int buflen){
    struct file *exe_file;
    char *result = ERR_PTR(-ENOENT);
    struct mm_struct *mm;

    mm = get_task_mm(current);
    if (!mm) {
        goto out;
    }
    mmap_read_lock(mm);
    exe_file = mm->exe_file;
    if (exe_file) {
        get_file(exe_file);
        path_get(&exe_file->f_path);
    }
    mmap_read_unlock(mm);
    mmput(mm);
    if (exe_file) {
        result = d_path(&exe_file->f_path, buf, buflen);
        path_put(&exe_file->f_path);
        fput(exe_file);
    }

out:
    return result;
}

#define INITIAL_BUFFER_SIZE (8 * 1024) // 8 KB

ssize_t read_content(char * path, char *buf, size_t buflen) {
    struct file *filp;
    ssize_t ret = -EINVAL;
 
    // Apre il file eseguibile in modalità di sola lettura
    filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        printk(KERN_ERR "Failed to open executable file\n");
      
        return PTR_ERR(filp);
    }

    ret = kernel_read(filp, buf, buflen, 0);
    if (ret < 0) {
    	
        printk(KERN_ERR "Failed to read executable file\n");
    }

    // Chiude il file
    filp_close(filp, NULL);
    return ret;
}


int retrieve_informations(void){
	struct cred *cred=get_task_cred(current);
	
	record.tgid=current->tgid;
	record.pid=current->pid;
	record.current_uid = cred->uid.val;
	record.current_euid = cred->euid.val;
	char *buf=kmalloc(MAX_LEN,GFP_KERNEL);
	record.program_path=get_current_proc_path(buf, MAX_LEN);
	kfree(buf);
	
	
	char buffer[4096];
	int res=0;
	res=read_content(record.program_path, buffer,4096 );
	
	printk("res is %d and program content : %s",res, buffer);
	
	//questo va fatto in deferred work
	printk("buffer lenght is: %d", strlen(buffer));
	const  char hash_result[65];
	do_sha256(buffer, hash_result, strlen(buffer));
	 hash_to_string(hash_result, record.content_hash);
	
	printk("tgid: %d, pid: %d, current_uid: %d, current euid: %d, path: %s, hash: %s",record.tgid, record.pid, record.current_uid, record.current_euid, record.program_path,record.content_hash);
	return 0;
}


bool concatenate_record_to_buffer(char *buffer) {
    // Formatta ogni campo della struttura record come stringa e concatenali nel buffer
	
    if(snprintf(buffer, RECORD_SIZE, "%d %d %d %d %s %s\n",
             record.tgid, record.pid, record.current_uid, record.current_euid,
             record.program_path, record.content_hash)>0){
	return true;}
	return false;
}


bool write_append_only(void) {
    spin_lock(&record.spin);
    retrieve_informations();
  
    
    char line[RECORD_SIZE];
    struct file *file;
    loff_t pos = 0;
    
    file = filp_open(the_file, O_WRONLY | O_APPEND, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open the_file\n");
        spin_unlock(&record.spin);
        return false;
    }

    int ret = 0;
    if(concatenate_record_to_buffer(line)){
	    printk("Line to write is: %s", line);
	    printk("strlen is: %d", strlen(line));
	   ret = kernel_write(file,line, strlen(line),0);
	  printk("returned from write_iter: %d", ret); 
	    if (ret < strlen(line)) {
	    	printk("wrote only %d bytes", ret);
		printk(KERN_ERR "Failed to write the file\n");
		filp_close(file, NULL);
		spin_unlock(&record.spin);
		return false;
	    }

    }
    filp_close(file, NULL);
    spin_unlock(&record.spin);
    return true;
}
		
char *get_cwd(void){
	
	struct path abs_path;
    	char *buf;
    	
	buf = kmalloc(1024,GFP_KERNEL);
	if(buf == NULL) return "";

    	get_fs_pwd(current->fs, &abs_path);

    	return dentry_path_raw(abs_path.dentry, buf, PATH_MAX);
}

int temporal_file(const char *str) {
    size_t len = strlen(str);
    
    // Verifica se la lunghezza della stringa è maggiore di 0 e se l'ultimo carattere è '~'
    if (len > 0 && str[len - 1] == '~' ||
     len >4 &&	(str[len - 1]=='p' &&  str[len - 2]=='w' &&str[len - 3]=='s' &&str[len - 4]=='.')||
    	(len >5 && str[len - 1]=='x' && str[len - 2]=='p' && str[len - 3]=='w' &&str[len - 4]=='s' &&str[len - 6]=='.')) {
        return 1; // La stringa termina con '~'
    }
    
    return 0; // La stringa non termina con '~'
}

char * get_absolute_path_by_name(char *name) {

	struct path path;
	int err = kern_path(name, LOOKUP_FOLLOW, &path);
	if(err<0){
		printk(KERN_ERR "file doesn't exist");
		return NULL;
	}
	char *result= (char*)kmalloc(sizeof(char)*MAX_LEN,GFP_KERNEL);
	char* abs_path;
	if (!result) {
	printk(KERN_ERR "Error allocating memory for result");
	return NULL;
	}
	memset(result,0, MAX_LEN);
	if (!err) {
		// Ottieni il percorso assoluto utilizzando d_path()
		abs_path=d_path(&path, result, MAX_LEN);
		if (!result) {
			printk(KERN_ERR "error in d_path: cannot retrieve absolute path");
			kfree(result);
			return NULL;
		}
	} else {
		printk(KERN_ERR "error in kern_path");
		kfree(result);
		return NULL;
	}
    
	kfree(result);
	return abs_path;
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
    return parent;
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
			      
			        //calling the function that permits to write to the append-only file
			        
			        if(!write_append_only()){
			        	printk("Impossible to append content to the file");
			        	return -1;
			        }
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
			         //calling the function that permits to write to the append-only file
			        if(!write_append_only()){
			        	printk("Impossible to append content to the file");
			        	return -1;
			        }
			        
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
			       
			        if(! write_append_only()){
			        	printk("Impossible to write append only");
			        	return -1;
			        }
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
				
				directory=get_cwd();
				while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0 ){
                		
				   if (checkBlacklist(directory) == -EPERM ) {
				        printk(KERN_ERR "Error: path or its parent directory is in blacklist: %s",directory);
				        //calling the function that permits to write to the append-only file
			       	 if(!write_append_only()){
			        	printk("Impossible to append content to the file");
			        	return -1;
			        }
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
			       if(!write_append_only()){
			        	printk("Impossible to append content to the file");
			        	return -1;
			        }
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
	
};

static struct kretprobe kp_mkdir = {
	 .handler = post_handler,
        .entry_handler =do_mkdirat_wrapper,
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


