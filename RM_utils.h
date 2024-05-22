#include <linux/string.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/user_namespace.h>


#define MODNAME "Reference monitor"
#define RECORD_SIZE 2*sizeof(pid_t)+2*sizeof(uid_t)+MAX_LEN+66

#define MAX_BUFFER_SIZE 66
#define MAX_LEN 2048
#define MAX_PATHS 128
#define PASS_LEN 20
#define MAX_PARENTS 10
#define  MAX_ACTIVE_KRETPROBES 500

#define LINE_SIZE 256


size_t my_min(size_t a , size_t b){
	if(a>=b){
		return b;
	}
	return a;
}
char *get_current_proc_path(void) {
    char *buf = kmalloc(MAX_LEN, GFP_KERNEL);
    if (!buf) {
        printk("Impossible to allocate space for buf");
        return ERR_PTR(-ENOMEM);
    }

    struct file *exe_file = NULL;
    char *result = NULL;
    struct mm_struct *mm = get_task_mm(current);
    if (!mm) {
        printk("Failed to get mm_struct");
        kfree(buf);
        return ERR_PTR(-ENOENT);
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
        result = d_path(&exe_file->f_path, buf, MAX_LEN);
        path_put(&exe_file->f_path);
        fput(exe_file);
    }

    kfree(buf);

    return result;
}

ssize_t read_content(char * path, char *buf, size_t buflen) {
    struct file *filp;
    ssize_t ret = -EINVAL;
 
    // Apre il file eseguibile in modalità di sola lettura
    filp = filp_open(path, O_RDONLY,0);
    if (IS_ERR(filp)) {
        printk(KERN_ERR "Failed to open executable file\n");
      
        return PTR_ERR(filp);
    }

    ret = kernel_read(filp, buf, buflen,0);
    if (ret < 0) {
    	
        printk(KERN_ERR "Failed to read executable file\n");
    }
    

    // Chiude il file
    filp_close(filp, NULL);
    return ret;
}


	
char *get_cwd(void){
	printk("into get_cwd");
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

char *get_absolute_path(const struct path *path) {
    char *buf;
    char *full_path;

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf) {
        printk(KERN_ERR "Failed to allocate space for buffer");
        return NULL;
    }

    full_path = dentry_path_raw(path->dentry, buf, PATH_MAX);
    if (IS_ERR(full_path)) {
        printk(KERN_ERR "Failed to get dentry path");
        kfree(buf);
        return NULL;
    }
    kfree(buf);
    return full_path;
}




char * get_absolute_path_by_name(char *name) {

	struct path path;
	int err = kern_path(name, LOOKUP_FOLLOW, &path);
	if(err<0){
		
		return NULL;
	}
	char *result= (char*)kmalloc(sizeof(char)*PATH_MAX,GFP_KERNEL);
	char* abs_path;
	if (!result) {
	printk(KERN_ERR "Error allocating memory for result");
	return NULL;
	}
	memset(result,0, PATH_MAX);
	if (!err) {
		// Ottieni il percorso assoluto utilizzando d_path()
		abs_path=d_path(&path, result, PATH_MAX);
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

// Create a restricted user namespace
struct user_namespace *create_restricted_user_ns(void) {
    struct user_namespace *new_ns;
    struct cred *new_cred;

    new_ns = kzalloc(sizeof(struct user_namespace), GFP_KERNEL);
    if (!new_ns) {
        printk(KERN_ALERT "Failed to allocate memory for user namespace\n");
        return ERR_PTR(-ENOMEM);
    }

    // Initialize the user namespace structure
    *new_ns = (struct user_namespace){
        .parent = current_user_ns(),
        .level = current_user_ns()->level + 1,
        .owner = current_uid(),
        .group = current_gid(),
    };

    // Restrict the new user namespace
    new_ns->uid_map.nr_extents = 0;
    new_ns->gid_map.nr_extents = 0;

    // Optionally, set other fields to restrict permissions further
    // new_ns->flags = ...

    return new_ns;
}

