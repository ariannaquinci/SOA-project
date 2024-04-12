#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define DEVICE_PATH "/dev/reference_monitor" // Percorso del dispositivo nel sistema

int main(int argc, char *argv[]) {
    int fd;
    
    ssize_t bytes_written;
	printf("argc=%d",argc);
    if(argc<4){
    	printf("Insufficient number of parameters passed\n");
    	
    	printf("try again doing this:\n\t-sudo ./user new_state <STATE> <your password>\n\t-sudo ./user change_pw <new password> <old password>\n\t-sudo ./user add_path <new path> <your password>\n\t-sudo ./user remove_path <path to remove> <your password>\n");
    	return 1;
    }
	
	
    // Apri il dispositivo
    fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open the device");
        return 1;
    }

    char args[strlen(argv[1]) + strlen(argv[2]) + strlen(argv[3])+3]; // 3 per lo spazio e il terminatore di stringa
    sprintf(args, "%s %s %s", argv[1], argv[2], argv[3]);
    
    bytes_written = write(fd, args, strlen(args));
    
    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        return 1;
    }


    // Chiudi il dispositivo
    close(fd);

    return 0;
}

