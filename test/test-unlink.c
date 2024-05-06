#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define DEVICE_PATH "/dev/reference_monitor" 

int main() {
    int fd;
    ssize_t bytes_written;
     
    char path[100];
    printf("Enter path to add:\n");
    fgets(path, sizeof(path), stdin);
    path[strcspn(path, "\n")] = 0; 
    
 
    // open device
    fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open the device");
        return 1;
    }


    // ask user to provide pw
    char password[20];
    printf("Enter your password:\n");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0; // Rimuovi il newline
    
// state OFF
    char change_state_command[100];
    sprintf(change_state_command, "new_state OFF %s", password);
    bytes_written = write(fd, change_state_command, strlen(change_state_command));
    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        return 1;
    }


  //create a file in the directory to be put in blacklist
    char touch_command[200];
    
    sprintf(touch_command, "touch %s/file", path);
    
    system(touch_command);
    
    // state REC_ON
    sprintf(change_state_command, "new_state REC_ON %s", password);
    bytes_written = write(fd, change_state_command, strlen(change_state_command));
    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        return 1;
    }


    // add path to the blacklist
    char command[200];
    sprintf(command, "add_path %s %s", path, password);
    bytes_written = write(fd, command, strlen(command));
    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        return 1;
    }

   
    close(fd);

    // try to remove the file inserted
    char rm_command[200];
    sprintf(rm_command, "rm %s/file", path);
    system(rm_command);

    printf("Test completed successfully.\n");

    return 0;
}

