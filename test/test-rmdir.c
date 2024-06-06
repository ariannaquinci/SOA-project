#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define DEVICE_PATH "/dev/reference_monitor" // Percorso del dispositivo nel sistema

int main(void) {
    int fd;
    ssize_t bytes_written;
     
    char path[100];
    printf("Enter path to add:\n");
    fgets(path, sizeof(path), stdin);
    path[strcspn(path, "\n")] = 0;    
    

    fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open the device");
        return 1;
    }

    char password[20];
    printf("Enter your password:\n");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;
    
    char change_state_command[100];
    sprintf(change_state_command, "new_state OFF %s", password);
    bytes_written = write(fd, change_state_command, strlen(change_state_command));
    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        return 1;
    }
    char mkdir_command[200];
    
    sprintf(mkdir_command, "mkdir -p %s/test_directory", path);
    system(mkdir_command);
    
   
    sprintf(change_state_command, "new_state REC_ON %s", password);
    bytes_written = write(fd, change_state_command, strlen(change_state_command));
    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        return 1;
    }

    char command[200];
    sprintf(command, "add_path %s %s", path, password);
    bytes_written = write(fd, command, strlen(command));
    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        return 1;
    }
    close(fd);

    char rmdir_command[200];
    sprintf(rmdir_command, "rmdir -p %s/test_directory", path);
    system(rmdir_command);

    
     

    printf("Test completed successfully.\n");

    return 0;
}

