#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define DEVICE_PATH "/dev/reference_monitor"

int main(void) {
    int fd;
    ssize_t bytes_written;

    fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open the device");
        return 1;
    }


    
    char password[20];
    printf("Enter your password:\n");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;
    
//change state in REC_ON
    char change_state_command[100];
    sprintf(change_state_command, "new_state REC_ON %s", password);
    bytes_written = write(fd, change_state_command, strlen(change_state_command));
    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        return 1;
    }

    char path[100];
    printf("Enter path to add:\n");
    fgets(path, sizeof(path), stdin);
    path[strcspn(path, "\n")] = 0; // remove newline char

    char command[200];
    sprintf(command, "add_path %s %s", path, password);
    bytes_written = write(fd, command, strlen(command));
    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        return 1;
    }

    close(fd);

    char file_path[200];
    sprintf(file_path, "%s/test_file", path);
    FILE *file = fopen(file_path, "w");
    if (file == NULL) {
        perror("Failed to create file");
        return 1;
    }
    fprintf(file, "This is a test file.");
    fclose(file);
  
     
    printf("Test completed successfully.\n");

    return 0;
}

