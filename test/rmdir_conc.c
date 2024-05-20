#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#define DEVICE_PATH "/dev/reference_monitor" // Percorso del dispositivo nel sistema

void* delete_directory(void* arg) {
    char* path = (char*)arg;
    char command[200];
    sprintf(command, "rmdir -p %s", path);
    system(command);
    return NULL;
}

int main() {
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

    for (int i = 0; i < 5; ++i) {
        char mkdir_command[200];
        sprintf(mkdir_command, "mkdir -p %s/test_directory%d", path, i);
        system(mkdir_command);
    }
   
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

    // Avvia 5 thread per eliminare le directory
    pthread_t threads[5];
    char* dirs[5];
    for (int i = 0; i < 5; ++i) {
        dirs[i] = malloc(128);
        if (dirs[i] == NULL) {
            perror("Failed to allocate memory");
            return 1;
        }
        sprintf(dirs[i], "%s/test_directory%d", path, i);
        pthread_create(&threads[i], NULL, delete_directory, (void*)dirs[i]);
    }

    // Attendere che tutti i thread terminino
    for (int i = 0; i < 5; ++i) {
        pthread_join(threads[i], NULL);
        free(dirs[i]); // Libera la memoria allocata per ogni percorso
    }

    printf("Test completed successfully.\n");

    return 0;
}

