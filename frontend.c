#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define DEVICE_PATH "/dev/reference_monitor" // Percorso del dispositivo nel sistema

int main() {
    int fd;
    ssize_t bytes_written;

    char command[100];
    printf("Enter command:\n");
    printf("\t- To change state: new_state <STATE> <your password>\n");
    printf("\t- To change password: change_pw <new password> <old password>\n");
    printf("\t- To add path: add_path <new path> <your password>\n");
    printf("\t- To remove path: remove_path <path to remove> <your password>\n");
   
    fgets(command, sizeof(command), stdin);

    // Rimuovi il newline inserito da fgets
    command[strcspn(command, "\n")] = 0;

    // Apri il dispositivo
    fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open the device");
        return 1;
    }

    bytes_written = write(fd, command, strlen(command));

    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        return 1;
    }

    // Chiudi il dispositivo
    close(fd);

    return 0;
}

