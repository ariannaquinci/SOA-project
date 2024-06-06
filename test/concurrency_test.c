#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#define DEVICE_PATH "/dev/reference_monitor" // Percorso del dispositivo nel sistema
#define NUM_THREADS 5

const char *states[] = {"ON", "REC_ON", "REC_OFF", "OFF"};

void *perform_operation(void *args) {
    char *operation = (char *)args;
    int fd;
    ssize_t bytes_written;

    // Apri il dispositivo
    fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open the device");
        pthread_exit(NULL);
    }

    printf("Thread %ld: %s\n", pthread_self(), operation);
    bytes_written = write(fd, operation, strlen(operation));
    
    if (bytes_written < 0) {
        perror("Failed to write to the device");
    }

    // Chiudi il dispositivo
    close(fd);

    // Libera la memoria allocata per operation
    free(operation);

    pthread_exit(NULL);
}

int main(void) {
    pthread_t threads[NUM_THREADS];
    int i;

    // Inizializza il generatore di numeri casuali con un seed diverso per ogni esecuzione
    srand(time(NULL));
    char password[20];
    printf("Insert password to run the test\n");
    fgets(password, sizeof(password), stdin);
    // Rimuovi il newline inserito da fgets
    password[strcspn(password, "\n")] = 0;

    for (i = 0; i < NUM_THREADS; i++) {
        // Crea la stringa operation per ogni thread e alloca memoria dinamicamente
        char *operation = malloc(100 * sizeof(char));
        if (operation == NULL) {
            perror("Failed to allocate memory");
            exit(EXIT_FAILURE);
        }

        sprintf(operation, "%s %s %s", "new_state", states[rand() % 4], password);

        pthread_create(&threads[i], NULL, perform_operation, (void *)operation);
    }

    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}

