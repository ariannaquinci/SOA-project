#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#define NUM_THREADS 5
#define DIR_PATH "/home/arianna/try"

void *create_file(void *arg) {
    char filename[256];
    pid_t tgid = getpid();
    pthread_t tid = pthread_self();

    // Genera il nome del file usando il TID
    int num=rand()%100;
    snprintf(filename, sizeof(filename), "%s/file%d", DIR_PATH, num);

    // Crea il file
    FILE *file = fopen(filename, "w+");
    if (file != NULL) {
        printf("Thread %lu (TGID: %d) created file: %s\n", tid, tgid, filename);
        fclose(file); // Chiude il file dopo la creazione
    } else {
        perror("fopen failed");
    }

    pthread_exit(NULL);
}

int main() {
    pthread_t threads[NUM_THREADS];
    int i;

    // Crea i thread
    for (i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, create_file, NULL) != 0) {
            perror("Failed to create thread");
            exit(EXIT_FAILURE);
        }
    }

    // Unisci i thread
    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}

