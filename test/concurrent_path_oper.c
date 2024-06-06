#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#define NUM_THREADS 10
#define DIR_PATH "/home/arianna/try"

void *create_directory(void *arg) {
    char dirname[256];
    pid_t tgid = getpid();
    pthread_t tid = pthread_self();

    // Genera il nome della directory usando il TID
    snprintf(dirname, sizeof(dirname), "%s/newdir%d", DIR_PATH,rand());

    // Crea la directory
    if (mkdir(dirname, 0777) == 0) {
        printf("Thread %lu (TGID: %d) created directory: %s\n", tid, tgid, dirname);
    } else {
        perror("mkdir failed");
    }

    pthread_exit(NULL);
}

int main(void) {
    pthread_t threads[NUM_THREADS];
    int i;

  
    // Crea i thread
    for (i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, create_directory, NULL) != 0) {
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

