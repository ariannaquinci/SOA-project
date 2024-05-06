#include <stdio.h>
#include <pthread.h>

#define NUM_THREADS 10

int open_attempts = 0;

void *open_file(void *thread_id) {
    int id = *(int *)thread_id;
    FILE *file;
    open_attempts++;
    char name[100];
    sprintf(name,"/home/arianna/try/example%d", id); 
    file = fopen(name, "w+");
    if (file == NULL) {
        printf("Thread %d failed to open file.\n", id);
    } else {
        fprintf(file, "Thread %d successfully opened file.\n", id);
        
        fclose(file);
    }
    pthread_exit(NULL);
}

int main() {
    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];
    int i;

    for (i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, open_file, (void *)&thread_ids[i]);
    }

    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("All threads have completed opening attempts.\n");
    printf("Total attempts to open file: %d\n", open_attempts);


    return 0;
}

