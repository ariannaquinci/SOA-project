# Definizione delle variabili
CC = gcc
CFLAGS = -pthread

# File sorgente per ciascun programma
CONC_SRCS = conc.c
CONCURRENCY_TEST_SRCS = concurrency_test.c
CONCURRENT_OPEN_SRCS = concurrent_open.c
CONCURRENT_PATH_OPER_SRCS = concurrent_path_oper.c
RMDIR_CONC_SRCS = rmdir_conc.c
TEST_SRCS = test.c
TEST_FILE_SRCS = test-file.c
TEST_RMDIR_SRCS = test-rmdir.c
TEST_UNLINK_SRCS = test-unlink.c

# Nome dei programmi finali
CONC_PROGRAM = conc
CONCURRENCY_TEST_PROGRAM = concurrency_test
CONCURRENT_OPEN_PROGRAM = concurrent_open
CONCURRENT_PATH_OPER_PROGRAM = concurrent_path_oper
RMDIR_CONC_PROGRAM = rmdir_conc
TEST_PROGRAM = test
TEST_FILE_PROGRAM = test-file
TEST_RMDIR_PROGRAM = test-rmdir
TEST_UNLINK_PROGRAM = test-unlink

# Target predefinito, compila tutti i programmi
all: $(CONC_PROGRAM) $(CONCURRENCY_TEST_PROGRAM) $(CONCURRENT_OPEN_PROGRAM) $(CONCURRENT_PATH_OPER_PROGRAM) $(RMDIR_CONC_PROGRAM) $(TEST_PROGRAM) $(TEST_FILE_PROGRAM) $(TEST_RMDIR_PROGRAM) $(TEST_UNLINK_PROGRAM)

# Regole per generare i programmi
$(CONC_PROGRAM): $(CONC_SRCS)
	$(CC) $(CFLAGS) $^ -o $@

$(CONCURRENCY_TEST_PROGRAM): $(CONCURRENCY_TEST_SRCS)
	$(CC) $(CFLAGS) $^ -o $@

$(CONCURRENT_OPEN_PROGRAM): $(CONCURRENT_OPEN_SRCS)
	$(CC) $(CFLAGS) $^ -o $@

$(CONCURRENT_PATH_OPER_PROGRAM): $(CONCURRENT_PATH_OPER_SRCS)
	$(CC) $(CFLAGS) $^ -o $@

$(RMDIR_CONC_PROGRAM): $(RMDIR_CONC_SRCS)
	$(CC) $(CFLAGS) $^ -o $@

$(TEST_PROGRAM): $(TEST_SRCS)
	$(CC) $(CFLAGS) $^ -o $@

$(TEST_FILE_PROGRAM): $(TEST_FILE_SRCS)
	$(CC) $(CFLAGS) $^ -o $@

$(TEST_RMDIR_PROGRAM): $(TEST_RMDIR_SRCS)
	$(CC) $(CFLAGS) $^ -o $@

$(TEST_UNLINK_PROGRAM): $(TEST_UNLINK_SRCS)
	$(CC) $(CFLAGS) $^ -o $@

# Pulisce gli oggetti e i programmi
clean:
	$(RM) $(CONC_PROGRAM) $(CONCURRENCY_TEST_PROGRAM) $(CONCURRENT_OPEN_PROGRAM) $(CONCURRENT_PATH_OPER_PROGRAM) $(RMDIR_CONC_PROGRAM) $(TEST_PROGRAM) $(TEST_FILE_PROGRAM) $(TEST_RMDIR_PROGRAM) $(TEST_UNLINK_PROGRAM)

