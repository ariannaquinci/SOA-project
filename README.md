# SOA-project
Developement of: https://francescoquaglia.github.io/TEACHING/AOS/CURRENT/PROJECTS/project-specification-2023-2024.html

In order to interact with the reference monitor you need to provide the password, the default one is "changeme".
To interact with the reference monitor you can use both:
- sudo ./frontend 
- sudo ./user with this sintax: (PLEASE IF YOUR PASSWORD CONTAINS SPECIAL CHARACTERS (e.g. !) INSERT A \ BEFORE EACH ONE)
	- sudo ./user new_state <STATE> <your password>
	- sudo ./user change_pw <new password> <old password> 
	- sudo ./user add_path <new path> <your password>
	- sudo ./user remove_path <path to remove> <your password>

In the directory "test" you'll find some test:
- concurrency_test.c contains tests to perform concurrent state changes of the RM by several threads. It will ask you to insert the password.
- test.c let inserts a directory in the blacklist and tries to create a directory in it.
- test-file.c inserts a directory in the blacklist and, after creating a file in it tries to open it in write mode.
- test-rmdir creates a directory into the path that will be inserted into blacklist then it tries to remove it.
- test-unlink like test-rmdir but instead of a diretcory it creates and deletes a file.


	
