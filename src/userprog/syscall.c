#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

node_t *head;
int nextFileId = 0;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&fs_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	typedef int syscall_function(int, int, int);
	/*A system call*/
	struct syscall {
		size_t arg_cnt; /*Number of arguements*/
		syscall_function *func; /*Implementation*/
	};
	/*Table of system calls*/
	static const struct syscall syscall_table[] = {
		{0, (syscall_function *) sys_halt},
		{1, (syscall_function *) sys_exit},
		{1, (syscall_function *) sys_exec},
		{1, (syscall_function *) sys_wait},
		{2, (syscall_function *) sys_create},
		{1, (syscall_function *) sys_remove},
		{1, (syscall_function *) sys_open},
		{1, (syscall_function *) sys_filesize},
		{3, (syscall_function *) sys_read},
		{3, (syscall_function *) sys_write},
		{2, (syscall_function *) sys_seek},
		{1, (syscall_function *) sys_tell},
		{1, (syscall_function *) sys_close}
	};

	const struct syscall *sc;
	unsigned call_nr;
	int args[3];

	/* Get the system call */
	copy_in(&call_nr, f->esp, sizeof call_nr);
	if (call_nr >= sizeof syscall_table / sizeof *syscall_table)
		thread_exit();
	sc = syscall_table + call_nr;

	/* Get the system call arguments */
	ASSERT(sc->arg_cnt <= sizeof args / sizeof *args);
	memset(args, 0, sizeof args);
	copy_in(args, (uint32_t *)f->esp + 1, sizeof *args * sc->arg_cnt);
	
	/* Execute the system call and set the return value */
	f->eax = sc->func(args[0], args[1], args[2]);
}

/* Halt system call */
static void
sys_halt(void) {
	shutdown_power_off();
}

/* Exit system call */
static void
sys_exit(int status) {
	// TODO
}

/* Execute system call */
static pid_t
sys_exec(const char *cmd_line) {
	if(process_execute(cmd_line) == TID_ERROR) {
		return -1;
	}
}

/* Wait system call */
static int
sys_wait(pid_t pid) {
	//TODO
}

/* Create system call */
static bool
sys_create(const char *file, unsigned initial_size) {
	bool result = filesys_create(file, initial_size);
	if(result) {
		add_new_file_to_list(file);
	}
	return result;
}

/* Remove system call */
static bool
sys_remove(const char *file) {
	bool result = filesys_remove(file);
	if(result) {
		remove_elem_from_list(file);
	}
	return result;
}

/* Open system call */
static int
sys_open(const char *ufile) {
	char *kfile = copy_in_string(ufile);
	struct file_descriptor *fd;
	int handle = -1;

	fd = malloc(sizeof *fd);
	if (fd != NULL) {
		lock_acquire(&fs_lock);
		fd->file = filesys_open(kfile);
		if(fd->file != NULL) {
			//add to list of fd's associated with thread
		}
	}
}

/* Get file size system call */
static int
sys_filesize(int fd) {
	struct file_elem elem = find_file_info(fd);
	if(elem.name != NULL) {
		return file_size(elem.file_info.file);
	}
	return 0;
}

/* Read system call */
static int
sys_read(int fd, void *buffer, unsigned size) {
	struct file_elem elem = find_file_info(fd);
	if(elem.name != NULL) {	
		return file_read(elem.name, buffer, size);
	}
	return 0;
}

/* Write system call */
static int
sys_write(int fd, const void *buffer, unsigned size) {
	struct file_elem elem = find_file_info(fd);
	if(elem.name != NULL) {
		return file_write(elem.name, buffer, size);
	}
	return 0;
}

/* Seek system call */
static void
sys_seek(int fd, unsigned position) {
	struct file_elem elem = find_file_info(fd);
	if(elem.name != NULL) {
		return file_seek(elem.name, position);
	}
}

/* Tell system call */
static unsigned
sys_tell(int fd) {
	struct file_elem elem = find_file_info(fd);
	if(elem.name != NULL) {
		return file_tell(elem.name);
	}
	return 0;
}

/* Close system call */
static void
sys_close(int fd) {
	// TODO
}

/* Add new file to file list */
void
add_new_file_to_list(const char *name) {
	head = malloc(sizeof(node_t));
	if(head == NULL) {
		return;
	}

	head->elem = create_file_elem(name);
	head->next = NULL;
}

/* Find file in linked list */
struct file_elem
find_file_info(int id) {
	node_t *current = head;
	while(current->next != NULL) {
		if(current->elem.file_info.file == id) {
			return current->elem;
		}
		current = current->next;
	}

	return create_file_elem(NULL);
}

/* Add new file element to end of linked list */
void
add_file_to_end(const char *name) {
	node_t *current = head;

	/* Get to end of list */
	while(current->next != NULL) {
		current = current->next;
	}

	/* Add new elem */
	current->next = malloc(sizeof(node_t));
	current->next->elem = create_file_elem(name);
	current->next->next = NULL;
}

/* Create new file element */
struct file_elem
create_file_elem(const char *name) {
	/* Create elem */
	struct file_elem elem;
	elem.file_info.file = nextFileId;
	elem.name = name;

	/* Update index */
	nextFileId++;

	return elem;
}

/* Remove elem by id */
void
remove_elem_from_list(int id) {
	node_t *current = head;

	while(current->next != NULL) {
		if(current->elem.file_info.file == id) {
			break;
		}
		current = current->next;
	}

	if(current->next == NULL) {
		return;
	}

	node_t *temp = current->next;
	current->next = temp->next;
	free(temp);
}
