#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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

	/* Verify pointers are valid */
	for(int i = 0; i < 4; i++) {
		if(check_valid_addr(f->esp + i)) {
			thread_exit();
		}
	}

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

/* Check if given memory address is valid */
bool
check_valid_addr(uint32_t *addr) {
	return (addr != NULL) && is_user_vaddr(addr);
}

/* Copy a certain section of memory from the user space to the kernel space */
void
copy_in(unsigned *var, uint32_t *start, int size) {
	for(int i = 0; i < (size / 4); i++) {
		/* Inspiration from: https://github.com/ryantimwilson/Pintos-Project-2/blob/master/src/userprog/syscall.c */
		int *ptr = (int *) start + i;
		//check_valid_ptr((const void *) ptr);
		var[i] = *ptr;
	}
}

/* Copy a string from user space to kernel space */
char *
copy_in_string(const char *uname) {
	return uname;
}

/* Terminate Pintos */
static void
sys_halt(void) {
	shutdown_power_off();
}

/* Terminate current user process */
static void
sys_exit(int status) {
	struct thread *cur = current_thread();
	printf("%s: exit(%d)\n", cur->name, status);
	process_exit();
}

/* Run given executable */
static pid_t
sys_exec(const char *cmd_line) {
	if(process_execute(cmd_line) == TID_ERROR) {
		return -1;
	}
}

/* Wait for child process */
static int
sys_wait(pid_t pid) {
	//TODO
}

/* Create new file */
static bool
sys_create(const char *file, unsigned initial_size) {
	return filesys_create(file, initial_size);
}

/* Remove file with given name */
static bool
sys_remove(const char *file) {
	bool result = filesys_remove(file);
	if(result) {
		remove_file_node(file);
	}
	return result;
}

/* Open file with given name */
static int
sys_open(const char *ufile) {
	char *kfile = copy_in_string(ufile);
	struct file_descriptor *fd;
	int handle = -1;

	/* Update file_descriptor for relevant file */
	fd = malloc(sizeof *fd);
	if (fd != NULL) {
		lock_acquire(&fs_lock);
		fd->id = nextFileId;
		fd->file = filesys_open(kfile);
		if(fd->file != NULL) {
			update_file_list(ufile, *fd);
		}
		lock_release(&fs_lock);

		nextFileId++;
		return nextFileId - 1;
	}

	return handle;
}

/* Get file size */
static int
sys_filesize(int fd) {
	struct file *file = get_file_by_id(fd);
	if(file != NULL) {
		return file_length(file);
	}
	return 0;
}

/* Read x bytes from given file into the buffer */
static int
sys_read(int fd, void *buffer, unsigned size) {
	struct file *file = get_file_by_id(fd);
	if(file != NULL) {	
		return file_read(file, buffer, size);
	}
	return 0;
}

/* Write data from buffer to file */
static int
sys_write(int fd, const void *buffer, unsigned size) {
	struct file *file = get_file_by_id(fd);
	if(file != NULL) {
		if (*buffer == NULL)			//supposed to stop writing if buffer is invalid
			file_deny_write(file);
		else							//makes sure allow_write is set otherwise
			file_allow_write(file);
		lock_acquire(&fs_lock);
		int status = file_write(file, buffer, size);
		lock_release(&fs_lock);
		return status;
	}
	return 0;
}

/* Changes next byte to be read or written in open file */
static void
sys_seek(int fd, unsigned position) {
	struct file *file = get_file_by_id(fd);
	if(file != NULL) {
		return file_seek(file, position);
	}
}

/* Get position of next byte to be read or written to in open file */
static unsigned
sys_tell(int fd) {
	struct file *file = get_file_by_id(fd);
	if(file != NULL) {
		return file_tell(file);
	}
	return 0;
}

/* Close file */
static void
sys_close(int fd) {
	struct file *file = get_file_by_id(fd);
	if(file != NULL) {
		file_close(file);
	}
}

/* Add new file to file list */
void
add_file(const char *name, struct file_descriptor fd) {
	if(head == NULL) {
		start_file_list(name, fd);
	}
	else {
		add_file_to_end(name, fd);
	}
}

/* Update file list with new file information */
void
update_file_list(const char *name, struct file_descriptor fd) {
	file_node *current = get_file_node(name);
	if(current != NULL) {
		update_file_id_list(current, fd);
	}
	else {
		add_file(name, fd);
	}
}

/* Update file node with new id */
void
update_file_id_list(file_node *current, struct file_descriptor fd) {
	add_fd_to_end(current->elem.fds, fd);
}

/* Add new file to file list */
file_node
start_file_list(const char *name, struct file_descriptor fd) {
	head = malloc(sizeof(file_node));
	if(head == NULL) {
		return;
	}

	head->elem = create_file_elem(name, fd);
	head->next = NULL;
}

/* Add file to end of file list */
void
add_file_to_end(const char *name, struct file_descriptor fd) {
	file_node *current = head;

	/* Get to end of list */
	while(current->next != NULL) {
		current = current->next;
	}

	/* Add new elem */
	current->next = malloc(sizeof(file_node));
	current->next->elem = create_file_elem(name, fd);
	current->next->next = NULL;
}

/* Start file_descriptor list */
fd_node *
start_fd_list(struct file_descriptor fd) {
	fd_node *cur;
	cur = malloc(sizeof(fd_node));
	if(cur->fd.file == NULL) {
		return;
	}

	cur->fd = fd;
	cur->next = NULL;
	return cur;
}

/* Add new file_descriptor element to end of list */
void
add_fd_to_end(fd_node *head, struct file_descriptor fd) {
	fd_node *current = head;

	/* Get to end of list */
	while(current->next != NULL) {
		current = current->next;
	}

	/* Add new elem */
	current->next = malloc(sizeof(fd_node));
	current->next->fd = fd;
	current->next->next = NULL;
}

/* Check if file_descriptor is in list */
bool
is_fd_in_list(fd_node *head, int id) {
	fd_node *current = head;

	while(current->next != NULL) {
		if(current->fd.id == id) {
			return true;
		}
		current = current->next;
	}

	if(current->fd.id == id) {
		return true;
	}

	return false;
}

/* Get file from file_descriptor in list */
struct file *
get_file_by_id(int id) {
	file_node *current = head;

	while(current->next != NULL) {
		if(current->elem.fds->fd.id == id) {
			return current->elem.fds->fd.file;
		}
		current = current->next;
	}

	if(current->elem.fds->fd.file == id) {
		return current->elem.fds->fd.file;
	}

	return NULL;
}

/* Find file in linked list by id */
struct file_elem
get_file_elem_by_id(int id) {
	file_node *current = head;
	while(current->next != NULL) {
		if(is_fd_in_list(current->elem.fds, id)) {
			return current->elem;
		}
		current = current->next;
	}

	if(is_fd_in_list(current->elem.fds, id)) {
		return current->elem;
	}

	struct file_descriptor fd;
	fd.id = -1;
	fd.file = NULL;

	return create_file_elem(NULL, fd);
}

/* Find file info in linked list by name */
struct file_elem
get_file_elem_by_name(const char *name) {
	file_node *current = head;
	while(current->next != NULL) {
		if(current->elem.name == name) {
			return current->elem;
		}
		current = current->next;
	}

	if(current->elem.name == name) {
		return current->elem;
	}

	struct file_descriptor fd;
	fd.id = -1;
	fd.file = NULL;

	return create_file_elem(NULL, fd);
}

/* Get file node */
file_node *
get_file_node(const char *name) {
	file_node *current = head;

	while(current->next != NULL) {
		if(current->elem.name == name) {
			return current;
		}
		current = current->next;
	}

	if((current->next == NULL) && (current->elem.name != name)) {
		return NULL;
	}

	return current;
}

/* Get file node before specified file node */
file_node *
get_file_node_before(const char *name) {
	file_node *current = head;

	while(current->next != NULL) {
		if(current->next->elem.name == name) {
			return current;
		}
		current = current->next;
	}

	/*struct file_node null_node;
	null_node.elem.name = NULL;*/
	return NULL;
}

/* Create new file element */
struct file_elem
create_file_elem(const char *name, struct file_descriptor fd) {
	struct file_elem elem;
	elem.fds = start_fd_list(fd);
	elem.name = name;

	return elem;
}

/* Remove file node from list of tracked files */
bool
remove_file_node(const char *name) {
	file_node *current = get_file_node_before(name);

	/* Return failure if node doesn't exist */
	if(current->elem.name == NULL) {
		return false;
	}

	file_node *temp = current->next;
	current->next = temp->next;
	return true;
}
