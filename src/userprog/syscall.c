#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

// Create list of tracked files
#define FILE_LIST_SIZE 100
static struct file_elem files[FILE_LIST_SIZE];
int nextFileId = 0;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&fs_lock);

  // Clear out file list
  memset(files, 0, sizeof files);
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
		struct file_elem newElem;
		newElem.file_info.file = nextFileId;
		newElem.name = file;
		files[nextFileId] = newElem;
		nextFileId++;
	}
	return result;
}

/* Remove system call */
static bool
sys_remove(const char *file) {
	return filesys_remove(file);
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
	return file_size(fd->file);
}

/* Read system call */
static int
sys_read(int fd, void *buffer, unsigned size) {
	return file_read(fd->file, buffer, size);
}

/* Write system call */
static int
sys_write(int fd, const void *buffer, unsigned size) {
	// TODO
}

/* Seek system call */
static void
sys_seek(int fd, unsigned position) {
	// TODO
}

/* Tell system call */
static unsigned
sys_tell(int fd) {
	// TODO
}

/* Close system call */
static void
sys_close(int fd) {
	// TODO
}
