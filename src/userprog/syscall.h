#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"
#include "filesys/file.h"

// Define new structs for code Dan provided
struct lock fs_lock;
struct file_descriptor {
	int id;
	struct file *file;
};

/* Create file descriptor node to hold list of file descriptors */
typedef struct node_d {
	struct file_descriptor fd;	/* File descriptor */
	struct node_d * next;		/* Next file_descriptor node */
} fd_node;

// Define new structs for file tracking
struct file_elem {
	fd_node *fds;		/* Linked list of file_descriptors */
	const char *name; 	/* File name */
};

/* Create file node to hold list of files being tracked */
/* Inspiration from: www.learn-c.org/en/Linked_list */
typedef struct node_t {
	struct file_elem elem;		/* Current file element */
	struct node_t * next;		/* Next file element */
} file_node;

// Define system call functions Dan provided
void syscall_init (void);
static void sys_halt (void);
static void sys_exit (int status);
static pid_t sys_exec (const char *cmd_line);
static int sys_wait (pid_t pid);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);

#endif /* userprog/syscall.h */
