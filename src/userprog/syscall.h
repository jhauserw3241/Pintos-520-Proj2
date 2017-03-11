#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"

// Define new structs for code Dan provided
struct lock fs_lock;
struct file_descriptor {
	int file;
};

// Define new structs for file tracking
struct file_elem {
	struct file_descriptor file_info; 	/* File id */
	const char *name; 			/* File name */
};

/* Inspiration from: www.learn-c.org/en/Linked_list */
typedef struct node {
	struct file_elem elem;
	struct node * next;
} node_t;

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

struct file_elem create_file_elem(const char *name);
struct file_elem find_file_info(int id);
void add_new_file_to_list(const char *name);
void add_file_to_end(const char *name);
void remove_elem_from_list(const char *name);

#endif /* userprog/syscall.h */
