#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

typedef struct child{
   tid_t id;
   bool called;
   struct child *next;
}child_t;

typedef struct rel{
   pid_t parent_id;
   child_t child;
   struct rel *next;
}rel_t;

void set_child_rel(pid_t parent, tid_t child);
bool is_parent_child (tid_t child_pid);
bool killed(tid_t child_pid);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
