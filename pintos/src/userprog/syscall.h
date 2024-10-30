#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
typedef int pid_t;

/* Project 1 */
void syscall_init (void);

void sys_halt (void);
void sys_exit (int);
pid_t sys_exec (const char *cmdline);
int sys_wait (pid_t pid);
int sys_read (int fd, void *buffer, unsigned size);
int sys_write (int fd, void *buffer, unsigned size);
int sys_fibonacci(int n);
int sys_max_of_four_int(int a,int b,int c,int d);

/* Project 2 */
// bool sys_create(const char *file, unsigned size);
// bool sys_remove(const char *file);
int sys_close(int fd);
void sys_seek(int fd, unsigned pos);
unsigned sys_tell(int fd);
int sys_filesize(int fd);
int sys_open(const char *file);
struct lock filesys_lock;
#endif /* userprog/syscall.h */
