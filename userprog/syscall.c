#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include <string.h>
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include <string.h>

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void check_address(void *addr);
void halt (void);
void exit (int status);
int fork (const char *thread_name, struct intr_frame *f);
int exec (const char *file);
int wait (int pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");

	uintptr_t rsp = f->rsp;
	uint64_t syscall_number = f->R.rax;

	/* Check the stack pointer point to user area */
	check_address(rsp);
	/* If the arguments that saved in user area are pointer type, 
	check the address is point to user area. */
	// get_argument(f);
	/* 시스템 콜 핸들러 syscall_handler() 가 제어권을 얻으면 시스템 콜 번호는 rax 에 있고, 
	인자는 %rdi, %rsi, %rdx, %r10, %r8, %r9 순서로 전달됩니다. */
	/* 함수 리턴 값을 위한 x86-64의 관례는 그 값을 RAX 레지스터에 넣는 것 입니다. 
	값을 리턴하는 시스템 콜도 struct intr_frame의  rax 멤버를 수정하는 식으로 이 관례를 따를 수 있습니다. */

	switch (syscall_number)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit((int)f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork ((char*)f->R.rdi, f);
		break;
	case SYS_EXEC:
		f->R.rax = exec((char*)f->R.rdi);
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create((char*)f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove ((char*)f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open((char*)f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, (char*)f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, (char*)f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	default:
		thread_exit ();
		break;
	}
}
void check_address(void *addr)
{
	/* Check the addr is valid address(is in user area). */
	/* if not, exit the process. */
	if (!is_user_vaddr(addr))
	{
		exit(-1);
	}
}
void
halt (void) {
	power_off();
}
void
exit (int status) {
	struct thread *curr = thread_current();
	/* Save exit status at process descriptor -> ??*/
	curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}
int
wait (int pid) {
	
	/* 자식 프로세스가 종료될 때 까지 대기하는 시스템 콜 */
	int status = process_wait(pid);
	return status;
}
int
exec (const char *file) {
	char *temp = palloc_get_page(PAL_USER);
	strlcpy(temp, file, strlen(file)+1);
	return process_exec (temp);
}
int
fork (const char *thread_name, struct intr_frame *if_){
	return process_fork (thread_name, if_);
}
bool
create (const char *file, unsigned initial_size) {
	if (file==NULL)
		exit(-1);
	return filesys_create (file, initial_size);
}
bool
remove (const char *file) {
	if (file==NULL)
		exit(-1);
	return filesys_remove (file);
}
int
open (const char *file) {
	if (file==NULL)
		exit(-1);
	
	struct thread *curr = thread_current();
	struct file *file_added = filesys_open (file);
	if (file_added==NULL)
		return -1;
	
	int fd = process_add_file(file_added);
	return fd;
}
int
filesize (int fd) {
	struct file * file_curr = process_get_file(fd);
	return file_length (file_curr);
}
int
read (int fd, void *buffer, unsigned size) {
	struct file *file_curr = process_get_file(fd);
	lock_acquire(&filesys_lock);
	int bytes_read;
	if (fd==0)
		bytes_read = input_getc(buffer, size);
	else
	{
		if(file_curr==NULL)
		{
			lock_release(&filesys_lock);
			return -1;
		}
		bytes_read = file_read (file_curr, buffer, size);
	}

	lock_release(&filesys_lock);
	return bytes_read;
}
int
write (int fd, const void *buffer, unsigned size) {

	struct thread *curr = thread_current();
	struct file *file_curr = process_get_file(fd);
	int bytes_written;
	lock_acquire(&filesys_lock);
	if (fd==1)
	{
		putbuf(buffer, size);
		bytes_written = strlen((char*)buffer);
		lock_release(&filesys_lock);
		return bytes_written < size ? bytes_written : size;
	}
	else
	{
		bytes_written = file_write (file_curr, buffer, size);
		lock_release(&filesys_lock);
		return bytes_written;
	}
}
void
seek (int fd, unsigned position) {

	struct file *file_curr = process_get_file(fd);
	file_seek (file_curr, position);
}
unsigned
tell (int fd) {

	struct file *file_curr = process_get_file(fd);

	return file_tell (file_curr);
}
void
close (int fd) {
	process_close_file(fd);
}

