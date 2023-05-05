#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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

	// 내용 수정
	// Project2 System Call
	lock_init(&filesys_lock);

}

// 내용 수정
// Project2 System Call
/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");

	/* 유저 스택에 저장되어 있는 시스템 콜 넘버를 이용해 시스템 콜
	핸들러 구현 */
	uint64_t scall = f->R.rax; /* 시스템 콜 번호*/

	/* 스택 포인터가 유저 영역인지 확인 */
	/* 저장된 인자 값이 포인터일 경우 유저 영역의 주소인지 확인 */
	check_address(f->rsp);
// %rdi, %rsi, %rdx, %r10, %r8, %r9
	switch(scall){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;             
		case SYS_FORK:
			f->R.rax = fork((const char *)f->R.rdi, f);
			break;
		case SYS_EXEC:
			f->R.rax = exec((const char *)f->R.rdi, f);
			break;   
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break; 
		case SYS_CREATE:
			f->R.rax = create((char *)f->R.rdi,f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove((char *)f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open((char *)f->R.rdi);                      
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);                  
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi,(void *)f->R.rsi,f->R.rdx);                      
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi,(void *)f->R.rsi,f->R.rdx);                     
			break;
		case SYS_SEEK:
			seek(f->R.rdi,f->R.rsi);                     
			break;			
		case SYS_TELL: 
			f->R.rax = tell(f->R.rdi);                    
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		default:
			thread_exit();
	}
}

// 내용 수정
// Project2 User Memory Access 
void check_address(void *addr)
{
	/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 */
	/*1. 유저영역의 주소보다 큰 경우*/
	/*2. 페이지 할당이 안된 경우*/
	/*3. addr 가 NULL인 경우*/
	if (!is_user_vaddr(addr) || !pml4_get_page(thread_current()->pml4,addr) || !addr) exit(-1);
}

// 내용 수정
// Project2 System Call
void halt (void)
{
	/* power_off()를 사용하여 pintos 종료 */
	power_off ();
}

// 내용 수정
// Project4 Process Termination Message
void exit (int status)
{
	/* 실행중인 스레드 구조체를 가져옴 */
	struct thread *curr = thread_current();

	/*Project2 Process Set*/
	/* 프로세스 디스크립터에 exit status 저장 */
	curr->exit_status = status;
	/* 프로세스 종료 메시지 출력, 
	출력 양식: “프로세스이름: exit(종료상태)” */
	printf("%s: exit(%d)\n",curr->name,status);
	/* 스레드 종료 */
	thread_exit ();
}

// 내용 수정
// Project2 System Call
bool create(const char *file , unsigned initial_size)
{
	/* file 명이 NULL 인 경우 실행없이 종료 */
	if (file == NULL) exit(-1);
	/* 파일 이름과 크기에 해당하는 파일 생성 */
	/* 파일 생성 성공 시 true 반환, 실패 시 false 반환 */
	return filesys_create(file,initial_size);
}

// 내용 수정
// Project2 System Call
bool remove(const char *file)
{	
	/* file 명이 NULL 인 경우 실행없이 종료 */
	if (file == NULL) exit(-1);
	/* 파일 이름에 해당하는 파일을 제거 */
	/* 파일 제거 성공 시 true 반환, 실패 시 false 반환 */
	return filesys_remove(file);
}

// 내용 수정
// Project2 System Call
int open(const char *file)
{	
	/* file명이 NULL 인 경우 실행없이 종료 */
	if (file == NULL) exit(-1);
	/* 파일을 open */
	struct file *result = filesys_open(file);
	/* 해당 파일 객체에 파일 디스크립터 부여 */
	int curr_fd = process_add_file(result);
	/* 해당 파일이 존재하면 파일 디스크립터 리턴 */
	if (result!=NULL) return curr_fd;
	/* 해당 파일이 존재하지 않으면 -1 리턴 */
	else return -1;
}

// 내용 수정
// Project2 System Call
int filesize (int fd)
{	
	/* 파일 디스크립터를 이용하여 파일 객체 검색 */
	struct file *f_obj = process_get_file(fd);
	/* 해당 파일의 크기를 리턴 */
	if (f_obj!=NULL) return file_length(f_obj);
	
	/* 해당 파일이 존재하지 않으면 -1 리턴 */
	else return -1;
}

// 내용 수정
// Project2 System Call
int read (int fd, void *buffer, unsigned size)
{
	struct thread *curr = thread_current();
	/* 파일에 동시 접근이 일어날 수 있으므로 Lock 사용 */
	lock_acquire(&filesys_lock);
	/* 파일 디스크립터를 이용하여 파일 객체 검색 */
	struct file *f_obj = process_get_file(fd);
	/* 파일 디스크립터가 0일 경우 키보드에 입력을 버퍼에 저장 후
	버퍼의 저장한 크기를 리턴 (input_getc() 이용) */
	if (fd==0){
		buffer = input_getc();
		lock_release(&filesys_lock);
		return buffer;

	}
	/* 파일 디스크립터가 0이 아닐 경우 파일의 데이터를 크기만큼 저
	장 후 읽은 바이트 수를 리턴 */
	else {
		off_t result = file_read(f_obj, buffer, size);
		lock_release(&filesys_lock);
		return result;
	}
}

// 내용 수정
// Project2 System Call
int write(int fd, void *buffer, unsigned size)
{
	struct thread *curr = thread_current();
	/* 파일에 동시 접근이 일어날 수 있으므로 Lock 사용 */
	lock_acquire(&filesys_lock);
	/* 파일 디스크립터를 이용하여 파일 객체 검색 */
	struct file *f_obj = process_get_file(fd);
	/* 파일 디스크립터가 1일 경우 버퍼에 저장된 값을 화면에 출력
	후 버퍼의 크기 리턴 (putbuf() 이용) */
	if (fd==1) {
		putbuf(buffer,size);
		// 버퍼의 크기 리턴??
		lock_release(&filesys_lock);
		return size;
	}
	/* 파일 디스크립터가 1이 아닐 경우 버퍼에 저장된 데이터를 크기
	만큼 파일에 기록후 기록한 바이트 수를 리턴 */
	else {
		off_t result = file_write(f_obj, buffer, size);
		lock_release(&filesys_lock);
		return result;
	}
}

// 내용 수정
// Project2 System Call
void seek (int fd, unsigned position)
{
	/* 파일 디스크립터를 이용하여 파일 객체 검색 */
	struct file *f_obj = process_get_file(fd);
	/* 해당 열린 파일의 위치(offset)를 position만큼 이동 */
	file_seek(f_obj,position);
}

// 내용 수정
// Project2 System Call
unsigned tell (int fd)
{
	/* 파일 디스크립터를 이용하여 파일 객체 검색 */
	struct file *f_obj = process_get_file(fd);
	/* 해당 열린 파일의 위치를 반환 */
	if (f_obj!=NULL) return file_tell(fd);
	else return -1;
}

// 내용 수정
// Project2 System Call
void close (int fd)
{
	/* 해당 파일 디스크립터에 해당하는 파일을 닫음 */
	/* 파일 디스크립터 엔트리 초기화 */
	process_close_file(fd);
}

// 내용 수정
// Project2 System Call
/* Process set */
tid_t exec(const char *cmd_line, struct intr_frame *if_)
{
	/* 함수를 호출하여 자식 프로세스 생성 */
	tid_t child_tid = fork (cmd_line, if_);
	/* 생성된 자식 프로세스 검색 */
	/* 자식 프로세스의 프로그램이 적재될 때까지 부모 프로세스 대기 */
	int result = wait(child_tid);
	/* 프로그램 적재 실패 시 -1 리턴 */
	if (result == -1 ) return -1;
	/* 프로그램 적재 성공 시 자식 프로세스의 pid 리턴 */
	else return child_tid;
}

int wait (tid_t tid){

	/* process_wait() 사용 */
	return process_wait(tid);
} 


tid_t fork (const char *name, struct intr_frame *if_){

	/*자식 프로세스 생성 */
	return process_fork(name, if_);
}
