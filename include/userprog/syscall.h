#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

// 내용 수정
// Project2 System Call
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "kernel/stdio.h"

void syscall_init (void);

// 내용 수정
// Project2 System Call
void check_address(void *addr);
void halt (void);
void exit (int status);
bool create(const char *file , unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write(int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);


// 수정
// Project2 System Call
/* read(), write() 시스템 콜에서 파일 접근하기 전에 lock을 획득하도록 구현
파일에 대한 접근이 끝난 뒤 lock 해제 */
struct lock filesys_lock;

#endif /* userprog/syscall.h */
