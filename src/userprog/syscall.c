#include "userprog/syscall.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/synch.h"

typedef int pid_t;

void shutdown_power_off (void);             /* devices/shutdown.h */
uint8_t input_getc (void);                  /* devices/input.h */
void putbuf (const char *buffer, size_t n); /* lib/kernel/console.h */

static void syscall_handler (struct intr_frame *);

/* Filesystem serialization lock */
static struct lock filesys_lock;

/* uaddr가 유저 영역에 매핑되어 있는지 확인 */
static void
validate_ptr (const void *uaddr)
{
  if (uaddr == NULL || !is_user_vaddr (uaddr) ||
      pagedir_get_page (thread_current ()->pagedir, uaddr) == NULL)
    {
      sys_exit (-1);
    }
}

/* 유저 메모리에서 32비트 값을 안전히 읽기 */
static int32_t
get_user_int (const void *uaddr)
{
  validate_ptr (uaddr);
  // validate_ptr (uaddr + 3); /* 4바이트 패딩 */
  return *(const int32_t *) uaddr;
}

/* size 바이트 범위를 모두 확인 */
/* 쓰기 가능한 버퍼 검증 */
static void
validate_writable_buffer (void *buf, unsigned size)
{
  for (unsigned i = 0; i < size; i++)
    validate_ptr ((uint8_t *) buf + i);
}

/* 읽기 전용 버퍼 검증. */
static void
validate_readable_buffer (const void *buf, unsigned size)
{
  for (unsigned i = 0; i < size; i++)
    validate_ptr ((const uint8_t *) buf + i);
}

/* NUL로 끝나는 문자열 전체를 검증. */
static void
validate_cstr (const char *str)
{
  validate_ptr (str);
  while (*str != '\0')
    {
      validate_ptr (str);
      str++;
    }
}

/* syscall function */
/*============================================*/
void sys_halt (void)
{
  shutdown_power_off ();
}

void sys_exit (int status)
{
  struct thread *t = thread_current ();
  t->exit_status = status;
  printf ("%s: exit(%d)\n", t->name, status);
  thread_exit ();
}

pid_t sys_exec (const char *cmd_line)
{
  validate_cstr (cmd_line);
  lock_acquire (&filesys_lock);
  pid_t pid = process_execute (cmd_line);
  lock_release (&filesys_lock);
  return pid;
}

int sys_wait (pid_t pid)
{
  return process_wait (pid);
}

/* User Program 2 */
bool sys_create (const char *file, unsigned initial_size)
{
  
}

bool sys_remove (const char *file)
{
  
}

int sys_open (const char *file)
{
  
}

int sys_filesize (int fd)
{
  
}

int sys_read (int fd, void *buffer, unsigned size)
{
  
}

int sys_write (int fd, const void *buffer, unsigned size)
{
  
}

void sys_seek (int fd, unsigned position)
{
  
}

unsigned sys_tell (int fd)
{
  
}

void sys_close (int fd)
{
  
}
/*================*/

int sys_fibonacci (int n)
{
  if (n < 0 || n > 46) return -1;   /* 범위 밖은 예외처리 */

  int pprev = 0, prev = 1, cur = 0;
  if (n == 0) return pprev;
  if (n == 1) return prev;

  for (int i = 1; i < n; i++)
  {
    cur = prev + pprev;
    pprev = prev;
    prev = cur;
  }

  return cur;
}

int sys_max_of_four_int (int a, int b, int c, int d)
{
  int max1 = a >= b ? a : b;
  int max2 = c >= d ? c : d;
  return max1 >= max2 ? max1 : max2;
}
/*============================================*/

void
syscall_init (void) 
{
  lock_init (&filesys_lock); /* 파일 시스템 lock init */
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void *esp = f->esp;

  validate_ptr (esp);
  int sysno = get_user_int (esp);

  int32_t arg0 = 0, arg1 = 0, arg2 = 0, arg3 = 0;
  if (sysno == SYS_HALT || sysno == SYS_EXIT || sysno == SYS_EXEC || 
      sysno == SYS_WAIT || sysno == SYS_CREATE || sysno == SYS_REMOVE ||
      sysno == SYS_OPEN || sysno == SYS_FILESIZE || sysno == SYS_SEEK ||
      sysno == SYS_READ || sysno == SYS_WRITE || sysno == SYS_TELL ||
      sysno == SYS_CLOSE || sysno == SYS_FIBONACCI || sysno == SYS_MAX_OF_FOUR_INT)
  {
    if (sysno != SYS_HALT)                
      arg0 = get_user_int ((uint8_t *) esp + 4);  // 1 arg
    if (sysno == SYS_READ || sysno == SYS_WRITE || sysno == SYS_MAX_OF_FOUR_INT ||
        sysno == SYS_CREATE || sysno == SYS_SEEK)
      arg1 = get_user_int ((uint8_t *) esp + 8);  // 2 arg
    if (sysno == SYS_READ || sysno == SYS_WRITE || sysno == SYS_MAX_OF_FOUR_INT)  
      arg2 = get_user_int ((uint8_t *) esp + 12); // 3 arg
    if (sysno == SYS_MAX_OF_FOUR_INT)             
      arg3 = get_user_int ((uint8_t *) esp + 16); // 4 arg
  }

  switch (sysno)
  {
  case SYS_HALT:
    sys_halt ();
    break;

  case SYS_EXIT:
    sys_exit (arg0);
    break;

  case SYS_EXEC:
    f->eax = (uint32_t) sys_exec ((const char *) arg0);
    break;

  case SYS_WAIT:
    f->eax = (uint32_t) sys_wait ((pid_t) arg0);
    break;

  case SYS_CREATE:
    f->eax = (uint32_t) sys_create ((const char *) arg0, (unsigned) arg1);
    break;

  case SYS_REMOVE:
    f->eax = (uint32_t) sys_remove ((const char *) arg0);
    break;

  case SYS_OPEN:
    f->eax = (uint32_t) sys_open ((const char *) arg0);
    break;

  case SYS_FILESIZE:
    f->eax = (uint32_t) sys_filesize (arg0);
    break;

  case SYS_READ:
    f->eax = (uint32_t) sys_read (arg0, (void *) arg1, (unsigned) arg2);
    break;

  case SYS_WRITE:
    f->eax = (uint32_t) sys_write (arg0, (const void *) arg1, (unsigned) arg2);
    break;

  case SYS_SEEK:
    sys_seek (arg0, (unsigned) arg1);
    break;

  case SYS_TELL:
    f->eax = (uint32_t) sys_tell (arg0);
    break;

  case SYS_CLOSE:
    sys_close (arg0);
    break;

  case SYS_FIBONACCI:
    f->eax = (uint32_t) sys_fibonacci (arg0);
    break;

  case SYS_MAX_OF_FOUR_INT:
    f->eax = (uint32_t) sys_max_of_four_int (arg0, arg1, arg2, arg3);
    break;

  default:
    sys_exit (-1);
    break;
  }
}