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

/* uaddr가 유저 영역에 매핑되어 있는지 확인.
   아니면 exit(-1)로 프로세스를 종료. */
static void
validate_ptr (const void *uaddr)
{
  if (uaddr == NULL || !is_user_vaddr (uaddr) ||
      pagedir_get_page (thread_current ()->pagedir, uaddr) == NULL)
    {
      printf ("%s: exit(%d)\n", thread_current ()->name, -1);
      thread_current ()->exit_status = -1;
      thread_exit ();
    }
}

/* 유저 메모리에서 32비트 값을 안전히 읽기. */
static int32_t
get_user_int (const void *uaddr)
{
  const uint8_t *p = uaddr;
  for (size_t i = 0; i < sizeof(int32_t); i++)
    validate_ptr(p + i);              // 4바이트 모두 검증
  int32_t val;
  memcpy(&val, uaddr, sizeof val);    // 정렬 문제 회피
  return val;
}


void fetch_args(void *esp, int n, int32_t *out) 
{
  for (int i = 0; i < n; i++) {
    out[i] = get_user_int ((uint8_t *)esp + 4 + i * 4);
  }
}

/* 쓰기 가능한 버퍼 검증. size 바이트 범위를 모두 확인. */
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

int sys_read (int fd, void *buffer, unsigned size)
{
  if (size == 0) return 0;
  validate_writable_buffer (buffer, size);

  if (fd == 0) /* STDIN */
    {
      for (unsigned i = 0; i < size; i++)
        ((uint8_t *) buffer)[i] = input_getc ();
      return (int) size;
    }
  /* 파일 디스크립터 테이블 확장 전: 그 외 FD는 미지원 */
  return -1;
}

int sys_write (int fd, const void *buffer, unsigned size)
{
  if (size == 0) return 0;
  validate_readable_buffer (buffer, size);

  if (fd == 1) /* STDOUT */
    {
      putbuf ((const char *) buffer, (size_t) size);
      return (int) size;
    }
  /* 파일 디스크립터 테이블 확장 전: 그 외 FD는 미지원 */
  return -1;
}

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

  int32_t args[4] = {0};

  switch (sysno) {
  case SYS_HALT:
    sys_halt ();
    break;
  case SYS_EXIT:
    fetch_args(esp, 1, args);
    sys_exit (args[0]);
    break;
  case SYS_EXEC:
    fetch_args(esp, 1, args);
    f->eax = (uint32_t) sys_exec ((const char *) args[0]);
    break;
  case SYS_WAIT:
    fetch_args(esp, 1, args);
    f->eax = (uint32_t) sys_wait ((pid_t) args[0]);
    break;
  case SYS_READ:
    fetch_args(esp, 3, args);
    f->eax = (uint32_t) sys_read (args[0], (void *) args[1], (unsigned) args[2]);
    break;
  case SYS_WRITE:
    fetch_args(esp, 3, args);
    f->eax = (uint32_t) sys_write (args[0], (const void *) args[1], (unsigned) args[2]);
    break;
  case SYS_FIBONACCI:
    fetch_args(esp, 1, args);
    f->eax = (uint32_t) sys_fibonacci (args[0]);
    break;
  case SYS_MAX_OF_FOUR_INT:
    fetch_args(esp, 4, args);
    f->eax = (uint32_t) sys_max_of_four_int (args[0], args[1], args[2], args[3]);
    break;
  default:
    sys_exit(-1);
}

}
