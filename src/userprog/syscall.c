#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "devices/console.h"
#include "userprog/process.h"
#include "threads/synch.h"

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
      /* 잘못된 포인터: 프로세스 종료 */
      printf ("%s: exit(%d)\n", thread_current ()->name, -1);
      thread_current ()->exit_status = -1;
      thread_exit ();
    }
}

/* 유저 메모리에서 32비트 값을 안전히 읽기. */
static int32_t
get_user_int (const void *uaddr)
{
  validate_ptr (uaddr);
  return *(const int32_t *) uaddr;
}

/* 쓰기 가능한 버퍼 검증. size 바이트 범위를 모두 확인. */
static void
validate_writable_buffer (void *buf, unsigned size)
{
  unsigned i;
  for (i = 0; i < size; i++)
    validate_ptr ((uint8_t *) buf + i);
}

/* 읽기 전용 버퍼 검증. */
static void
validate_readable_buffer (const void *buf, unsigned size)
{
  unsigned i;
  for (i = 0; i < size; i++)
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

static void sys_halt (void)
{
  shutdown_power_off ();
}

static void sys_exit (int status)
{
  struct thread *t = thread_current ();
  t->exit_status = status;
  printf ("%s: exit(%d)\n", t->name, status);
  thread_exit ();
}

static pid_t sys_exec (const char *cmd_line)
{
  validate_cstr (cmd_line);
  lock_acquire (&filesys_lock);
  pid_t pid = process_execute (cmd_line);
  lock_release (&filesys_lock);
  return pid;
}

static int sys_wait (pid_t pid)
{
  return process_wait (pid);
}

static int sys_read (int fd, void *buffer, unsigned size)
{
  if (size == 0) return 0;
  validate_writable_buffer (buffer, size);

  if (fd == 0) /* STDIN */
    {
      unsigned i;
      for (i = 0; i < size; i++)
        ((uint8_t *) buffer)[i] = input_getc ();
      return (int) size;
    }
  /* 파일 디스크립터 테이블 확장 전: 그 외 FD는 미지원 */
  return -1;
}

static int sys_write (int fd, const void *buffer, unsigned size)
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

void
syscall_init (void) 
{
  lock_init (&filesys_lock); /* 파일 시스템 lock init */
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call!\n");
  // thread_exit ();

  /* 유저 스택 포인터 */
  void *esp = f->esp;

  /* 시스템 콜 번호 */
  validate_ptr (esp);
  int sysno = get_user_int (esp);

  /* 인자 간격은 4바이트 */
  int32_t arg0 = 0, arg1 = 0, arg2 = 0;
  if (sysno == SYS_EXIT || sysno == SYS_EXEC || sysno == SYS_WAIT ||
      sysno == SYS_READ || sysno == SYS_WRITE || sysno == SYS_HALT)
    {
      if (sysno != SYS_HALT)
        arg0 = get_user_int ((uint8_t *) esp + 4);
      if (sysno == SYS_EXEC || sysno == SYS_WAIT ||
          sysno == SYS_READ || sysno == SYS_WRITE)
        arg1 = get_user_int ((uint8_t *) esp + 8);
      if (sysno == SYS_READ || sysno == SYS_WRITE)
        arg2 = get_user_int ((uint8_t *) esp + 12);
    }

  switch (sysno)
  {
  case SYS_HALT:
    sys_halt (); /* 복귀하지 않음 */
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

  case SYS_READ:
    f->eax = (uint32_t) sys_read (arg0, (void *) arg1, (unsigned) arg2);
    break;

  case SYS_WRITE:
    f->eax = (uint32_t) sys_write (arg0, (const void *) arg1, (unsigned) arg2);
    break;

  default:
    /* 알 수 없는 시스템 콜은 종료 */
    exit (-1);
    break;
  }
}
