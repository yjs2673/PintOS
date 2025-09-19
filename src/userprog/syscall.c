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
