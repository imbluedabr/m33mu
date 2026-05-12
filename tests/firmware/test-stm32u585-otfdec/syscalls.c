/* m33mu -- OTFDEC firmware test syscalls stub
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sys/stat.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>

extern uint32_t _ebss;
extern uint32_t _estack;
extern volatile uint32_t systick_ms;

static char *heap_end;

/* _write is defined in main.c */

int _close(int file) { (void)file; return -1; }
int _fstat(int file, struct stat *st)
{
    (void)file;
    if (st) { st->st_mode = S_IFCHR; }
    return 0;
}
int _isatty(int file) { (void)file; return 1; }
int _lseek(int file, int ptr, int dir) { (void)file; (void)ptr; (void)dir; return 0; }
int _read(int file, char *ptr, int len) { (void)file; (void)ptr; (void)len; return 0; }

void *_sbrk(ptrdiff_t incr)
{
    char *prev;
    if (heap_end == 0) {
        heap_end = (char *)&_ebss;
    }
    prev = heap_end;
    if ((heap_end + incr) >= (char *)&_estack) {
        errno = ENOMEM;
        return (void *)-1;
    }
    heap_end += incr;
    return prev;
}

void _exit(int status) { (void)status; while (1) { __asm volatile("wfi"); } }
int _kill(int pid, int sig) { (void)pid; (void)sig; errno = EINVAL; return -1; }
int _getpid(void) { return 1; }
void _init(void) {}
void _fini(void) {}
