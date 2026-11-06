/* freebsd_compat.c — FreeBSD shims for Linux-specific libc functions used by
 * dtape source files.  Compiled WITHOUT -DKERNEL so POSIX headers are usable. */

#include <unistd.h>

/* get_nprocs / get_nprocs_conf: Linux <sys/sysinfo.h> glibc functions.
 * FreeBSD equivalent: sysconf(_SC_NPROCESSORS_*). */

int get_nprocs(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? (int)n : 1;
}

int get_nprocs_conf(void)
{
    long n = sysconf(_SC_NPROCESSORS_CONF);
    return (n > 0) ? (int)n : 1;
}

/* memfd_create: Linux syscall for anonymous file; FreeBSD uses shm_open(SHM_ANON).
 * Used by dtape memory.c for mach_vm_remap shared descriptor backing. */
#include <sys/mman.h>
#include <fcntl.h>

int memfd_create(const char *name, unsigned int flags)
{
    (void)name;
    int fd = shm_open(SHM_ANON, O_RDWR | O_CREAT, 0600);
    if (fd < 0)
        return -1;
    if (flags & 0x1u) { /* MFD_CLOEXEC */
        int fl = fcntl(fd, F_GETFD, 0);
        if (fl >= 0)
            fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
    }
    return fd;
}
