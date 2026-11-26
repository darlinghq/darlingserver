# Exception codes of hardware faults

Host-only test, no darlingserver build needed. From the repository root:

```sh
tests/run-exception-codes.sh   # the EXC_BAD_ACCESS code and subcode of each kind of fault
```

The test cuts `dtape_thread_process_signal` and `ux_exception` out of `duct-tape/src/thread.c`, with
the Mach and BSD constants taken from the imported XNU headers. It feeds the first one the signal,
`si_code` and address of each kind of Linux fault, captures the exception it raises, and checks that
exception and the BSD signal that `ux_exception` makes of it when no handler takes the exception:

| Linux signal | Exception code | Subcode | Signal | |
|---|---|---|---|---|
| `SIGSEGV`, `SEGV_MAPERR` | `KERN_INVALID_ADDRESS` | address | `SIGSEGV` | observed on macOS 27 |
| `SIGSEGV`, `SEGV_ACCERR` | `KERN_PROTECTION_FAILURE` | address | `SIGBUS` | observed on macOS 27 |
| `SIGBUS`, `BUS_ADRERR` | `KERN_MEMORY_ERROR` | address | `SIGBUS` | observed on macOS 27 |
| `SIGSEGV`, `SEGV_PKUERR` | `KERN_PROTECTION_FAILURE` | address | `SIGBUS` | by analogy with `SEGV_ACCERR` |
| `SIGBUS`, `BUS_OBJERR` | `KERN_MEMORY_ERROR` | address | `SIGBUS` | by analogy with `BUS_ADRERR` |
| `SIGSEGV`, `SI_KERNEL` | `KERN_INVALID_ADDRESS` | 0 | `SIGSEGV` | general protection fault, unchanged |
| `SIGBUS`, `BUS_ADRALN` | `EXC_I386_ALIGNFLT` (`EXC_ARM_DA_ALIGN` on arm64) | 0 | `SIGBUS` | unchanged |

The macOS observations (x86_64 under Rosetta, and arm64) are of a thread that reads a page it has no
access to, writes a read-only page, reads an unmapped page, and reads a file mapping past the end of the
file, with an `EXC_BAD_ACCESS` port whose handler fails the exception, then a `sigaction` handler.
Darling delivers the same codes and signals for these accesses.

Pass a checkout, or a `git archive` of another revision, to run the same test against it. Before the
codes followed `si_code`, every `SIGSEGV` gave `KERN_INVALID_ADDRESS` and every `SIGBUS` the alignment
code without an address, and the test fails.
