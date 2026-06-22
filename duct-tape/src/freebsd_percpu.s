/* freebsd_percpu.s — minimal percpu section for single-CPU dtape on FreeBSD.
 *
 * XNU's percpu mechanism expects Mach-O section boundary symbols
 * (section$start$__DATA$__percpu / section$end$__DATA$__percpu) and per-CPU
 * variable slots (percpu_slot_*).  On ELF/FreeBSD these don't exist natively,
 * so we provide a static single-CPU block here.
 *
 * Assembled with: clang -x assembler-with-cpp
 */

    .section .data
    .align  64

    .globl  section$start$__DATA$__percpu
section$start$__DATA$__percpu:
    /* 16 KB zeroed: covers all percpu slots for single-CPU dtape */
    .space  16384

    /* processor slot starts at offset 0 from section start */
    .globl  percpu_slot_processor
percpu_slot_processor = section$start$__DATA$__percpu

    /* sched_stats slot at offset 4096 */
    .globl  percpu_slot_sched_stats
percpu_slot_sched_stats = section$start$__DATA$__percpu + 4096

    /* end symbol immediately after the 16KB block */
    .globl  section$end$__DATA$__percpu
section$end$__DATA$__percpu = section$start$__DATA$__percpu + 16384
