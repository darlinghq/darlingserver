#ifndef _DARLINGSERVER_DUCT_TAPE_PROCESOR_H_
#define _DARLINGSERVER_DUCT_TAPE_PROCESOR_H_

void dtape_processor_init(void);

// reads the CPU time counters of the host: those of CPU number `cpu`, or the sum over all CPUs if `cpu` is -1.
// the ticks are in the order of CPU_STATE_USER, CPU_STATE_SYSTEM, CPU_STATE_IDLE and CPU_STATE_NICE and
// are in units of 1/100 s (like the ticks that host_statistics() reports), modulo 2^32.
// returns false if they can't be read (or there is no such CPU).
bool dtape_cpu_load_ticks(int cpu, uint32_t ticks[4]);

#endif // _DARLINGSERVER_DUCT_TAPE_PROCESOR_H_
