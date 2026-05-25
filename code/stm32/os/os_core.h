#ifndef OS_CORE_H
#define OS_CORE_H

#include "os_err.h"
#include "os_cfg.h"
#include "os_task.h"
#include "os_plat.h"

void os_sched_disable (void);
void os_sched_run (void);
void os_sched_enable (void);
void os_sched_set_ready (os_task_t * task);
void os_sched_set_unready (os_task_t * task);
void os_task_set_delay (os_task_t * task, int ms);
void os_task_set_wakeup (os_task_t * task);
void os_time_tick (void);
os_task_t * os_task_self (void);
int os_tick_count(void);

void os_task_set_curr(os_task_t * task_to);
void os_task_insert_delete(os_task_t * task);

os_task_ctx_t *os_switch_ctx(os_task_ctx_t *ctx);
void os_init (void);
void os_start (void);

void os_app_init (void);
void os_app_loop(void);

#endif // OS_CORE_H
