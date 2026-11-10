// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
struct task {unsigned id;};
using task_t=task *;
extern task_t kernel_task;
task_t current_task();
