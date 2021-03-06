/* See COPYRIGHT for copyright information. */

#ifndef JOS_INC_ENV_H
#define JOS_INC_ENV_H

#include <inc/types.h>
#include <inc/trap.h>
#include <inc/memlayout.h>

typedef int32_t envid_t;


// An environment ID 'envid_t' has three parts:
//
// +1+---------------21-----------------+--------10--------+
// |0|          Uniqueifier             |   Environment    |
// | |                                  |      Index       |
// +------------------------------------+------------------+
//                                       \--- ENVX(eid) --/
//
// The environment index ENVX(eid) equals the environment's offset in the
// 'envs[]' array.  The uniqueifier distinguishes environments that were
// created at different times, but share the same environment index.
//
// All real environments are greater than 0 (so the sign bit is zero).
// envid_ts less than 0 signify errors.  The envid_t == 0 is special, and
// stands for the current environment.

// 31位被固定为0；第10~30这21位是标识符，标示这个用户环境；第0~9位代表这个用户环境所采
// 用的 Env 结构体，在envs数组中的索引

// evns 数组就等价于 PCB 表,其共有1024(NENV)个表项,即JOS系统并发度为1024
#define LOG2NENV		10
#define NENV			(1 << LOG2NENV)
// 当前用户env在数组中的下标
#define ENVX(envid)		((envid) & (NENV - 1))

// Values of env_status in struct Env
// 用户环境状态类型
enum {
	ENV_FREE = 0,
	ENV_DYING,    // 僵尸环境,在下一次陷入内核时被释放回收
	ENV_RUNNABLE, // 用户环境就绪，等待分配处理机
	ENV_RUNNING,  // 用户环境正在运行
	ENV_NOT_RUNNABLE //用户环境阻塞
};

// Special environment types
enum EnvType {
	ENV_TYPE_USER = 0,
};

struct Env {
	struct Trapframe env_tf;	// Saved registers
	struct Env *env_link;		// Next free Env
	envid_t env_id;			// Unique environment identifier
	envid_t env_parent_id;		// env_id of this env's parent
	enum EnvType env_type;		// Indicates special system environments
	unsigned env_status;		// Status of the environment
	uint32_t env_runs;		// Number of times environment has run

	// Address space env_pgdir变量:用户环境的页目录的虚拟地址
	pde_t *env_pgdir;		// Kernel virtual address of page dir
};

#endif // !JOS_INC_ENV_H
