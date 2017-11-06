#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>

#define ABORT(expr, fmt, ...) \
do { \
	if (expr) { \
		fprintf(stderr, fmt "\n", ## __VA_ARGS__); \
		exit(0); \
	} \
} while (0)

#define PAGE_SIZE 4096

enum pt_event_kind {
	PT_EVENT_NONE,
	PT_EVENT_CALL,
	PT_EVENT_RET,
	PT_EVENT_XBEGIN,
	PT_EVENT_XCOMMIT,
	PT_EVENT_XABORT,
};

// Packed to 64 bits, or 8B line (6B addr, 2B kind)
// Not something I'm interested in messing with, for performance reasons
// ... But I think I need to, for testing retrieving the offset
struct pt_event {
	unsigned long addr:48;
	unsigned long kind:16;
	unsigned char * offset;
};

#define MAGIC 0x51C0FFEE
#define VERSION 1

struct pt_logfile_header {
	unsigned int magic;
	unsigned int version;
};

enum pt_logitem_kind {
	PT_LOGITEM_BUFFER,
	PT_LOGITEM_PROCESS,
	PT_LOGITEM_THREAD,
	PT_LOGITEM_IMAGE,
	PT_LOGITEM_XPAGE,
	PT_LOGITEM_UNMAP,
	PT_LOGITEM_FORK,
	PT_LOGITEM_SECTION,
	PT_LOGITEM_THREAD_END,
};

struct pt_logitem_header {
	enum pt_logitem_kind kind;
	unsigned int size;
};

struct pt_logitem_buffer {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long pid;
	unsigned long sequence;
	unsigned long size;
};

struct pt_logitem_process {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long cmd_size;
};

struct pt_logitem_thread {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long pid;
};

struct pt_logitem_image {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long base;
	unsigned int size;
	unsigned int timestamp;
	unsigned long image_name_length;
};

struct pt_logitem_xpage {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long base;
	unsigned long size;
};

struct pt_logitem_unmap {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long base;
};

struct pt_logitem_fork {
	struct pt_logitem_header header;
	unsigned long parent_tgid;
	unsigned long parent_pid;
	unsigned long child_tgid;
	unsigned long child_pid;
};

#define PID_SPACE 0xffff
struct {
	void *top;
	struct pt_event *sp;
	struct pt_event *xbegin;
} stacks[PID_SPACE];

#define MIRROR_DISTANCE 0x010000000000
#define MIRROR(addr, level) (((addr) + (level) * MIRROR_DISTANCE) & 0x7fffffffffff)

#define PT_IP_TO_CODE(addr) MIRROR(addr, 1)
#define PT_IP_TO_BLOCK(addr) MIRROR((addr) & ~0x7, ((addr) & 0x7) + 2)

typedef unsigned short pt_recover_arg;

#define pt_on_call(addr, pid, offset) do { \
	*(stacks[pid].sp--) = (struct pt_event) {addr, PT_EVENT_CALL, offset}; \
} while (0)

static inline void pt_on_ret(unsigned long addr, pt_recover_arg pid)
{
	struct pt_event *sp;

	/* ignore sigreturn */
	if (*(unsigned long *)(PT_IP_TO_CODE(addr)) == 0x0f0000000fc0c748 &&
			*(unsigned char *)(PT_IP_TO_CODE(addr) + 8) == 0x05)
		return;

	// Walk back up the stack
	for (sp = stacks[pid].sp + 1; ; sp++) {

		// If the stack item is not a call, then the next stack item
		// becomes the return call, and we move to the stack item
		// after the return call
		if (sp->kind != PT_EVENT_CALL) {
			*(sp - 1) = (struct pt_event) {addr, PT_EVENT_RET, 0};
			stacks[pid].sp = sp - 2;
			return;
		}

		// If this stack item is a call, and if the address matches,
		// then we go back in the stack to this position.
		if (sp->addr == addr) {
			stacks[pid].sp = sp;
			return;
		}
	}
}

unsigned long plt_start_addr;
unsigned long plt_end_addr;

#if 0
static inline void pt_reconstruct(struct pt_event *, struct pt_event *, pt_recover_arg);

static inline void pt_find_blame(pt_recover_arg pid)
{
	struct pt_event *sp;
	unsigned long curr_address = stacks[pid].sp->addr;
	for (sp = stacks[pid].sp + 1; sp->kind >= PT_EVENT_NONE && sp->kind <= PT_EVENT_XABORT; sp++) {
		if (sp->kind == PT_EVENT_CALL) {
			printf("  blamed address: %lx at offset %lu\n", sp->addr, sp->offset);
			pt_reconstruct(sp, stacks[pid].sp + 1, pid);
			return;
		}
	}

	printf("  no blamed address found\n");
	return;
}

#define pt_plt_addr(addr, pid) do { \
	if (addr >= plt_start_addr && addr <= plt_end_addr) { \
		printf("  PLT call: %lx\n", addr); \
		pt_find_blame(pid); \
	} \
} while (0)
#endif

#define pt_plt_addr(next_addr, ip, pid) do { \
	if (next_addr >= plt_start_addr && next_addr <= plt_end_addr) { \
		printf("  PLT call: %lx\n", ip); \
	} \
} while (0)

static inline void pt_on_xbegin(pt_recover_arg pid)
{
	if (!stacks[pid].xbegin) {
		*(stacks[pid].sp--) = (struct pt_event) {0, PT_EVENT_XBEGIN, 0};
		stacks[pid].xbegin = stacks[pid].sp + 1;
	}
}

static inline void pt_on_xcommit(pt_recover_arg pid, unsigned char * offset)
{
	struct pt_event *old_sp, *sp;

	if (!stacks[pid].xbegin)
		return;

	old_sp = stacks[pid].sp;
	stacks[pid].sp = stacks[pid].xbegin;

	for (sp = stacks[pid].xbegin - 1; sp > old_sp; sp--) {
		if (sp->kind == PT_EVENT_CALL)
			pt_on_call(sp->addr, pid, offset);
		else if (sp->kind == PT_EVENT_RET)
			pt_on_ret(sp->addr, pid);
		else
			ABORT(1, "unexpected event type (%d) while commit", sp->kind);
	}

	stacks[pid].xbegin = NULL;
}

static inline void pt_on_xabort(pt_recover_arg pid)
{
	ABORT(!stacks[pid].xbegin, "abort outside a transaction");

	stacks[pid].sp = stacks[pid].xbegin;
	stacks[pid].xbegin = NULL;
}

#define pt_on_mode(mode_payload, pid)

static inline void pt_on_syscall(unsigned long addr)
{
	printf("  syscall: %lx\n", addr);
}

static inline void pt_on_direct_call(unsigned long addr)
{
	printf("  direct_call: %lx\n", addr);
}

static inline void pt_on_indirect_call(unsigned long addr)
{
	printf("  indirect_call: %lx\n", addr);
}

static inline void pt_on_return(unsigned long addr)
{
	printf("  return: %lx\n", addr);
}

static inline void pt_on_block(unsigned long addr, pt_recover_arg pid)
{
	printf("  block: %lx\n", addr);
}

#define PT_USE_MIRROR

#include "blame.h"

#if 0
static inline void pt_reconstruct(struct pt_event * start_sp, struct pt_event * stop_sp, pt_recover_arg pid)
{
	enum pt_packet_kind kind;
	unsigned long packet_len;
	printf("  reconstruction beginning offset: %lu\n", start_sp->offset);
	printf("  reconstruction ending offset: %lu\n", stop_sp->offset);

	// Todo: Find a way to reconstruct the packets here without duplication
	//kind = pt_get_packet(start_sp->offset, 1000, &packet_len);
	//unsigned long size = (unsigned long)stop_sp->offset - (unsigned long)start_sp->offset;
	//printf("  pid: %lu, size: %lu, char offset: %p\n", pid, size, start_sp->offset);
	//pt_recover((char *)start_sp->offset, size, pid);

	printf("  reconstruction complete\n");
}
#endif

int main(int argc, char *argv[])
{
	FILE *log;
	size_t len;
	struct pt_logfile_header lhdr;
	struct pt_logitem_header header;
	struct pt_logitem_buffer *buffer;
	struct pt_logitem_process *process;
	struct pt_logitem_thread *thread;
	struct pt_logitem_image *image;
	struct pt_logitem_xpage *xpage;
	void *addr;
	struct pt_logitem_unmap *unmap;
	struct pt_logitem_fork *fork;
	void *item;
	struct pt_event *sp;
	int i;

	ABORT(argc < 4, "./blame log-file plt-start-addr-hex plt-end-addr-hex");

	log = fopen(argv[1], "r");
	ABORT(!log, "open %s failed", argv[1]);

	// Get the PLT range to trigger the blame investigation
	plt_start_addr = strtol(argv[2], NULL, 16);
	plt_end_addr = strtol(argv[3], NULL, 16);

	len = fread(&lhdr, 1, sizeof(lhdr), log);
	ABORT(len < sizeof(lhdr), "corrupted log");
	ABORT(lhdr.magic != MAGIC, "unmatched magic");
	ABORT(lhdr.version != VERSION, "unmatched version");

	while ((len = fread(&header, 1, sizeof(header), log))) {
		/* undo the seek due to header read */
		fseek(log, -sizeof(header), SEEK_CUR);

		/* allocate memory to store the whole item */
		item = malloc(header.size);
		ABORT(!item, "malloc for item failed");

		/* read in */
		len = fread(item, 1, header.size, log);
		ABORT(len != header.size, "unexpected log ending");

		switch (header.kind) {
		case PT_LOGITEM_BUFFER:
			buffer = (struct pt_logitem_buffer *) item;
			printf("buffer: pid=%lu, size=%lu\n", buffer->pid, buffer->size);
			pt_recover((char *)(buffer + 1), buffer->size, buffer->pid);
			break;
		case PT_LOGITEM_PROCESS:
			process = (struct pt_logitem_process *) item;
			printf("process: tgid=%lu, cmd=%s\n", process->tgid, (char *) (process + 1));
			break;
		case PT_LOGITEM_THREAD:
			thread = (struct pt_logitem_thread *) item;
			printf("thread: tgid=%lu, pid=%lu\n", thread->tgid, thread->pid);
			if (stacks[thread->pid].top)
				break;
			stacks[thread->pid].top = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
			ABORT(!stacks[thread->pid].top, "stack allocation failed");
			stacks[thread->pid].top += PAGE_SIZE;
			stacks[thread->pid].sp = ((struct pt_event *) stacks[thread->pid].top) - 1;
			stacks[thread->pid].xbegin = NULL;
			break;
		case PT_LOGITEM_IMAGE:
			ABORT(1, "IMAGE unsupported");
			break;
		case PT_LOGITEM_XPAGE:
			xpage = (struct pt_logitem_xpage *) item;
			printf("xpage: tgid=%lu, base=%llx, size=%llx\n", xpage->tgid, xpage->base, xpage->size);
			for (i = 1; i < 10; i++) {
				addr = mmap((void *) MIRROR(xpage->base, i), xpage->size,
						PROT_READ | PROT_WRITE, MAP_ANONYMOUS
						| MAP_PRIVATE | MAP_FIXED, -1, 0);
				ABORT((unsigned long) addr != MIRROR(xpage->base, i), "mirror failed");
			}
			memcpy((void *) PT_IP_TO_CODE(xpage->base), xpage + 1, xpage->size);
			break;
		case PT_LOGITEM_UNMAP:
			ABORT(1, "UNMAP unsupported");
			break;
		case PT_LOGITEM_FORK:
			fork = (struct pt_logitem_fork *) item;
			printf("fork: parent=%lu, child=%lu\n", fork->parent_pid, fork->child_pid);
			stacks[fork->child_pid].top = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
			ABORT(!stacks[fork->child_pid].top, "stack allocation failed");
			stacks[fork->child_pid].top += PAGE_SIZE;
			stacks[fork->child_pid].sp = ((struct pt_event *) stacks[fork->child_pid].top) - 1;
			stacks[fork->child_pid].xbegin = stacks[fork->parent_pid].xbegin;
			ABORT(stacks[fork->child_pid].xbegin, "fork in transaction?");
			/* duplicate call stack from parent thread */
			for (sp = stacks[fork->parent_pid].top - 1; sp > stacks[fork->parent_pid].sp; sp--)
				*(stacks[fork->child_pid].sp--) = *sp;
			break;
		default:
			ABORT(1, "unrecognized item type: %d", header.kind);
		}

		free(item);
	}

	fclose(log);
}
