/*
   american fuzzy lop++ - instrumentation bootstrap
   ------------------------------------------------

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0


*/

#ifdef __ANDROID__
  #include "android-ashmem.h"
#endif
#include "config.h"
#include "types.h"
#include "cmplog.h"
#include "funclog.h"
#include "llvm-ngram-coverage.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <errno.h>

#include <sys/mman.h>
#ifndef __HAIKU__
  #include <sys/shm.h>
#endif
#include <sys/wait.h>
#include <sys/types.h>
#include <dirent.h>

#if !__GNUC__
  #include "llvm/Config/llvm-config.h"
#endif

#ifdef __linux__
  #include "snapshot-inl.h"
#endif

/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifndef MAP_FIXED_NOREPLACE
  #ifdef MAP_EXCL
    #define MAP_FIXED_NOREPLACE MAP_EXCL | MAP_FIXED
  #else
    #define MAP_FIXED_NOREPLACE MAP_FIXED
  #endif
#endif

#define CTOR_PRIO 3

#include <sys/mman.h>
#include <fcntl.h>

/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to
   run. It will end up as .comm, so it shouldn't be too wasteful. */

#if MAP_SIZE <= 65536
  #define MAP_INITIAL_SIZE 2097152
#else
  #define MAP_INITIAL_SIZE MAP_SIZE
#endif

#define FUNC_MAP_INITIAL_SIZE 10000

u8   __afl_area_initial[MAP_INITIAL_SIZE];
u8 * __afl_area_ptr_dummy = __afl_area_initial;
u8 * __afl_area_ptr = __afl_area_initial;
u8 * __afl_area_ptr_backup = __afl_area_initial;
u8 * __afl_dictionary;
u8 * __afl_fuzz_ptr;
u32  __afl_fuzz_len_dummy;
u32 *__afl_fuzz_len = &__afl_fuzz_len_dummy;

u8 __afl_func_area_initial[FUNC_MAP_INITIAL_SIZE];
u8 * __afl_func_area_ptr = __afl_func_area_initial;

u32 __afl_final_loc;
u32 __afl_map_size = MAP_SIZE;
u32 __afl_dictionary_len;
u64 __afl_map_addr;

char __afl_write_files_initial[1000];
char * __afl_write_files = __afl_write_files_initial;
u32 __afl_write_file_len;

// for the __AFL_COVERAGE_ON/__AFL_COVERAGE_OFF features to work:
int __afl_selective_coverage __attribute__((weak));
int __afl_selective_coverage_start_off __attribute__((weak));
int __afl_selective_coverage_temp = 1;

#if defined(__ANDROID__) || defined(__HAIKU__)
PREV_LOC_T __afl_prev_loc[NGRAM_SIZE_MAX];
u32        __afl_prev_ctx;
u32        __afl_cmp_counter;
#else
__thread PREV_LOC_T __afl_prev_loc[NGRAM_SIZE_MAX];
__thread u32        __afl_prev_ctx;
__thread u32        __afl_cmp_counter;
#endif

int __afl_sharedmem_fuzzing __attribute__((weak));

struct cmp_map *__afl_cmp_map;
struct cmp_map *__afl_cmp_map_backup;
static struct cmp_entry * __afl_branch_map;

/* Child pid? */

static s32 child_pid;
static void (*old_sigterm_handler)(int) = 0;

/* Running in persistent mode? */

static u8 is_persistent;

/* Are we in sancov mode? */

static u8 _is_sancov;

/* ensure we kill the child on termination */

void at_exit(int signal) {

  if (child_pid > 0) { kill(child_pid, SIGKILL); }

}

/* Uninspired gcc plugin instrumentation */

void __afl_trace(const u32 x) {

  PREV_LOC_T prev = __afl_prev_loc[0];
  __afl_prev_loc[0] = (x >> 1);

  u8 *p = &__afl_area_ptr[prev ^ x];

#if 1                                      /* enable for neverZero feature. */
  #if __GNUC__
  u8 c = __builtin_add_overflow(*p, 1, p);
  *p += c;
  #else
  *p += 1 + ((u8)(1 + *p) == 0);
  #endif
#else
  ++*p;
#endif

  return;

}

/* Error reporting to forkserver controller */

void send_forkserver_error(int error) {

  u32 status;
  if (!error || error > 0xffff) return;
  status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(error));
  if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) { return; }

}

/* SHM fuzzing setup. */

static void __afl_map_shm_fuzz() {

  char *id_str = getenv(SHM_FUZZ_ENV_VAR);

  if (getenv("AFL_DEBUG")) {

    fprintf(stderr, "DEBUG: fuzzcase shmem %s\n", id_str ? id_str : "none");

  }

  if (id_str) {

    u8 *map = NULL;

#ifdef USEMMAP
    const char *shm_file_path = id_str;
    int         shm_fd = -1;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
    if (shm_fd == -1) {

      fprintf(stderr, "shm_open() failed for fuzz\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

    map =
        (u8 *)mmap(0, MAX_FILE + sizeof(u32), PROT_READ, MAP_SHARED, shm_fd, 0);

#else
    u32 shm_id = atoi(id_str);
    map = (u8 *)shmat(shm_id, NULL, 0);

#endif

    /* Whooooops. */

    if (!map || map == (void *)-1) {

      perror("Could not access fuzzing shared memory");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

    __afl_fuzz_len = (u32 *)map;
    __afl_fuzz_ptr = map + sizeof(u32);

    if (getenv("AFL_DEBUG")) {

      fprintf(stderr, "DEBUG: successfully got fuzzing shared memory\n");

    }

  } else {

    fprintf(stderr, "Error: variable for fuzzing shared memory is not set\n");
    send_forkserver_error(FS_ERROR_SHM_OPEN);
    exit(1);

  }

}

/* SHM setup. */

static void __afl_map_shm(void) {

  // if we are not running in afl ensure the map exists
  if (!__afl_area_ptr) { __afl_area_ptr = __afl_area_ptr_dummy; }

  char *id_str = getenv(SHM_ENV_VAR);

  if (__afl_final_loc) {

    if (__afl_final_loc % 64) {

      __afl_final_loc = (((__afl_final_loc + 63) >> 6) << 6);

    }

    __afl_map_size = __afl_final_loc;

    if (__afl_final_loc > MAP_SIZE) {

      char *ptr;
      u32   val = 0;
      if ((ptr = getenv("AFL_MAP_SIZE")) != NULL) val = atoi(ptr);
      if (val < __afl_final_loc) {

        if (__afl_final_loc > FS_OPT_MAX_MAPSIZE) {

          if (!getenv("AFL_QUIET"))
            fprintf(stderr,
                    "Error: AFL++ tools *require* to set AFL_MAP_SIZE to %u "
                    "to be able to run this instrumented program!\n",
                    __afl_final_loc);

          if (id_str) {

            send_forkserver_error(FS_ERROR_MAP_SIZE);
            exit(-1);

          }

        } else {

          if (!getenv("AFL_QUIET"))
            fprintf(stderr,
                    "Warning: AFL++ tools will need to set AFL_MAP_SIZE to %u "
                    "to be able to run this instrumented program!\n",
                    __afl_final_loc);

        }

      }

    }

  }

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (getenv("AFL_DEBUG"))
    fprintf(stderr,
            "DEBUG: id_str %s, __afl_area_ptr %p, __afl_area_initial %p, "
            "__afl_map_addr 0x%llx, MAP_SIZE %u, __afl_final_loc %u, "
            "max_size_forkserver %u/0x%x\n",
            id_str == NULL ? "<null>" : id_str, __afl_area_ptr,
            __afl_area_initial, __afl_map_addr, MAP_SIZE, __afl_final_loc,
            FS_OPT_MAX_MAPSIZE, FS_OPT_MAX_MAPSIZE);

  if (id_str) {

    if (__afl_area_ptr && __afl_area_ptr != __afl_area_initial) {

      if (__afl_map_addr) {

        munmap((void *)__afl_map_addr, __afl_final_loc);

      } else {

        free(__afl_area_ptr);

      }

      __afl_area_ptr = __afl_area_ptr_dummy;

    }

#ifdef USEMMAP
    const char *   shm_file_path = id_str;
    int            shm_fd = -1;
    unsigned char *shm_base = NULL;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
    if (shm_fd == -1) {

      fprintf(stderr, "shm_open() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

    /* map the shared memory segment to the address space of the process */
    if (__afl_map_addr) {

      shm_base =
          mmap((void *)__afl_map_addr, __afl_map_size, PROT_READ | PROT_WRITE,
               MAP_FIXED_NOREPLACE | MAP_SHARED, shm_fd, 0);

    } else {

      shm_base = mmap(0, __afl_map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                      shm_fd, 0);

    }

    if (shm_base == MAP_FAILED) {

      close(shm_fd);
      shm_fd = -1;

      fprintf(stderr, "mmap() failed\n");
      if (__afl_map_addr)
        send_forkserver_error(FS_ERROR_MAP_ADDR);
      else
        send_forkserver_error(FS_ERROR_MMAP);
      perror("mmap for map");

      exit(2);

    }

    __afl_area_ptr = shm_base;
#else
    u32 shm_id = atoi(id_str);

    if (__afl_map_size && __afl_map_size > MAP_SIZE) {

      u8 *map_env = (u8 *)getenv("AFL_MAP_SIZE");
      if (!map_env || atoi((char *)map_env) < MAP_SIZE) {

        send_forkserver_error(FS_ERROR_MAP_SIZE);
        _exit(1);

      }

    }

    __afl_area_ptr = (u8 *)shmat(shm_id, (void *)__afl_map_addr, 0);

    /* Whooooops. */

    if (!__afl_area_ptr || __afl_area_ptr == (void *)-1) {

      if (__afl_map_addr)
        send_forkserver_error(FS_ERROR_MAP_ADDR);
      else
        send_forkserver_error(FS_ERROR_SHMAT);

      perror("shmat for map");
      _exit(1);

    }

#endif

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  } else if ((!__afl_area_ptr || __afl_area_ptr == __afl_area_initial) &&

             __afl_map_addr) {

    __afl_area_ptr = (u8 *)mmap(
        (void *)__afl_map_addr, __afl_map_size, PROT_READ | PROT_WRITE,
        MAP_FIXED_NOREPLACE | MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (__afl_area_ptr == MAP_FAILED) {

      fprintf(stderr, "can not acquire mmap for address %p\n",
              (void *)__afl_map_addr);
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

  } else if (_is_sancov && __afl_area_ptr != __afl_area_initial) {

    free(__afl_area_ptr);
    __afl_area_ptr = NULL;

    if (__afl_final_loc > MAP_INITIAL_SIZE) {

      __afl_area_ptr = (u8 *)malloc(__afl_final_loc);

    }

    if (!__afl_area_ptr) { __afl_area_ptr = __afl_area_ptr_dummy; }

  }

  __afl_area_ptr_backup = __afl_area_ptr;

  if (__afl_selective_coverage) {

    if (__afl_map_size > MAP_INITIAL_SIZE) {

      __afl_area_ptr_dummy = (u8 *)malloc(__afl_map_size);

      if (__afl_area_ptr_dummy) {

        if (__afl_selective_coverage_start_off) {

          __afl_area_ptr = __afl_area_ptr_dummy;

        }

      } else {

        fprintf(stderr, "Error: __afl_selective_coverage failed!\n");
        __afl_selective_coverage = 0;
        // continue;

      }

    }

  }

  id_str = getenv(CMPLOG_SHM_ENV_VAR);

  if (getenv("AFL_DEBUG")) {

    fprintf(stderr, "DEBUG: cmplog id_str %s\n",
            id_str == NULL ? "<null>" : id_str);

  }

  if (id_str) {

#ifdef USEMMAP
    const char *    shm_file_path = id_str;
    int             shm_fd = -1;
    struct cmp_map *shm_base = NULL;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
    if (shm_fd == -1) {

      perror("shm_open() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

    /* map the shared memory segment to the address space of the process */
    shm_base = mmap(0, sizeof(struct cmp_map), PROT_READ | PROT_WRITE,
                    MAP_SHARED, shm_fd, 0);
    if (shm_base == MAP_FAILED) {

      close(shm_fd);
      shm_fd = -1;

      fprintf(stderr, "mmap() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(2);

    }

    __afl_cmp_map = shm_base;
#else
    u32 shm_id = atoi(id_str);

    __afl_cmp_map = (struct cmp_map *)shmat(shm_id, NULL, 0);
#endif

    __afl_cmp_map_backup = __afl_cmp_map;

    if (!__afl_cmp_map || __afl_cmp_map == (void *)-1) {

      perror("shmat for cmplog");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      _exit(1);

    }

  }

  id_str = getenv(AFL_FUNC_SHM_ENV_VAR);

  if (getenv("AFL_DEBUG")) {
    fprintf(stderr, "DEBUG: func id_str %s\n",
            id_str == NULL ? "<null>" : id_str);
  }

  if(id_str) {
    u32 shm_id = atoi(id_str);
    __afl_branch_map = shmat(shm_id, NULL, 0);

    if (__afl_branch_map == (void *)-1) _exit(1);
  }

  id_str = getenv(AFL_FILEN_SHM_ENV_VAR);

  if (getenv("AFL_DEBUG")) {
    fprintf(stderr, "DEBUG: filen id_str %s\n",
            id_str == NULL ? "<null>" : id_str);
  }

  if(id_str) {
    u32 shm_id = atoi(id_str);
    __afl_write_files = shmat(shm_id, NULL, 0);

    if (__afl_write_files == (void *)-1) _exit(1);
  }

}

#ifdef __linux__
static void __afl_start_snapshots(void) {

  static u8 tmp[4] = {0, 0, 0, 0};
  u32       status = 0;
  u32       already_read_first = 0;
  u32       was_killed;

  u8 child_stopped = 0;

  void (*old_sigchld_handler)(int) = 0;  // = signal(SIGCHLD, SIG_DFL);

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  status |= (FS_OPT_ENABLED | FS_OPT_SNAPSHOT);
  if (__afl_sharedmem_fuzzing != 0) status |= FS_OPT_SHDMEM_FUZZ;
  if (__afl_map_size <= FS_OPT_MAX_MAPSIZE)
    status |= (FS_OPT_SET_MAPSIZE(__afl_map_size) | FS_OPT_MAPSIZE);
  if (__afl_dictionary_len && __afl_dictionary) status |= FS_OPT_AUTODICT;
  memcpy(tmp, &status, 4);

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) { return; }

  if (__afl_sharedmem_fuzzing || (__afl_dictionary_len && __afl_dictionary)) {

    if (read(FORKSRV_FD, &was_killed, 4) != 4) { _exit(1); }

    if (getenv("AFL_DEBUG")) {

      fprintf(stderr, "target forkserver recv: %08x\n", was_killed);

    }

    if ((was_killed & (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ)) ==
        (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ)) {

      __afl_map_shm_fuzz();

    }

    if ((was_killed & (FS_OPT_ENABLED | FS_OPT_AUTODICT)) ==
            (FS_OPT_ENABLED | FS_OPT_AUTODICT) &&
        __afl_dictionary_len && __afl_dictionary) {

      // great lets pass the dictionary through the forkserver FD
      u32 len = __afl_dictionary_len, offset = 0;
      s32 ret;

      if (write(FORKSRV_FD + 1, &len, 4) != 4) {

        write(2, "Error: could not send dictionary len\n",
              strlen("Error: could not send dictionary len\n"));
        _exit(1);

      }

      while (len != 0) {

        ret = write(FORKSRV_FD + 1, __afl_dictionary + offset, len);

        if (ret < 1) {

          write(2, "Error: could not send dictionary\n",
                strlen("Error: could not send dictionary\n"));
          _exit(1);

        }

        len -= ret;
        offset += ret;

      }

    } else {

      // uh this forkserver does not understand extended option passing
      // or does not want the dictionary
      if (!__afl_fuzz_ptr) already_read_first = 1;

    }

  }

  while (1) {

    int status;

    if (already_read_first) {

      already_read_first = 0;

    } else {

      /* Wait for parent by reading from the pipe. Abort if read fails. */
      if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    }

  #ifdef _AFL_DOCUMENT_MUTATIONS
    if (__afl_fuzz_ptr) {

      static uint32_t counter = 0;
      char            fn[32];
      sprintf(fn, "%09u:forkserver", counter);
      s32 fd_doc = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
      if (fd_doc >= 0) {

        if (write(fd_doc, __afl_fuzz_ptr, *__afl_fuzz_len) != *__afl_fuzz_len) {

          fprintf(stderr, "write of mutation file failed: %s\n", fn);
          unlink(fn);

        }

        close(fd_doc);

      }

      counter++;

    }

  #endif

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {

      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);

    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        //(void)nice(-20);  // does not seem to improve

        signal(SIGCHLD, old_sigchld_handler);
        signal(SIGTERM, old_sigterm_handler);

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);

        if (!afl_snapshot_take(AFL_SNAPSHOT_MMAP | AFL_SNAPSHOT_FDS |
                               AFL_SNAPSHOT_REGS | AFL_SNAPSHOT_EXIT)) {

          raise(SIGSTOP);

        }

        __afl_area_ptr[0] = 1;
        memset(__afl_prev_loc, 0, NGRAM_SIZE_MAX * sizeof(PREV_LOC_T));

        return;

      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, WUNTRACED) < 0) _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}

#endif

/* Fork server logic. */

static void __afl_start_forkserver(void) {

  struct sigaction orig_action;
  sigaction(SIGTERM, NULL, &orig_action);
  old_sigterm_handler = orig_action.sa_handler;
  signal(SIGTERM, at_exit);

#ifdef __linux__
  if (/*!is_persistent &&*/ !__afl_cmp_map && !getenv("AFL_NO_SNAPSHOT") &&
      afl_snapshot_init() >= 0) {

    __afl_start_snapshots();
    return;

  }

#endif

  u8  tmp[4] = {0, 0, 0, 0};
  u32 status_for_fsrv = 0;
  u32 already_read_first = 0;
  u32 was_killed;

  u8 child_stopped = 0;

  void (*old_sigchld_handler)(int) = 0;  // = signal(SIGCHLD, SIG_DFL);

  if (__afl_map_size <= FS_OPT_MAX_MAPSIZE) {

    status_for_fsrv |= (FS_OPT_SET_MAPSIZE(__afl_map_size) | FS_OPT_MAPSIZE);

  }

  if (__afl_dictionary_len && __afl_dictionary) {

    status_for_fsrv |= FS_OPT_AUTODICT;

  }

  if (__afl_sharedmem_fuzzing != 0) { status_for_fsrv |= FS_OPT_SHDMEM_FUZZ; }
  if (status_for_fsrv) { status_for_fsrv |= (FS_OPT_ENABLED); }
  memcpy(tmp, &status_for_fsrv, 4);

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) { return; }

  if (__afl_sharedmem_fuzzing || (__afl_dictionary_len && __afl_dictionary)) {

    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    if (getenv("AFL_DEBUG")) {

      fprintf(stderr, "target forkserver recv: %08x\n", was_killed);

    }

    if ((was_killed & (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ)) ==
        (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ)) {

      __afl_map_shm_fuzz();

    }

    if ((was_killed & (FS_OPT_ENABLED | FS_OPT_AUTODICT)) ==
            (FS_OPT_ENABLED | FS_OPT_AUTODICT) &&
        __afl_dictionary_len && __afl_dictionary) {

      // great lets pass the dictionary through the forkserver FD
      u32 len = __afl_dictionary_len, offset = 0;

      if (write(FORKSRV_FD + 1, &len, 4) != 4) {

        write(2, "Error: could not send dictionary len\n",
              strlen("Error: could not send dictionary len\n"));
        _exit(1);

      }

      while (len != 0) {

        s32 ret;
        ret = write(FORKSRV_FD + 1, __afl_dictionary + offset, len);

        if (ret < 1) {

          write(2, "Error: could not send dictionary\n",
                strlen("Error: could not send dictionary\n"));
          _exit(1);

        }

        len -= ret;
        offset += ret;

      }

    } else {

      // uh this forkserver does not understand extended option passing
      // or does not want the dictionary
      if (!__afl_fuzz_ptr) already_read_first = 1;

    }

  }

  while (1) {

    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (already_read_first) {

      already_read_first = 0;

    } else {

      if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    }

#ifdef _AFL_DOCUMENT_MUTATIONS
    if (__afl_fuzz_ptr) {

      static uint32_t counter = 0;
      char            fn[32];
      sprintf(fn, "%09u:forkserver", counter);
      s32 fd_doc = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
      if (fd_doc >= 0) {

        if (write(fd_doc, __afl_fuzz_ptr, *__afl_fuzz_len) != *__afl_fuzz_len) {

          fprintf(stderr, "write of mutation file failed: %s\n", fn);
          unlink(fn);

        }

        close(fd_doc);

      }

      counter++;

    }

#endif

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {

      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);

    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        //(void)nice(-20);

        signal(SIGCHLD, old_sigchld_handler);
        signal(SIGTERM, old_sigterm_handler);

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;

      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}

/* A simplified persistent mode handler, used as explained in
 * README.llvm.md. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(__afl_area_ptr, 0, __afl_map_size);
      __afl_area_ptr[0] = 1;
      memset(__afl_prev_loc, 0, NGRAM_SIZE_MAX * sizeof(PREV_LOC_T));

    }

    cycle_cnt = max_cnt;
    first_pass = 0;
    __afl_selective_coverage_temp = 1;

    return 1;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      raise(SIGSTOP);

      __afl_area_ptr[0] = 1;
      memset(__afl_prev_loc, 0, NGRAM_SIZE_MAX * sizeof(PREV_LOC_T));
      __afl_selective_coverage_temp = 1;

      return 1;

    } else {

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */

      __afl_area_ptr = __afl_area_ptr_dummy;

    }

  }

  return 0;

}

/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static u8 init_done;

  if (getenv("AFL_DISABLE_LLVM_INSTRUMENTATION")) {

    init_done = 1;
    is_persistent = 0;
    __afl_sharedmem_fuzzing = 0;
    if (__afl_area_ptr == NULL) __afl_area_ptr = __afl_area_ptr_dummy;

    if (getenv("AFL_DEBUG"))
      fprintf(stderr,
              "DEBUG: disabled instrumentation because of "
              "AFL_DISABLE_LLVM_INSTRUMENTATION\n");

  }

  if (!init_done) {

    __afl_start_forkserver();
    init_done = 1;

  }

}

/* Initialization of the forkserver - latest possible */

__attribute__((constructor())) void __afl_auto_init(void) {

  if (getenv("AFL_DISABLE_LLVM_INSTRUMENTATION")) return;

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}

/* Initialization of the shmem - earliest possible because of LTO fixed mem. */

__attribute__((constructor(CTOR_PRIO))) void __afl_auto_early(void) {

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv("AFL_DISABLE_LLVM_INSTRUMENTATION")) return;

  __afl_map_shm();

}

/* preset __afl_area_ptr #2 */

__attribute__((constructor(1))) void __afl_auto_second(void) {

  if (getenv("AFL_DISABLE_LLVM_INSTRUMENTATION")) return;
  u8 *ptr;

  if (__afl_final_loc) {

    if (__afl_area_ptr && __afl_area_ptr != __afl_area_initial)
      free(__afl_area_ptr);

    if (__afl_map_addr)
      ptr = (u8 *)mmap((void *)__afl_map_addr, __afl_final_loc,
                       PROT_READ | PROT_WRITE,
                       MAP_FIXED_NOREPLACE | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    else
      ptr = (u8 *)malloc(__afl_final_loc);

    if (ptr && (ssize_t)ptr != -1) {

      __afl_area_ptr = ptr;
      __afl_area_ptr_backup = __afl_area_ptr;

    }

  }

}

/* preset __afl_area_ptr #1 - at constructor level 0 global variables have
   not been set */

__attribute__((constructor(0))) void __afl_auto_first(void) {

  if (getenv("AFL_DISABLE_LLVM_INSTRUMENTATION")) return;
  u8 *ptr;

  ptr = (u8 *)malloc(MAP_INITIAL_SIZE);

  if (ptr && (ssize_t)ptr != -1) {

    __afl_area_ptr = ptr;
    __afl_area_ptr_backup = __afl_area_ptr;

  }

}

/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.md.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {

  // For stability analysis, if you want to know to which function unstable
  // edge IDs belong - uncomment, recompile+install llvm_mode, recompile
  // the target. libunwind and libbacktrace are better solutions.
  // Set AFL_DEBUG_CHILD=1 and run afl-fuzz with 2>file to capture
  // the backtrace output
  /*
  uint32_t unstable[] = { ... unstable edge IDs };
  uint32_t idx;
  char bt[1024];
  for (idx = 0; i < sizeof(unstable)/sizeof(uint32_t); i++) {

    if (unstable[idx] == __afl_area_ptr[*guard]) {

      int bt_size = backtrace(bt, 256);
      if (bt_size > 0) {

        char **bt_syms = backtrace_symbols(bt, bt_size);
        if (bt_syms) {

          fprintf(stderr, "DEBUG: edge=%u caller=%s\n", unstable[idx],
  bt_syms[0]);
          free(bt_syms);

        }

      }

    }

  }

  */

#if (LLVM_VERSION_MAJOR < 9)

  __afl_area_ptr[*guard]++;

#else

  __afl_area_ptr[*guard] =
      __afl_area_ptr[*guard] + 1 + (__afl_area_ptr[*guard] == 255 ? 1 : 0);

#endif

}

/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {

  u32   inst_ratio = 100;
  char *x;

  _is_sancov = 1;

  if (getenv("AFL_DEBUG")) {

    fprintf(stderr,
            "Running __sanitizer_cov_trace_pc_guard_init: %p-%p (%lu edges)\n",
            start, stop, (unsigned long)(stop - start));

  }

  if (start == stop || *start) return;

  x = getenv("AFL_INST_RATIO");
  if (x) inst_ratio = (u32)atoi(x);

  if (!inst_ratio || inst_ratio > 100) {

    fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
    abort();

  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  *(start++) = ++__afl_final_loc;

  while (start < stop) {

    if (R(100) < inst_ratio)
      *start = ++__afl_final_loc;
    else
      *start = 0;

    start++;

  }

}

void __cmp_log_hook(uint32_t cmpid, uint32_t condition, uint32_t value) {
  if (unlikely(!__afl_branch_map)) {
    //fprintf(stderr, "cmpid : %u, condition : %u\n", cmpid, condition);
    return;
  }

  __afl_branch_map[cmpid].value = condition;
  u8 cond = condition ? 2 : 1;
  __afl_branch_map[cmpid].condition |= cond;
}

ssize_t __read_wrapper(int fd, void * buf, size_t nbytes) {
  size_t cur_pos = lseek(fd, 0, SEEK_CUR);
  ssize_t read_bytes = read(fd, buf, nbytes);
  fprintf(stderr, "fd : %i, offset : %ld~%ld\n", fd, cur_pos, cur_pos + read_bytes);
  return read_bytes;
}

ssize_t __pread_wrapper(int fd, void * buf, size_t nbyte, off_t offset) {
  size_t cur_pos = lseek(fd, 0, SEEK_CUR);
  ssize_t read_bytes = pread(fd, buf, nbyte, offset);
  fprintf(stderr, "fd : %i, offset : %ld~%ld\n", fd, cur_pos, cur_pos + read_bytes);
  return read_bytes;
}

size_t __fread_wrapper(void *ptr, size_t size, size_t nmemb, FILE * stream) {
  long cur_pos = ftell(stream);
  size_t read_bytes = fread(ptr, size, nmemb, stream);
  fprintf(stderr, "fstream : %p, offset : %lu~%lu\n", stream, cur_pos, cur_pos + (read_bytes * size));
  return read_bytes;
}

///// CmpLog instrumentation

void __cmplog_ins_hook1(uint8_t arg1, uint8_t arg2, uint8_t attr) {

  // fprintf(stderr, "hook1 arg0=%02x arg1=%02x attr=%u\n",
  //         (u8) arg1, (u8) arg2, attr);

  if (unlikely(!__afl_cmp_map || arg1 == arg2)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 0;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

void __cmplog_ins_hook2(uint16_t arg1, uint16_t arg2, uint8_t attr) {

  if (unlikely(!__afl_cmp_map || arg1 == arg2)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 1;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (!__afl_cmp_map->headers[k].shape) {

      __afl_cmp_map->headers[k].shape = 1;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

void __cmplog_ins_hook4(uint32_t arg1, uint32_t arg2, uint8_t attr) {

  // fprintf(stderr, "hook4 arg0=%x arg1=%x attr=%u\n", arg1, arg2, attr);

  if (unlikely(!__afl_cmp_map || arg1 == arg2)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 3;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < 3) {

      __afl_cmp_map->headers[k].shape = 3;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

void __cmplog_ins_hook8(uint64_t arg1, uint64_t arg2, uint8_t attr) {

  // fprintf(stderr, "hook8 arg0=%lx arg1=%lx attr=%u\n", arg1, arg2, attr);

  if (unlikely(!__afl_cmp_map || arg1 == arg2)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 7;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < 7) {

      __afl_cmp_map->headers[k].shape = 7;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

#ifdef WORD_SIZE_64
// support for u24 to u120 via llvm _ExitInt(). size is in bytes minus 1
void __cmplog_ins_hookN(uint128_t arg1, uint128_t arg2, uint8_t attr,
                        uint8_t size) {

  // fprintf(stderr, "hookN arg0=%llx:%llx arg1=%llx:%llx bytes=%u attr=%u\n",
  // (u64)(arg1 >> 64), (u64)arg1, (u64)(arg2 >> 64), (u64)arg2, size + 1,
  // attr);

  if (unlikely(!__afl_cmp_map || arg1 == arg2)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = size;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < size) {

      __afl_cmp_map->headers[k].shape = size;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = (u64)arg1;
  __afl_cmp_map->log[k][hits].v1 = (u64)arg2;

  if (size > 7) {

    __afl_cmp_map->log[k][hits].v0_128 = (u64)(arg1 >> 64);
    __afl_cmp_map->log[k][hits].v1_128 = (u64)(arg2 >> 64);

  }

}

void __cmplog_ins_hook16(uint128_t arg1, uint128_t arg2, uint8_t attr) {

  if (unlikely(!__afl_cmp_map)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 15;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < 15) {

      __afl_cmp_map->headers[k].shape = 15;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = (u64)arg1;
  __afl_cmp_map->log[k][hits].v1 = (u64)arg2;
  __afl_cmp_map->log[k][hits].v0_128 = (u64)(arg1 >> 64);
  __afl_cmp_map->log[k][hits].v1_128 = (u64)(arg2 >> 64);

}

#endif

void __sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2) {

  __cmplog_ins_hook1(arg1, arg2, 0);

}

void __sanitizer_cov_trace_const_cmp1(uint8_t arg1, uint8_t arg2) {

  __cmplog_ins_hook1(arg1, arg2, 0);

}

void __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2) {

  __cmplog_ins_hook2(arg1, arg2, 0);

}

void __sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2) {

  __cmplog_ins_hook2(arg1, arg2, 0);

}

void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {

  __cmplog_ins_hook4(arg1, arg2, 0);

}

void __sanitizer_cov_trace_cost_cmp4(uint32_t arg1, uint32_t arg2) {

  __cmplog_ins_hook4(arg1, arg2, 0);

}

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {

  __cmplog_ins_hook8(arg1, arg2, 0);

}

void __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2) {

  __cmplog_ins_hook8(arg1, arg2, 0);

}

#ifdef WORD_SIZE_64
void __sanitizer_cov_trace_cmp16(uint128_t arg1, uint128_t arg2) {

  __cmplog_ins_hook16(arg1, arg2, 0);

}

#endif

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {

  if (unlikely(!__afl_cmp_map)) return;

  for (uint64_t i = 0; i < cases[0]; i++) {

    uintptr_t k = (uintptr_t)__builtin_return_address(0) + i;
    k = (k >> 4) ^ (k << 8);
    k &= CMP_MAP_W - 1;

    u32 hits;

    if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

      __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
      hits = 0;
      __afl_cmp_map->headers[k].hits = 1;
      __afl_cmp_map->headers[k].shape = 7;

    } else {

      hits = __afl_cmp_map->headers[k].hits++;

      if (__afl_cmp_map->headers[k].shape < 7) {

        __afl_cmp_map->headers[k].shape = 7;

      }

    }

    __afl_cmp_map->headers[k].attribute = 1;

    hits &= CMP_MAP_H - 1;
    __afl_cmp_map->log[k][hits].v0 = val;
    __afl_cmp_map->log[k][hits].v1 = cases[i + 2];

  }

}

// POSIX shenanigan to see if an area is mapped.
// If it is mapped as X-only, we have a problem, so maybe we should add a check
// to avoid to call it on .text addresses
static int area_is_mapped(void *ptr, size_t len) {

  char *p = (char *)ptr;
  char *page = (char *)((uintptr_t)p & ~(sysconf(_SC_PAGE_SIZE) - 1));

  int r = msync(page, (p - page) + len, MS_ASYNC);
  if (r < 0) return errno != ENOMEM;
  return 1;

}

void __cmplog_rtn_hook(u8 *ptr1, u8 *ptr2) {

  /*
    u32 i;
    if (!area_is_mapped(ptr1, 32) || !area_is_mapped(ptr2, 32)) return;
    fprintf(stderr, "rtn arg0=");
    for (i = 0; i < 24; i++)
      fprintf(stderr, "%02x", ptr1[i]);
    fprintf(stderr, " arg1=");
    for (i = 0; i < 24; i++)
      fprintf(stderr, "%02x", ptr2[i]);
    fprintf(stderr, "\n");
  */

  if (unlikely(!__afl_cmp_map)) return;

  if (!area_is_mapped(ptr1, 32) || !area_is_mapped(ptr2, 32)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_RTN) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_RTN;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 31;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < 31) {

      __afl_cmp_map->headers[k].shape = 31;

    }

  }

  hits &= CMP_MAP_RTN_H - 1;
  __builtin_memcpy(((struct cmpfn_operands *)__afl_cmp_map->log[k])[hits].v0,
                   ptr1, 32);
  __builtin_memcpy(((struct cmpfn_operands *)__afl_cmp_map->log[k])[hits].v1,
                   ptr2, 32);

}

// gcc libstdc++
// _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc
static u8 *get_gcc_stdstring(u8 *string) {

  u32 *len = (u32 *)(string + 8);

  if (*len < 16) {  // in structure

    return (string + 16);

  } else {  // in memory

    u8 **ptr = (u8 **)string;
    return (*ptr);

  }

}

// llvm libc++ _ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocator
//             IcEEE7compareEmmPKcm
static u8 *get_llvm_stdstring(u8 *string) {

  // length is in: if ((string[0] & 1) == 0) u8 len = (string[0] >> 1);
  // or: if (string[0] & 1) u32 *len = (u32 *) (string + 8);

  if (string[0] & 1) {  // in memory

    u8 **ptr = (u8 **)(string + 16);
    return (*ptr);

  } else {  // in structure

    return (string + 1);

  }

}

void __cmplog_rtn_gcc_stdstring_cstring(u8 *stdstring, u8 *cstring) {

  if (unlikely(!__afl_cmp_map)) return;
  if (!area_is_mapped(stdstring, 32) || !area_is_mapped(cstring, 32)) return;

  __cmplog_rtn_hook(get_gcc_stdstring(stdstring), cstring);

}

void __cmplog_rtn_gcc_stdstring_stdstring(u8 *stdstring1, u8 *stdstring2) {

  if (unlikely(!__afl_cmp_map)) return;
  if (!area_is_mapped(stdstring1, 32) || !area_is_mapped(stdstring2, 32))
    return;

  __cmplog_rtn_hook(get_gcc_stdstring(stdstring1),
                    get_gcc_stdstring(stdstring2));

}

void __cmplog_rtn_llvm_stdstring_cstring(u8 *stdstring, u8 *cstring) {

  if (unlikely(!__afl_cmp_map)) return;
  if (!area_is_mapped(stdstring, 32) || !area_is_mapped(cstring, 32)) return;

  __cmplog_rtn_hook(get_llvm_stdstring(stdstring), cstring);

}

void __cmplog_rtn_llvm_stdstring_stdstring(u8 *stdstring1, u8 *stdstring2) {

  if (unlikely(!__afl_cmp_map)) return;
  if (!area_is_mapped(stdstring1, 32) || !area_is_mapped(stdstring2, 32))
    return;

  __cmplog_rtn_hook(get_llvm_stdstring(stdstring1),
                    get_llvm_stdstring(stdstring2));

}

/* COVERAGE manipulation features */

// this variable is then used in the shm setup to create an additional map
// if __afl_map_size > MAP_SIZE or cmplog is used.
// Especially with cmplog this would result in a ~260MB mem increase per
// target run.

// disable coverage from this point onwards until turned on again
void __afl_coverage_off() {

  if (likely(__afl_selective_coverage)) {

    __afl_area_ptr = __afl_area_ptr_dummy;
    __afl_cmp_map = NULL;

  }

}

// enable coverage
void __afl_coverage_on() {

  if (likely(__afl_selective_coverage && __afl_selective_coverage_temp)) {

    __afl_area_ptr = __afl_area_ptr_backup;
    __afl_cmp_map = __afl_cmp_map_backup;

  }

}

// discard all coverage up to this point
void __afl_coverage_discard() {

  memset(__afl_area_ptr_backup, 0, __afl_map_size);
  __afl_area_ptr_backup[0] = 1;

  if (__afl_cmp_map) { memset(__afl_cmp_map, 0, sizeof(struct cmp_map)); }

}

// discard the testcase
void __afl_coverage_skip() {

  __afl_coverage_discard();

  if (likely(is_persistent && __afl_selective_coverage)) {

    __afl_coverage_off();
    __afl_selective_coverage_temp = 0;

  } else {

    exit(0);

  }

}

// mark this area as especially interesting
void __afl_coverage_interesting(u8 val, u32 id) {

  __afl_area_ptr[id] = val;

}

void __afl_parse_argv(int* argc, char ***argv) {
  if (*argc < 2) {
    fprintf(stderr, "Argc & Argv canno be less than 2.\n");
    return;
  }

  FILE *raw = fopen((*argv)[1], "rb");
  if (raw == NULL) {
    fprintf(stderr, "Can not open file argv[1]\n");
    return;
  }

  const int MAXB = 2048;
  s8 * buffer = (s8 *) malloc(sizeof(s8) * MAXB); //not going to be freed...
  u32 i = 0;
  
  size_t read_bytes = fread(buffer, sizeof(s8), 2048, raw);
  fclose(raw);

  int new_argc = 0;

  for (i = 0; i < read_bytes; i++) {
    if (buffer[i] == '\0') {
      new_argc++;
    }
  }

  char ** new_argv = (char **) malloc(sizeof(char *) * (new_argc + 1));
  u8 is_argv_idx = 1;
  u32 argv_idx = 0;

  for (i = 0; i < read_bytes; i++) {
    if (is_argv_idx) {
      new_argv[argv_idx++] = buffer + i;
      is_argv_idx = 0;
    } else if (buffer[i] == '\0') {
      is_argv_idx = 1;
    }
  }

  new_argv[new_argc] = 0;

  /*
  fprintf(stderr, "Your argc: %d\n", new_argc);
  for (int i = 0; i < new_argc; i++) {
    fprintf(stderr, "Your argv %d: #%s#\n", i, new_argv[i]);
  }
  */

  *argc = new_argc;
  *argv = new_argv;
  return;
}

FILE * __afl_fopen_wrapper(const char * pathname, const char * mode) {
  // fprintf(stderr, "[o] fopen wrapper: %s\n", pathname); // CREATE FILE LOG
  FILE * res = fopen(pathname, mode);
  if (strchr(mode, 'w') && res) {
    size_t len = strlen(pathname);
    if (likely((__afl_write_file_len + len + 2) < 1000)) {
      __afl_write_files[__afl_write_file_len] = 'f';
      memcpy(__afl_write_files + (__afl_write_file_len + 1), pathname, len + 1);
      __afl_write_file_len += len + 2;
    } else {
      fclose(res);
      unlink(pathname);
      return fopen("/dev/null", mode);
    }
  }
  return res;
}

FILE * __afl_freopen_wrapper(const char * pathname, const char * mode, FILE * stream) {
  // fprintf(stderr, "[o] freopen wrapper: %s\n", pathname); // CREATE FILE LOG

  FILE * res = freopen(pathname, mode, stream);
  if (strchr(mode, 'w') && res) {
    size_t len = strlen(pathname);
    if (likely((__afl_write_file_len + len + 2) < 1000)) {
      __afl_write_files[__afl_write_file_len] = 'f';
      memcpy(__afl_write_files + (__afl_write_file_len + 1), pathname, len + 1);
      __afl_write_file_len += len + 2;
    } else {
      fclose(res);
      unlink(pathname);
      return freopen("/dev/null", mode, stream);
    }
  }
  return res;
}

int __afl_open_wrapper(const char *pathname, int flags, ...) {
  // fprintf(stderr, "[o] open wrapper: %s\n", pathname); // CREATE FILE LOG
  int res = open(pathname, flags);
  if ((flags & (O_WRONLY | O_RDWR)) && (res > 0)) {
    size_t len = strlen(pathname);
    if (likely((__afl_write_file_len + len + 2) < 1000)) {
      __afl_write_files[__afl_write_file_len] = 'f';
      memcpy(__afl_write_files + (__afl_write_file_len + 1), pathname, len + 1);
      __afl_write_file_len += len + 2;
    } else {
      close(res);
      unlink(pathname);
      return open("/dev/null", flags);
    }
  }
  return res;
}

int __afl_creat_wrapper (const char * filename, mode_t mode) {
  // fprintf(stderr, "[o] creat wrapper: %s\n", filename); // CREATE FILE LOG
  int res = creat(filename, mode);
  if (res > 0) {
    size_t len = strlen(filename);
    if (likely((__afl_write_file_len + len + 2) < 1000)) {
      __afl_write_files[__afl_write_file_len] = 'f';
      memcpy(__afl_write_files + (__afl_write_file_len + 1), filename, len + 1);
      __afl_write_file_len += len + 2;
    } else {
      close(res);
      unlink(filename);
      return creat("/dev/null", mode);
    }
  }
  return res;
}

int __afl_mkstemp_wrapper (char * filename) {
  // fprintf(stderr, "[o] mkstemp wrapper: %s\n", filename); // CREATE FILE LOG
  int ret = mkstemp(filename);
  if (ret > 0) {
    size_t len = strlen(filename);
    if (likely((__afl_write_file_len + len + 2) < 1000)) {
      __afl_write_files[__afl_write_file_len] = 'f';
      memcpy(__afl_write_files + (__afl_write_file_len + 1), filename, len + 1);
      __afl_write_file_len += len + 2;
    } else {
      unlink(filename);
      return -1;
    }
  }
  return ret;
}

int __afl_mkstemps_wrapper (char * filename, int suffixLen) {
  // fprintf(stderr, "[o] mkstemps wrapper: %s\n", filename); // CREATE FILE LOG
  int ret = mkstemps(filename, suffixLen);
  if (ret > 0) {
    size_t len = strlen(filename);
    if (likely((__afl_write_file_len + len + 2) < 1000)) {
      __afl_write_files[__afl_write_file_len] = 'f';
      memcpy(__afl_write_files + (__afl_write_file_len + 1), filename, len + 1);
      __afl_write_file_len += len + 2;
    } else {
      unlink(filename);
      return -1;
    }
  }
  return ret;
}

/*
int __afl_mkostemp_wrapper (char * filename, int flag) {
  // fprintf(stderr, "[o] mkostemp wrapper: %s\n", filename); // CREATE FILE LOG
  int ret = mkostemp(filename, flag);
  if (ret > 0) {
    if (likely(__afl_num_write_files < AFL_NUM_FILES)) {
      size_t len = strlen(filename);
      __afl_write_files[__afl_num_write_files] = malloc(sizeof (u8) * (len + 1));
      memcpy(__afl_write_files[__afl_num_write_files], filename, len + 1);
      __afl_num_write_files++;
    } else {
      unlink(filename);
      return -1;
    }
  }
  return ret;
}

int __afl_mkostemps_wrapper (char * filename, int suffixLen, int flag) {
  // fprintf(stderr, "[o] mkostemps wrapper: %s\n", filename); // CREATE FILE LOG
  int ret = mkostemps(filename, suffixLen, flag);
  if (ret > 0) {
    if (likely(__afl_num_write_files < AFL_NUM_FILES)) {
      size_t len = strlen(filename);
      __afl_write_files[__afl_num_write_files] = malloc(sizeof (u8) * (len + 1));
      memcpy(__afl_write_files[__afl_num_write_files], filename, len + 1);
      __afl_num_write_files++;
    } else {
      unlink(filename);
      return -1;
    }
  }
  return ret;
}
*/

static u8 delete_files(u8 *path) {

  DIR *          d;
  struct dirent *d_ent;

  d = opendir(path);

  if (!d) { return 0; }

  while ((d_ent = readdir(d))) {

    if (d_ent->d_name[0] != '.') {

      u8 *fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (unlink(fname)) { PFATAL("Unable to delete '%s'", fname); }
      ck_free(fname);

    }

  }

  closedir(d);

  return !!rmdir(path);

}

char * __afl_mkdtemp_wrapper (char * template) {
  // fprintf(stderr, "[o] mkostemps wrapper: %s\n", filename); // CREATE FILE LOG
  char * ret = mkdtemp(template);
  if (ret != NULL) {
    size_t len = strlen(template);
    if (likely((__afl_write_file_len + len + 2) < 1000)) {
      __afl_write_files[__afl_write_file_len] = 'd';
      memcpy(__afl_write_files + (__afl_write_file_len + 1), template, len + 1);
      __afl_write_file_len += len + 2;
    } else {
      delete_files(template);
    }
  }
  return ret;
}

void __afl_delete_file_dirs() {
  u32 idx = 0;
  if (unlikely(__afl_branch_map == NULL)) {
    while (idx < __afl_write_file_len) {
      char * strptr = __afl_write_files + idx + 1;
      switch (__afl_write_files[idx]) {
        case 'f': {
          fprintf(stderr, "%s\n", strptr);
          unlink(strptr);
          break;
        }
        case 'd' : {
          fprintf(stderr, "%s\n", strptr);
          delete_files(strptr);
          break;
        }
      }
      __afl_write_files[idx] = 'r';
      idx += strlen(strptr) + 2;
    }
    return;
  }
  while (idx < __afl_write_file_len) {
    char * strptr = __afl_write_files + idx + 1;
    switch (__afl_write_files[idx]) {
      case 'f': {
        unlink(strptr);
        break;
      }
      case 'd' : {
        delete_files(strptr);
        break;
      }
    }
    __afl_write_files[idx] = 'r';
    idx += strlen(strptr) + 2;
  }
}