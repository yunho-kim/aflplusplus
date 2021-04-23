/*
   american fuzzy lop++ - map display utility
   ------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   A very simple tool that runs the targeted binary and displays
   the contents of the trace bitmap in a human-readable form. Useful in
   scripts to eliminate redundant inputs and perform other checks.

   Exit code is 2 if the target program crashes; 1 if it times out or
   there is a problem executing it; or 0 if execution is successful.

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "sharedmem.h"
#include "forkserver.h"
#include "common.h"
#include "hash.h"
#include "afl-fuzz.h"
#include "funclog.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/wait.h>
#include <sys/time.h>
#ifndef USEMMAP
  #include <sys/shm.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>

static u8 *in_file = NULL;              /* input file                      */

static u32 map_size = MAP_SIZE;

static sharedmem_t       shm;
static afl_forkserver_t *fsrv;
u8 remove_shm = 0;

/* Get rid of temp files (atexit handler). */

static void at_exit_handler(void) {


  if (remove_shm) {

    if (shm.map) afl_shm_deinit(&shm);

  }

  afl_fsrv_killall();

}
/* Handle Ctrl-C and the like. */

static void handle_stop_sig(int sig) {

  (void)sig;
  afl_fsrv_killall();

}

/* Show banner. */

static void show_banner(void) {

  SAYF(cCYA "afl-showmap" VERSION cRST " by Michal Zalewski\n");

}

/* Display usage hints. */

static void usage(u8 *argv0) {

  show_banner();

  SAYF(
      "\n%s -i inputfile -D num_cmp -- /path/to/target_app.func [args]\n\n", argv0);

  exit(1);

}

/* Main entry point */

int main(int argc, char **argv_orig, char **envp) {

  // TODO: u64 mem_limit = MEM_LIMIT;                  /* Memory limit (MB) */

  s32    opt, i;
  u32 num_cmp;
  char **use_argv;

  char **argv = argv_cpy_dup(argc, argv_orig);

  afl_forkserver_t fsrv_var = {0};
  fsrv = &fsrv_var;
  afl_fsrv_init(fsrv);
  map_size = get_map_size();
  fsrv->map_size = map_size;

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  while ((opt = getopt(argc, argv, "+i:D:h")) > 0) {

    switch (opt) {

      case 'i':
        if (in_file) { FATAL("Multiple -i options not supported"); }
        in_file = optarg;
        break;

      case 'h':
        usage(argv[0]);
        return -1;
        break;

      case 'D':
        if (sscanf(optarg, "%d", &num_cmp) < 0) {

          FATAL("Bad syntax used for -D");

        }
        break;

      default:
        usage(argv[0]);

    }

  }

  if (optind == argc) { usage(argv[0]); }

  check_environment_vars(envp);

  if (getenv("AFL_DEBUG")) {

    DEBUGF("");
    for (i = 0; i < argc; i++)
      SAYF(" %s", argv[i]);
    SAYF("\n");

  }

  //  if (afl->shmem_testcase_mode) { setup_testcase_shmem(afl); }

  setenv("AFL_NO_AUTODICT", "1", 1);

  /* initialize cmplog_mode */
  shm.cmplog_mode = 0;

  fsrv->target_path = find_binary(argv[optind]);
  fsrv->trace_bits = afl_shm_init(&shm, map_size, 0, num_cmp);

  detect_file_args(argv + optind, "", &fsrv->use_stdin);

  fsrv->dev_null_fd = open("/dev/null", O_RDWR);
  if (fsrv->dev_null_fd < 0) { PFATAL("Unable to open /dev/null"); }

  use_argv = argv + optind;

  u8 * stdin_file = (char *)alloc_printf(".afl-showmap-temp-%u", (u32)getpid());
  unlink(stdin_file);
  fsrv->out_file = stdin_file;
  fsrv->out_fd = open(stdin_file, O_RDWR | O_CREAT | O_EXCL, 0600);
  if (fsrv->out_fd < 0) { PFATAL("Unable to create '%s'", stdin_file); }
  fsrv->kill_signal =
        parse_afl_kill_signal_env(getenv("AFL_KILL_SIGNAL"), SIGKILL);
  u8 tmp = 0;

  afl_fsrv_start(fsrv, use_argv, &tmp,
                   (get_afl_env("AFL_DEBUG_CHILD") ||
                    get_afl_env("AFL_DEBUG_CHILD_OUTPUT"))
                       ? 1
                       : 0);

    map_size = fsrv->map_size;

  FILE * fp = fopen(in_file, "r");
  fseek(fp, 0L, SEEK_END);
  u32 len = ftell(fp);
  fclose(fp);

  s32 fd = open(in_file, O_RDONLY);

  if (unlikely(fd < 0)) 
    PFATAL("Unable to open '%s'", in_file);

  u8 * buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  u32 cmp_id;
  struct cmp_func_entry * entries = shm.func_map;

  for (cmp_id = 0; cmp_id < num_cmp ; cmp_id++) {
    entries[cmp_id].condition = 0;
  }

  afl_fsrv_write_to_testcase(fsrv, buf, len);

  u8 fault = afl_fsrv_run_target(fsrv, EXEC_TIMEOUT, &tmp);

  if (fault == FSRV_RUN_TMOUT) {
    //what?
    WARNF("input in the queue timed out on func log");
    return 1;
  }

  u32 cmp_cov = 0;

  for (cmp_id = 0; cmp_id < num_cmp; cmp_id++) {
    if (entries[cmp_id].condition) {
      if (entries[cmp_id].condition == 3) {
        cmp_cov += 2;
      } else {
        cmp_cov ++;
      }
    }
  }

  printf("Coverage : %u\n", cmp_cov);

  remove_shm = 0;
  afl_shm_deinit(&shm);

  munmap(buf, len);

  if (fsrv->target_path) { ck_free(fsrv->target_path); }

  afl_fsrv_deinit(fsrv);
  argv_cpy_free(argv);
  return 0;
}

