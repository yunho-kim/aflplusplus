/*
   american fuzzy lop++ - cmplog header
   ------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#ifndef _AFL_CMPFUNCLOG_H
#define _AFL_CMPFUNCLOG_H

#include "config.h"
#include "forkserver.h"

//cmp entries used for tracking branch coverage
struct cmp_entry {
  //last execution condition value
  u32 value;
  //condition recored at the execution, MSB : true, LSB : false,  true | false covered  
  u8 condition;
};

//cmp entries used for tracking branch coverage
struct cmp_entry2 {
  //last execution condition value
  u32 cmp_id;
  //condition recored at the execution, MSB : true, LSB : false,  true | false covered  
  u8 condition;
};

void func_exec_child(afl_forkserver_t *fsrv, char ** argv);

#endif

