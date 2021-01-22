

#include "afl-fuzz.h"
#include "funclog.h"

void func_exec_child(afl_forkserver_t *fsrv, char **argv) {
  execv(fsrv->func_binary, argv);
}


void init_func(afl_state_t* afl) {
  FILE * f = fopen(afl->func_info_txt, "r");

  if (f == NULL) PFATAL("Can't open func txt file");

  int res;
  res = fscanf(f, "%u,%u\n", &afl->num_func, &afl->num_cmp);
  if (res == EOF) PFATAL("Can't read func txt file");

  afl->cmp_func_map = malloc(sizeof(u32) * afl->num_cmp);

  OKF("Number of function : %u, cmp Instr. : %u", afl->num_func, afl->num_cmp);

  u32 i,j, num_func_cmp, tmp, cur_cmp_idx = 0;
  for (i = 0; i < afl->num_func; i++) {
    res = fscanf(f, "%u\n", &num_func_cmp);
    if (res == EOF) PFATAL("Can't read func txt file");
    //SAYF("funcid : %u, # of cmp : %u\n",i, num_func_cmp);
    tmp = num_func_cmp - cur_cmp_idx;
    for (j = 0; j < tmp; j++) {
      //SAYF("%u : %u\n", cur_cmp_idx, i);
      afl->cmp_func_map[cur_cmp_idx++] = i;
    }
  }
  fclose(f);

  afl->func_exec_count_table =
    (u32 **) calloc (sizeof(u32*), afl->num_func);
  if (!afl->func_exec_count_table) PFATAL("Can't alloc func_exec_count_table");

  for (i = 0; i < afl->num_func ; i++) {
    afl->func_exec_count_table[i] = (u32 *) calloc(sizeof(u32), afl->num_func);
    if (!afl->func_exec_count_table[i]) PFATAL("Can't alloc func_exec_count_table[i]");
  }

  afl->func_exec_list = (u8 *) malloc (sizeof(u8) * afl->num_func);
  if (!afl->func_exec_list) PFATAL("Can't alloc func_exec_exec");

  afl->cmp_queue_entries = (struct cmp_queue_entry *) calloc(afl->num_cmp, sizeof(struct cmp_queue_entry));
  if (afl->cmp_queue_entries == NULL) PFATAL("Can't alloc cmp_queue_entries");
}

//Execute the input which is being mutated to get precondition
void func_shm_init(afl_state_t * afl) {
  //assume input is already written

  u32 i1;
  for (i1 = 0; i1 < CMP_FUNC_MAP_SIZE ; i1++) {
    afl->shm.func_map->entries[i1].condition = 0;
    afl->shm.func_map->entries[i1].precondition = 0;
  }

  u8 fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout);

  if (fault == FSRV_RUN_TMOUT) {
    //what?
    FATAL("input in the queue timed out on func log");
  }

  for (i1 = 0; i1 < CMP_FUNC_MAP_SIZE; i1++) {
    afl->shm.func_map->entries[i1].precondition = afl->shm.func_map->entries[i1].condition;
  }
}

void run_func_get_cmp(afl_state_t * afl) {

  //can we skip write_testcase?

  u32 i1,i2,cmp_id;
  for (i1 = 0; i1 < CMP_FUNC_MAP_SIZE ; i1++) {
    afl->shm.func_map->entries[i1].condition = 0;
    afl->shm.func_map->entries[i1].executed = 0;
  }

  u8 fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout);

  if (fault == FSRV_RUN_TMOUT) {
    //what?
    return ;
  }

  memset(afl->func_exec_list, 0, FUNC_MAP_SIZE);
  u8 precondition, postcondition;

  struct cmp_func_entry * entries = afl->shm.func_map->entries;
  struct cmp_queue_entry * queue_entries = afl->cmp_queue_entries;

  for (cmp_id = 0; cmp_id < CMP_FUNC_MAP_SIZE; cmp_id++) {

    if (entries[cmp_id].executed) {
      precondition = entries[cmp_id].precondition;
      postcondition = entries[cmp_id].condition;
      if (precondition && (precondition != postcondition)) {
        //previously half covered, now changed the condition
        //record bytes
        //TODO : overwrite old bytes with new ones
        
        if ( queue_entries[cmp_id].num_bytes == 0 ) afl->num_queued_cmps ++;

        if (afl->cur_num_bytes + queue_entries[cmp_id].num_bytes < MAX_NUM_BYTES) {
          memcpy(queue_entries[cmp_id].bytes, afl->cur_bytes, sizeof(u32) * afl->cur_num_bytes);
          queue_entries[cmp_id].num_bytes += afl->cur_num_bytes;
          afl->total_num_bytes += afl->cur_num_bytes;
        } else {
          u32 left_len = MAX_NUM_BYTES - queue_entries[cmp_id].num_bytes;
          if (left_len >= afl->cur_num_bytes) {
            memcpy(queue_entries[cmp_id].bytes, afl->cur_bytes, sizeof(u32) * afl->cur_num_bytes);
            queue_entries[cmp_id].num_bytes += afl->cur_num_bytes;
            afl->total_num_bytes += afl->cur_num_bytes;
          } else {
            memcpy(queue_entries[cmp_id].bytes, afl->cur_bytes, sizeof(u32) * left_len);
            queue_entries[cmp_id].num_bytes += left_len;
            afl->total_num_bytes += left_len;
          }
        }
      }
    
      //1. The cmp instruction was never executed -> new target
      //2-1. The cmp instruction was half covered, and the new execution did not cover the another branch
      //2-2. The cmp instruction was half covered, and the new execution cover the another branch
      //3. The cmp instruction was already completely covered.
      precondition = queue_entries[cmp_id].condition;
      queue_entries[cmp_id].condition |= afl->shm.func_map->entries[cmp_id].condition;
      postcondition = queue_entries[cmp_id].condition;

      if ((precondition == 0) && (postcondition != 3)) {
        //new target
        if (likely(afl->cmp_queue)) {
          afl->cmp_queue_top->next = &(queue_entries[cmp_id]);
          afl->cmp_queue_top = &(queue_entries[cmp_id]);
          afl->cmp_queue_size++;
        } else {
          afl->cmp_queue = afl->cmp_queue_top = afl->cmp_queue_cur = &(queue_entries[cmp_id]);
          afl->cmp_queue_size++;
        }
        afl->covered_branch++;
      } else if ((precondition == 0) && (postcondition == 3)) {
        afl->covered_branch += 2;
      } else if ((precondition != 3) && (postcondition == 3)) {
        afl->covered_branch++;
      }

      afl->func_exec_list[afl->cmp_func_map[cmp_id]] = 1;
    }    
  }

  //record function relevance
  for (i1 = 0; i1 < afl->num_func ; i1++) {
    if (afl->func_exec_list[i1]) {
      for (i2 = 0; i2 < afl->num_func ; i2++) {
        afl->func_exec_count_table[i1][i2] += afl->func_exec_list[i2]; 
      }
    }
  }
}