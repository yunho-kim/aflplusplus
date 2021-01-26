

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

  if (afl->num_cmp > CMP_FUNC_MAP_SIZE) {
    WARNF("# of cmp is bigger than CMP_FUNC_MAP_SIZE");
    afl->num_cmp = CMP_FUNC_MAP_SIZE;
  }

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
  for (i1 = 0; i1 < afl->num_cmp ; i1++) {
    afl->shm.func_map->entries[i1].condition = 0;
    afl->shm.func_map->entries[i1].precondition = 0;
  }

  u8 fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout);

  if (fault == FSRV_RUN_TMOUT) {
    //what?
    WARNF("input in the queue timed out on func log");
    afl->get_func_info = 0;
    return;
  }
  afl->get_func_info = 1;

  for (i1 = 0; i1 < afl->num_cmp; i1++) {
    afl->shm.func_map->entries[i1].precondition = afl->shm.func_map->entries[i1].condition;
  }
}

void run_func_get_cmp(afl_state_t * afl) {

  //can we skip write_testcase?

  if (afl->is_spliced) afl->num_new_path_spliced++;

  if (!afl->get_func_info) return;

  u32 i1,i2,cmp_id;
  for (i1 = 0; i1 < afl->num_cmp ; i1++) {
    afl->shm.func_map->entries[i1].condition = 0;
    afl->shm.func_map->entries[i1].executed = 0;
  }

  u8 fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout);

  if (fault == FSRV_RUN_TMOUT) {
    //what?
    return ;
  }

  memset(afl->func_exec_list, 0, sizeof(u8) * afl->num_func);
  u8 precondition, postcondition;

  struct cmp_func_entry * entries = afl->shm.func_map->entries;
  struct cmp_queue_entry * queue_entries = afl->cmp_queue_entries;

  for (cmp_id = 0; cmp_id < afl->num_cmp; cmp_id++) {

    if (entries[cmp_id].executed) {
      precondition = entries[cmp_id].precondition;
      postcondition = entries[cmp_id].condition;
      if (precondition && (precondition != postcondition)) {
        //previously half covered, now changed the condition
        //record bytes
        //TODO : overwrite old bytes with new ones
        
        if ( queue_entries[cmp_id].num_bytes == 0 ) afl->num_queued_cmps ++;

        if (afl->cur_num_bytes + queue_entries[cmp_id].num_bytes < MAX_NUM_BYTES) {
          memcpy(queue_entries[cmp_id].bytes + queue_entries[cmp_id].num_bytes, afl->cur_bytes,
            sizeof(u32) * afl->cur_num_bytes);
          queue_entries[cmp_id].num_bytes += afl->cur_num_bytes;
          afl->total_num_bytes += afl->cur_num_bytes;
        } else {
          u32 left_len = MAX_NUM_BYTES - queue_entries[cmp_id].num_bytes;
          if (left_len >= afl->cur_num_bytes) {
            memcpy(queue_entries[cmp_id].bytes + queue_entries[cmp_id].num_bytes, afl->cur_bytes,
              sizeof(u32) * afl->cur_num_bytes);
            queue_entries[cmp_id].num_bytes += afl->cur_num_bytes;
            afl->total_num_bytes += afl->cur_num_bytes;
          } else {
            memcpy(queue_entries[cmp_id].bytes + queue_entries[cmp_id].num_bytes, afl->cur_bytes,
              sizeof(u32) * left_len);
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

void write_func_stats (afl_state_t * afl) {
  u8    fn[PATH_MAX];
  FILE *f;
  u32 idx1, idx2;
  s32 fd;

  if (afl->func_exec_count_table) {
    snprintf(fn, PATH_MAX, "%s/func_exec_table.csv", afl->out_dir);
    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
  
    f = fdopen(fd, "w");
    fprintf(f, ",");
    for (idx1 = 0; idx1 < afl->num_func; idx1++){
      fprintf(f, "%u,", idx1);
    }
    fprintf(f,"\n");
    for (idx1 = 0; idx1 < afl->num_func; idx1++){
      fprintf(f, "%u,", idx1);
      for (idx2 = 0; idx2 < afl->num_func ; idx2++){
        fprintf(f, "%u,", afl->func_exec_count_table[idx1][idx2]);
      }
      fprintf(f, "\n");
    }
    fclose(f);

    for (idx1 = 0; idx1 < afl->num_func ; idx1 ++ ) {
      free(afl->func_exec_count_table[idx1]);
    }
    free(afl->func_exec_count_table);
  }

  // FRIEND related stats
  if (afl->func_binary) {
    snprintf(fn, PATH_MAX, "%s/FRIEND.stat", afl->out_dir);
    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);

    f = fdopen(fd, "w");
    fprintf(f, "# of func :%u\n", afl->num_func);
    fprintf(f, "# of cmp :%u\n", afl->num_cmp);
    fprintf(f, "# of total bytes :%u\n", afl->total_num_bytes);
    fprintf(f, "# of covered branch:%u\n", afl->covered_branch);
    fprintf(f, "# of queued_cmps :%u\n", afl->num_queued_cmps);
    fprintf(f, "Avg. # of bytes :%.1f\n", (double) afl->total_num_bytes / afl->num_queued_cmps);
    fprintf(f, "cmp queue size :%u\n", afl->cmp_queue_size);
    fclose(f);

    snprintf(fn, PATH_MAX, "%s/FRIEND_cmp_queue.stat", afl->out_dir);
    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    f = fdopen(fd, "w");

    fprintf(f, "cmp queue size :%u\n", afl->num_queued_cmps);
    struct cmp_queue_entry * q = afl->cmp_queue;
    fprintf(f, "cmpid, condition, num_bytes, bytes\n");
    while (q != NULL) {
      
      fprintf(f, "%ld,%u,%u\n", q - afl->cmp_queue_entries, q->condition, q->num_bytes);
      for (idx1 = 0; idx1 < q->num_bytes; idx1 ++) {
        fprintf(f, "%u,", q->bytes[idx1]);
      }
      fprintf(f,"\n");
      q = q->next;
    }
    fclose(f);
  }

  return;
}