
#include "afl-fuzz.h"
#include "funclog.h"

static void mining_serialize(afl_state_t *afl, struct byte_cmp_set ** mining_result, u32 num_mining_frag);
static struct byte_cmp_set ** mining_deserialize(afl_state_t * afl, u32 tc_idx);
static void mining_deserialize_free(struct byte_cmp_set ** mining_result, u32 num_mining_frag);
static void mining_bytes(afl_state_t *afl, u8 * out_buf, u32 len);
static void get_close_tcs(afl_state_t * afl, u32 target_id, u32 * close_tcs, u32 * num_close_tc, u8 degree, u32 frag_len);

void func_exec_child(afl_forkserver_t *fsrv, char **argv) {
  execv(fsrv->func_binary, argv);
}


void init_func(afl_state_t* afl) {

  u8    fn[PATH_MAX];
  FILE * f;
  
  snprintf(fn, PATH_MAX, "%s/FRIEND_func_cmp_id_info", afl->func_infos_dir);
  f = fopen(fn, "r");
  if (f == NULL) PFATAL("Can't open func txt file");

  int res;
  res = fscanf(f, "%u,%u\n", &afl->num_func, &afl->num_cmp);
  if (res == EOF) PFATAL("Can't read func txt file");

  afl->cmp_func_map = malloc(sizeof(u32) * afl->num_cmp);
  afl->func_cmp_map = malloc(sizeof(struct func_cmp_info *) * afl->num_func);

  OKF("Number of function : %u, cmp Instr. : %u", afl->num_func, afl->num_cmp);

  u32 i,j, num_func_cmp, tmp, cur_cmp_idx = 0;
  for (i = 0; i < afl->num_func; i++) {
    res = fscanf(f, "%u\n", &num_func_cmp);
    if (res == EOF) PFATAL("Can't read func txt file");
    //SAYF("funcid : %u, # of cmp : %u\n",i, num_func_cmp);
    afl->func_cmp_map[i] = malloc(sizeof(struct func_cmp_info));
    afl->func_cmp_map[i]->cmp_id_begin = cur_cmp_idx;
    tmp = num_func_cmp - cur_cmp_idx;
    for (j = 0; j < tmp; j++) {
      //SAYF("%u : %u\n", cur_cmp_idx, i);
      afl->cmp_func_map[cur_cmp_idx++] = i;
    }
    afl->func_cmp_map[i]->cmp_id_end = num_func_cmp;
  }
  fclose(f);
  
  afl->func_exec_count_table =
    (u32 **) calloc (sizeof(u32*), afl->num_func);
  if (!afl->func_exec_count_table) PFATAL("Can't alloc func_exec_count_table");

  afl->func_cmp_exec_count_table = (u32 ***) calloc (afl->num_func, sizeof (u32 **));
  if (!afl->func_cmp_exec_count_table) PFATAL("Can't alloc func_cmp_exec_count_table");

  afl->func_list = (u8 *) malloc (sizeof(u8) * afl->num_func);
  if (!afl->func_list) PFATAL("Can't alloc func_exec_exec");

  afl->cmp_queue_buf = (struct cmp_queue_entry **) calloc(afl->num_cmp, sizeof(struct cmp_queue_entry*));
  if (afl->cmp_queue_buf == NULL) PFATAL("Can't alloc cmp_queue_entries");
  for (i = 0 ; i < afl->num_cmp; i++) {
    afl->cmp_queue_buf[i] = (struct cmp_queue_entry *) calloc(1, sizeof(struct cmp_queue_entry));
    afl->cmp_queue_buf[i]->id = i;
  }

  afl->mutated_frag_idx = (u32 *) malloc(sizeof (u32) * (1 << HAVOC_STACK_POW2));
  afl->close_tcs = (u32 *) malloc(sizeof (u32) * CLOSE_TCS_SIZE);

  /*
  snprintf(fn, PATH_MAX, "%s/FRIEND_magic_byte_cmps", afl->func_infos_dir);
  f = fopen(fn, "r");
  if (f == NULL) PFATAL("Can't open magic bytes txt file");
  u32 num_magic_cmps;
  res = fscanf(f, "%u\n", &num_magic_cmps);
  if (res == EOF) PFATAL("Can't read magic bytes txt file");
  for (i = 0; i < num_magic_cmps; i++) {
    res = fscanf(f, "%u\n", &cur_cmp_idx);
    if (unlikely(res == EOF)) PFATAL("Can't read magic bytes txt file");
    afl->cmp_queue_buf[cur_cmp_idx]->is_magic_bytes = 1;
  }

  fclose(f);
  */

  afl->pre_value = (u32 *) malloc (sizeof(u32) * afl->num_cmp);
  afl->is_changed = (u8 *) malloc (sizeof(u8) * afl->num_cmp);

  snprintf(fn, PATH_MAX, "%s/FRIEND_debug.txt", afl->out_dir);
  s32 fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  afl->debug_file = fdopen(fd, "w");
}

void destroy_func(afl_state_t * afl) {
  u32 idx1, idx2;

  if (afl->debug_file)
    fclose(afl->debug_file);

  for (idx1 = 0; idx1 < afl->num_cmp; idx1++) {
    if (afl->cmp_queue_buf[idx1]) {
      free(afl->cmp_queue_buf[idx1]->value_changing_tcs);
      free(afl->cmp_queue_buf[idx1]);
    }
  }
  free(afl->cmp_queue_buf);

  ck_free(afl->func_binary);

  free(afl->cmp_func_map);
  free(afl->func_list);
  
  if(afl->func_exec_count_table) {
    for (idx1 = 0; idx1 < afl->num_func ; idx1 ++ ) {
      free(afl->func_exec_count_table[idx1]);
    }
    free(afl->func_exec_count_table);
  }

  if (afl->func_cmp_exec_count_table) {
    for (idx1 = 0; idx1 < afl->num_func; idx1++) {
      if (afl->func_cmp_exec_count_table[idx1]) {
        u32 num_cmp = afl->func_cmp_map[idx1]->cmp_id_end - afl->func_cmp_map[idx1]->cmp_id_begin;
        for (idx2 = 0; idx2 < num_cmp; idx2++) {
          if (afl->func_cmp_exec_count_table[idx1][idx2]) {
            free(afl->func_cmp_exec_count_table[idx1][idx2]);
          }
        }
        free(afl->func_cmp_exec_count_table[idx1]);
      }
    }
    free(afl->func_cmp_exec_count_table);
  }

  if (afl->func_cmp_map) {
    for (idx1 = 0; idx1 < afl->num_func; idx1++) {
      free(afl->func_cmp_map[idx1]);
    }
    free(afl->func_cmp_map);
  }

  free(afl->pre_value);
  free(afl->frag_score);
  free(afl->num_frag_score_sum);
  free(afl->frag_buf);
  free(afl->mutated_frag_idx);
  free(afl->close_tcs);
  free(afl->is_changed);
}

void init_trim_and_func(afl_state_t * afl) {

  s32 len;
  u8 * in_buf;

  u32 tc_idx = 0;

  u32 num_init = afl->queued_paths;

  for(tc_idx = 0; tc_idx < num_init; tc_idx++) {

    afl->current_entry = tc_idx;
    struct queue_entry * q = afl->queue_buf[tc_idx];
    afl->queue_cur = q;

    if (q->disabled) {
      continue;
    }

    len = q->len;
    in_buf = queue_testcase_get(afl, q);

    //res = trim_case(afl, q, in_buf);
    //if (unlikely(res == FSRV_RUN_ERROR)) FATAL("Unable to execute target application");

    //q->trim_done = 1;

    update_tc_graph_and_branch_cov(afl, tc_idx, (u32) -1, in_buf, len);

    mining_wrapper(afl, tc_idx);
   
  }

  return;
}

void mining_wrapper(afl_state_t * afl, u32 tc_id) {

  s32  len;
  u8 * in_buf;

  u32 tmp = afl->current_entry;
  afl->current_entry = tc_id;
  afl->queue_cur = afl->queue_buf[tc_id];

  struct queue_entry * q = afl->queue_cur;

  if (q->disabled) {
    afl->current_entry = tmp;
    afl->queue_cur = afl->queue_buf[tmp];
    return;
  }

  afl->stage_name = "mining";
  afl->stage_short = "mining";

  u32 tmp_stage_cur = afl->fsrv.total_execs;
  u32 tmp_hit = afl->queued_paths + afl->unique_crashes;

  len = q->len;

  in_buf = queue_testcase_get(afl, q);

  mining_bytes(afl, in_buf, len);

  afl->current_entry = tmp;
  afl->queue_cur = afl->queue_buf[tmp];

  afl->stage_finds[STAGE_MINING] += afl->queued_paths + afl->unique_crashes - tmp_hit;
  afl->stage_cycles[STAGE_MINING] += afl->fsrv.total_execs - tmp_stage_cur;

}

static u32 func_choose_block_len(afl_state_t *afl, u32 limit, u32 len) {

  u32 min_value, max_value;
  u32 rlim = MIN(afl->queue_cycle, (u32)3);

  if (unlikely(!afl->run_over10m)) { rlim = 1; }

  switch (rand_below(afl, rlim)) {

    case 0:
      min_value = 1;
      max_value = len * FUNC_HAVOC_BLK_SMALL_RATIO;
      if (max_value < FUNC_HAVOC_BLK_SMALL_MIN)
        max_value = FUNC_HAVOC_BLK_SMALL_MIN;
      break;

    case 1:
      min_value = len * FUNC_HAVOC_BLK_SMALL_RATIO;
      if (min_value < FUNC_HAVOC_BLK_SMALL_MIN)
        min_value = FUNC_HAVOC_BLK_SMALL_MIN;
      max_value = len * FUNC_HAVOC_BLK_MEDIUM_RATIO;
      if (max_value < FUNC_HAVOC_BLK_MEDIUM_MIN)
        max_value = FUNC_HAVOC_BLK_MEDIUM_MIN;
      break;

    default:

      if (likely(rand_below(afl, 10))) {

        min_value = len * FUNC_HAVOC_BLK_MEDIUM_RATIO;
        if (min_value < FUNC_HAVOC_BLK_MEDIUM_MIN)
          min_value = FUNC_HAVOC_BLK_MEDIUM_MIN;
        max_value = len * FUNC_HAVOC_BLK_LARGE_RATIO;
        if (max_value < FUNC_HAVOC_BLK_LARGE_MIN)
          max_value = FUNC_HAVOC_BLK_LARGE_MIN;

      } else {

        min_value = len * FUNC_HAVOC_BLK_LARGE_RATIO;
        if (min_value < FUNC_HAVOC_BLK_LARGE_MIN)
          min_value = FUNC_HAVOC_BLK_LARGE_MIN;
        max_value = len * FUNC_HAVOC_BLK_XL_RATIO;
        if (max_value < FUNC_HAVOC_BLK_XL_MIN)
          max_value = FUNC_HAVOC_BLK_XL_MIN;

      }

  }

  if (min_value >= limit) { min_value = 1; }

  return min_value + rand_below(afl, MIN(max_value, limit) - min_value + 1);

}

void update_tc_graph_and_branch_cov(afl_state_t * afl, u32 tc_idx, u32 parent_idx, u8 * buf, u32 len) {

  u32 idx1, idx2;

  struct queue_entry * q = afl->queue_buf[tc_idx];

  q->parent_id = parent_idx;

  if (parent_idx != (u32) -1) {
      if (likely(parent_idx < tc_idx)) {
      struct queue_entry * parent = afl->queue_buf[parent_idx];
      if (parent->children == NULL) { 
        parent->children = (u32 *) malloc (sizeof(u32) * TC_CHILDREN_SIZE);
        parent->children_size = TC_CHILDREN_SIZE;
      }
      parent->children[parent->num_children++] = tc_idx;
      if(unlikely(parent->num_children >= parent->children_size)){
        parent->children_size *= 2;
        parent->children = realloc(parent->children, parent->children_size * sizeof(u32));
      }
    }
  }

  u32 cmp_id;
  struct cmp_entry * entries = afl->shm.branch_map;

  for (cmp_id = 0; cmp_id < afl->num_cmp ; cmp_id++) {
    entries[cmp_id].condition = 0;
  }

  write_to_testcase(afl, buf, len, q->argv_idx);
  memset(afl->shm.filen_map, 0, 1000);
  u8 fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout * 2);

  if (fault == FSRV_RUN_TMOUT) {
    //what?
    WARNF("input in the queue timed out on func log");
    u32 idx = 0;
    while (afl->shm.filen_map[idx]) {
      char * strptr = afl->shm.filen_map + idx + 1;
      switch (afl->shm.filen_map[idx]) {
        case 'f':
          unlink(strptr);
          break;
        case 'd':
          delete_files(strptr, NULL);
          break;
        case 'r':
          break;
      }
      idx += strlen(strptr) + 2;
    }
    memset(afl->shm.filen_map, 0, 1000);
    return;
  }

  u8 precondition, postcondition;
  struct cmp_queue_entry * cur_queue_entry;
  memset(afl->func_list, 0, sizeof(u8) * afl->num_func);

  //update branch coverage/cmp queue
  for (cmp_id = 0; cmp_id < afl->num_cmp; cmp_id++) {
    if (entries[cmp_id].condition) {

      afl->func_list[afl->cmp_func_map[cmp_id]] = 1;

      cur_queue_entry = afl->cmp_queue_buf[cmp_id];
      precondition = cur_queue_entry->condition;

      if (precondition == 3) continue;

      cur_queue_entry->condition |= entries[cmp_id].condition;
      postcondition = cur_queue_entry->condition;

      if ((precondition == 0) && (postcondition != 3)) {
        //new target
        if (likely(afl->cmp_queue)) {
          afl->cmp_queue_top->next = cur_queue_entry;
          cur_queue_entry->prev = afl->cmp_queue_top;
          afl->cmp_queue_top = cur_queue_entry;
        } else {
          afl->cmp_queue = afl->cmp_queue_top = afl->cmp_queue_cur = cur_queue_entry;
        }
        afl->cmp_queue_size++;
        afl->covered_branch++;
      } else if (postcondition == 3) {
        if (precondition == 0) {
          afl->covered_branch += 2;
        } else {
          afl->covered_branch ++;
        }

        free(cur_queue_entry->value_changing_tcs);
        cur_queue_entry->value_changing_tcs = NULL;
        cur_queue_entry->num_value_changing_tcs = 0;

        if (cur_queue_entry->prev != NULL) {
          cur_queue_entry->prev->next = cur_queue_entry->next;
          afl->cmp_queue_size--;
        } else if (afl->cmp_queue == cur_queue_entry) {
          afl->cmp_queue = cur_queue_entry->next;
        }
      }

      /*
      if (postcondition != 3 && !cur_queue_entry->exec_max_reached) {
        
        if (cur_queue_entry->executing_tcs == NULL) {
          cur_queue_entry->executing_tcs = (u32 *) malloc (sizeof(u32) * EXEC_TCS_SIZE);
          cur_queue_entry->executing_tcs_size = EXEC_TCS_SIZE;
        }
        
        if (len > TC_LEN_MIN) {
          cur_queue_entry->executing_tcs[cur_queue_entry->num_executing_tcs++] = tc_idx;
          if (unlikely(cur_queue_entry-> num_executing_tcs >= cur_queue_entry->executing_tcs_size)) {
            cur_queue_entry->executing_tcs_size += EXEC_TCS_SIZE;
            cur_queue_entry->executing_tcs = (u32 *) realloc(
              cur_queue_entry->executing_tcs,
              sizeof(u32) * cur_queue_entry->executing_tcs_size);
          }
        }

        if (unlikely((((float) cur_queue_entry->num_executing_tcs) / ((float) afl->queued_paths)) 
              > CMP_MAX_EXEC_TC_TRESHOLD) && (afl->queued_paths > CMP_CHECK_MAX_EXEC_TC_TRESHOLD)) {
            cur_queue_entry->exec_max_reached = 1;
            free(cur_queue_entry->executing_tcs);
            cur_queue_entry->executing_tcs = NULL;
        }
      }

      */
    }
  }

  //update func rel/ cmp rel
  for (idx1 = 0; idx1 < afl->num_func; idx1++) {
    if (afl->func_list[idx1]) {
      if (unlikely(afl->func_exec_count_table[idx1] == NULL)) {
        afl->func_exec_count_table[idx1] = (u32 *) calloc(sizeof (u32), afl->num_func);
        if (unlikely(afl->func_exec_count_table[idx1] == NULL))
          PFATAL("Can't alloc func_exec_count_table[idx1]");
      }

      
      u32 * cur_func_exec_table = afl->func_exec_count_table[idx1];
      for (idx2 = 0; idx2 < afl->num_func; idx2++) {
        cur_func_exec_table[idx2] += afl->func_list[idx2]; 
      }

      /*
      struct func_cmp_info * cur_func_info = afl->func_cmp_map[idx1];
      u32 cmp_id_begin = cur_func_info->cmp_id_begin;
      u32 num_cmp = cur_func_info->cmp_id_end - cmp_id_begin;
      if (unlikely(afl->func_cmp_exec_count_table[idx1] == NULL)) {        
        u32 ** cur_func_table = (u32 **) calloc(num_cmp, sizeof (u32 *));
        for (idx2 = 0; idx2 < num_cmp; idx2++) {
          cur_func_table[idx2] = (u32 *) calloc (num_cmp, sizeof (u32));
        }
        afl->func_cmp_exec_count_table[idx1] = cur_func_table;
      }

      u32 ** cur_func_table = afl->func_cmp_exec_count_table[idx1];
      for (idx2 = 0; idx2 < num_cmp; idx2++) {
        if (entries[idx2 + cur_func_info->cmp_id_begin].condition) {
          u32 * cur_func_cmp_table = cur_func_table[idx2];
          for (idx3 = 0; idx3 < num_cmp; idx3++) {
            cur_func_cmp_table[idx3] += entries[idx3 + cmp_id_begin].condition ? 1 : 0;
          }
        }
      }
      */
      
    }
  }

  return;
}

static void mining_serialize(afl_state_t *afl, struct byte_cmp_set ** mining_result, u32 num_mining_frag) {
  u32 idx1;
  u8 * fn = alloc_printf("%s/FRIEND/mining/id:%06u", afl->out_dir, afl->queue_cur->id);
  FILE * f = fopen(fn, "w");

  fwrite(&num_mining_frag, sizeof(u32), 1, f);

  for (idx1 = 0; idx1 < num_mining_frag; idx1++) {

    struct byte_cmp_set * tmp = mining_result[idx1];

    fwrite(&(tmp->num_changed_val_cmps), sizeof(u32), 1, f);
    if (tmp->num_changed_val_cmps != 0) {
      fwrite(tmp->changed_val_cmps, sizeof(u32), tmp->num_changed_val_cmps, f);
      free(tmp->changed_val_cmps);
    }
    free(tmp);

  }

  free(mining_result);

  ck_free(fn);
  fclose(f);
}

static struct byte_cmp_set ** mining_deserialize(afl_state_t * afl, u32 tc_idx) {
  u32 idx1;
  u8 * fn = alloc_printf("%s/FRIEND/mining/id:%06u", afl->out_dir, tc_idx);
  FILE * f = fopen(fn, "r");

  u32 num_mining_frag = 0;

  u32 read_size = fread(&num_mining_frag, sizeof(u32), 1, f);
  assert(likely(read_size == 1));

  struct byte_cmp_set ** mining_result =
    (struct byte_cmp_set **) malloc(sizeof(struct byte_cmp_set *) * num_mining_frag);

  for (idx1 = 0; idx1 < num_mining_frag; idx1++) {
    struct byte_cmp_set * tmp = (struct byte_cmp_set *) malloc(sizeof(struct byte_cmp_set));
    mining_result[idx1] = tmp;
    read_size = fread(&(tmp->num_changed_val_cmps), sizeof(u32), 1, f);
    assert(likely(read_size == 1));

    if (tmp->num_changed_val_cmps != 0) {
      
      tmp->changed_val_cmps = (u32 *) malloc(sizeof(u32) * tmp->num_changed_val_cmps);
      read_size = fread(tmp->changed_val_cmps, sizeof(u32), tmp->num_changed_val_cmps, f);
      assert(likely(read_size == tmp->num_changed_val_cmps));
    } else {
      tmp->changed_val_cmps = NULL;
    }
  }

  ck_free(fn);
  fclose(f);
  return mining_result;
}

static void mining_deserialize_free(struct byte_cmp_set ** mining_result, u32 num_mining_frag) {
  u32 idx1;

  for (idx1 = 0; idx1< num_mining_frag; idx1++) {
    struct byte_cmp_set * tmp = mining_result[idx1];
    free(tmp->changed_val_cmps);
    free(tmp);
  }

  free(mining_result);
}

static void mining_bytes(afl_state_t *afl, u8 * out_buf, u32 len) {

  u32 idx1, idx2, idx3, cmp_id;
  struct cmp_entry * entries = afl->shm.branch_map;
  struct queue_entry * cur_q = afl->queue_cur;
  u64 start_us, diff_us;

  if (len < 16) return;

  start_us = get_cur_time_us();

  for (idx1 = 0; idx1 < afl->num_cmp; idx1++) {
    entries[idx1].value = 0;
  }

  write_to_testcase(afl, out_buf, len, cur_q->argv_idx);
  memset(afl->shm.filen_map, 0, 1000);

  u8 fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout * 5);

  if (fault == FSRV_RUN_TMOUT) {
    //what?
    WARNF("input in the queue timed out on func log");
    u32 idx = 0;
    while (afl->shm.filen_map[idx]) {
      char * strptr = afl->shm.filen_map + idx + 1;
      switch (afl->shm.filen_map[idx]) {
        case 'f':
          unlink(strptr);
          break;
        case 'd':
          delete_files(strptr, NULL);
          break;
        case 'r':
          break;
      }
      idx += strlen(strptr) + 2;
    }
    memset(afl->shm.filen_map, 0, 1000);
    return;
  }

  //get condition values of the new test input
  for (idx1 = 0; idx1 < afl->num_cmp; idx1++) {
    afl->pre_value[idx1] = entries[idx1].value;
  }

  diff_us = get_cur_time_us() - start_us;

  u32 num_mining_exec = 100000 / diff_us;

  if (num_mining_exec < 1) {
    WARNF("give up mining hits input");
    return;
  }

  u32 frag_len = 16;

  while (num_mining_exec < (len / frag_len)) {
    frag_len *= 2;
  }

  u32 num_repeat = num_mining_exec / (len / frag_len);

  if (num_repeat > 16) num_repeat = 16;
  if (num_repeat < 1) num_repeat = 1;
  
  u8 * out_buf2 = afl_realloc(AFL_BUF_PARAM(mining), len);
  memcpy(out_buf2, out_buf, len);
  
  cur_q->mining_frag_len = frag_len;
  u32 num_frag = len / frag_len + 1;

  struct byte_cmp_set ** mining_result = malloc(sizeof(struct byte_cmp_set*) * num_frag);

  //mutate and get new byte/cmps sets
  u32 r, cur_offset = 0, cur_len = frag_len;

#define FLIP_BIT(_ar, _b)                 \
do {                                      \
                                          \
  u8 *_arf = (u8 *)(_ar);                 \
  u32 _bf = (_b);                         \
  _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                          \
} while (0)

  u32 mining_idx = 0;

  u8 * is_changed_cmp = afl->is_changed;

  memset(is_changed_cmp, 0, sizeof(u8) * afl->num_cmp);

  afl->stage_max = len / frag_len;
  afl->stage_cur = 0;

  for (cur_offset = 0; cur_offset < len; cur_offset += cur_len) {

    if (unlikely(cur_offset + cur_len > len)) {
      cur_len = len - cur_offset;
      if (cur_len < 4) {
        break;
      }
    }

    mining_result[mining_idx] = (struct byte_cmp_set *) calloc(1, sizeof(struct byte_cmp_set));
    u32 num_changed_val_cmps = 0;
    u32 * changed_val_cmps = (u32 *) malloc (sizeof(u32) * CMP_BUF_SIZE);
    u32 changed_val_cmps_buf_size = CMP_BUF_SIZE;

    for (idx2 = 0; idx2 < num_repeat; idx2++) {

      u32 use_stacking = 1 << (1 + rand_below(afl, HAVOC_STACK_POW2));
      u32 rand_value;

      for (idx3 = 0; idx3 < use_stacking; ++idx3) {
        
        switch (r = rand_below(afl, 12)) {

          case 0:
          
            rand_value = rand_below(afl, cur_len << 3) + (cur_offset << 3);
            FLIP_BIT(out_buf2, rand_value);
            break;

          case 1:

            rand_value = cur_offset + rand_below(afl, cur_len);
            out_buf2[rand_value] =
                interesting_8[rand_below(afl, sizeof(interesting_8))];
            break;

          case 2:

            /* Set word to interesting value, randomly choosing endian. */

            if (len < 2) { break; }

            rand_value = cur_offset + rand_below(afl, cur_len - 1);

            if (rand_below(afl, 2)) {
              *(u16 *)(out_buf2 + rand_value) =
                  interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)];

            } else {
              *(u16 *)(out_buf2 + rand_value) = SWAP16(
                  interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)]);
            }

            break;

          case 3:

            /* Set dword to interesting value, randomly choosing endian. */

            if (len < 4) { break; }

            if (rand_below(afl, 2)) {

              rand_value = cur_offset + rand_below(afl, cur_len - 3);
              *(u32 *)(out_buf2 + rand_value) =
                  interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)];

            } else {
              
              rand_value = cur_offset + rand_below(afl, cur_len - 3);
              *(u32 *)(out_buf2 + rand_value) = SWAP32(
                  interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)]);

            }

            break;

          case 4:

            /* Randomly subtract from word, random endian. */

            if (len < 2) { break; }

            if (rand_below(afl, 2)) {

              rand_value = cur_offset + rand_below(afl, cur_len - 1);
              *(u16 *)(out_buf2 + rand_value) -= 1 + rand_below(afl, ARITH_MAX);

            } else {

              rand_value = cur_offset + rand_below(afl, cur_len - 1);
              u16 num = 1 + rand_below(afl, ARITH_MAX);

              *(u16 *)(out_buf2 + rand_value) =
                  SWAP16(SWAP16(*(u16 *)(out_buf2 + rand_value)) - num);

            }

            break;

          case 5:

            /* Randomly add to word, random endian. */

            if (len < 2) { break; }

            if (rand_below(afl, 2)) {

              rand_value = cur_offset + rand_below(afl, cur_len - 1);
              *(u16 *)(out_buf2 + rand_value) += 1 + rand_below(afl, ARITH_MAX);

            } else {

              rand_value = cur_offset + rand_below(afl, cur_len - 1);
              u16 num = 1 + rand_below(afl, ARITH_MAX);

              *(u16 *)(out_buf2 + rand_value) =
                  SWAP16(SWAP16(*(u16 *)(out_buf2 + rand_value)) + num);

            }

            break;

          case 6:

            /* Randomly subtract from dword, random endian. */

            if (len < 4) { break; }

            rand_value = cur_offset + rand_below(afl, cur_len - 3);

            if (rand_below(afl, 2)) {

              *(u32 *)(out_buf2 + rand_value) -= 1 + rand_below(afl, ARITH_MAX);

            } else {

              u32 num = 1 + rand_below(afl, ARITH_MAX);
              *(u32 *)(out_buf2 + rand_value) =
                  SWAP32(SWAP32(*(u32 *)(out_buf + rand_value)) - num);

            }

            break;

          case 7:

            /* Randomly add to dword, random endian. */

            if (len < 4) { break; }

            rand_value = cur_offset + rand_below(afl, cur_len - 3);

            if (rand_below(afl, 2)) {

              *(u32 *)(out_buf2 + rand_value) += 1 + rand_below(afl, ARITH_MAX);

            } else {

              u32 num = 1 + rand_below(afl, ARITH_MAX);
              *(u32 *)(out_buf2 + rand_value) =
                  SWAP32(SWAP32(*(u32 *)(out_buf + rand_value)) + num);

            }

            break;

          case 8:

            /* Just set a random byte to a random value. Because,
              why not. We use XOR with 1-255 to eliminate the
              possibility of a no-op. */

            rand_value = cur_offset + rand_below(afl, cur_len);
            out_buf2[rand_value] ^= 1 + rand_below(afl, 255);
            break;

          case 9: {

            /* Overwrite bytes with a randomly selected chunk (75%) or fixed
              bytes (25%). */

            u32 copy_from, copy_to, copy_len;

            if (len < 2) { break; }

            copy_len = func_choose_block_len(afl, cur_len - 1, cur_len);

            copy_from = rand_below(afl, len - copy_len + 1);
            copy_to = cur_offset + rand_below(afl, cur_len - copy_len + 1);

            if (likely(rand_below(afl, 4))) {

              if (copy_from != copy_to) {

                memmove(out_buf2 + copy_to, out_buf2 + copy_from, copy_len);

              }

            } else {

              memset(out_buf2 + copy_to,
                    rand_below(afl, 2) ? rand_below(afl, 256)
                                        : out_buf2[rand_below(afl, len)],
                    copy_len);

            }

            break;

          }

          case 10:
            /* Overwrite bytes with an extra. */

            if (!afl->extras_cnt ||
                (afl->a_extras_cnt && rand_below(afl, 2))) {

              /* No user-specified extras or odds in our favor. Let's use an
                  auto-detected one. */

              u32 use_extra = rand_below(afl, afl->a_extras_cnt);
              u32 extra_len = afl->a_extras[use_extra].len;
              u32 insert_at;

              if (extra_len > cur_len) { break; }

              insert_at = cur_offset + rand_below(afl, cur_len - extra_len + 1);

              memcpy(out_buf2 + insert_at, afl->a_extras[use_extra].data,
                      extra_len);

            } else if (afl->extras_cnt) {

              /* No auto extras or odds in our favor. Use the dictionary. */

              u32 use_extra = rand_below(afl, afl->extras_cnt);
              u32 extra_len = afl->extras[use_extra].len;
              u32 insert_at;

              if (extra_len > cur_len) { break; }

              insert_at = cur_offset + rand_below(afl, cur_len - extra_len + 1);

              memcpy(out_buf2 + insert_at, afl->extras[use_extra].data,
                      extra_len);

            }

            break;

          default:
            /* Overwrite bytes with a randomly selected chunk from another
                testcase or insert that chunk. */

            if (afl->queued_paths < 4) break;

            /* Pick a random queue entry and seek to it. */

            u32 tid;
            do
              tid = rand_below(afl, afl->queued_paths);
            while (tid == afl->queue_cur->id || afl->queue_buf[tid]->len < 4);

            struct queue_entry *target = afl->queue_buf[tid];
            u32                 new_len = target->len;
            u8 *                new_buf = queue_testcase_get(afl, target);

            //overwrite

            u32 copy_from, copy_to, copy_len;

            copy_len = func_choose_block_len(afl, new_len - 1, cur_len);
            if (copy_len > cur_len) copy_len = cur_len;

            copy_from = rand_below(afl, new_len - copy_len + 1);
            copy_to = cur_offset + rand_below(afl, cur_len - copy_len + 1);

            memmove(out_buf2 + copy_to, new_buf + copy_from, copy_len);

            break;
        } // end of switch
      } // end of for (idx3 = 0; idx3 < use_stacking ; idx3++)

      //get byte cmps set

      common_fuzz_stuff(afl, out_buf2, len, cur_q->argv_idx);

      //execute
      for (idx3 = 0; idx3 < afl->num_cmp; idx3++) {
        entries[idx3].condition = 0;
      }
      memset(afl->shm.filen_map, 0, 1000);

      fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout);      

      if (fault == FSRV_RUN_TMOUT) {
        memcpy(out_buf2 + cur_offset, out_buf + cur_offset, cur_len);
        u32 idx = 0;
        while (afl->shm.filen_map[idx]) {
          char * strptr = afl->shm.filen_map + idx + 1;
          switch (afl->shm.filen_map[idx]) {
            case 'f':
              unlink(strptr);
              break;
            case 'd':
              delete_files(strptr, NULL);
              break;
            case 'r':
              break;
          }
          idx += strlen(strptr) + 2;
        }
        memset(afl->shm.filen_map, 0, 1000);
        continue;
      }

      for (cmp_id = 0; cmp_id < afl->num_cmp; cmp_id ++) {
        if(entries[cmp_id].condition) {
          if (afl->pre_value[cmp_id] != entries[cmp_id].value) {
            changed_val_cmps[num_changed_val_cmps++] = cmp_id;
            if (unlikely(num_changed_val_cmps >= changed_val_cmps_buf_size)) {
              changed_val_cmps_buf_size *= 2;
             changed_val_cmps = (u32 *) realloc(changed_val_cmps, sizeof(u32) * changed_val_cmps_buf_size);
            }

            struct cmp_queue_entry * cq = afl->cmp_queue_buf[cmp_id];
            if (cq->condition != 3) {
              is_changed_cmp[cmp_id] = 1;
            }
          }
        }
      }

      memcpy(out_buf2 + cur_offset, out_buf + cur_offset, cur_len);

    }  // end of for (idx2 = 0; idx2 < num_repeat; idx2++)

    if (num_changed_val_cmps == 0) {
      free(changed_val_cmps);
      changed_val_cmps = NULL;
    }

    mining_result[mining_idx]->changed_val_cmps = changed_val_cmps;
    mining_result[mining_idx]->num_changed_val_cmps = num_changed_val_cmps;

    cur_offset += cur_len;
    mining_idx++;
    afl->stage_cur++;

    if (afl->stop_soon) { break; }
  }

  if (afl->stop_soon) {
    for (idx1 = 0; idx1 < mining_idx; idx1++) {
      struct byte_cmp_set * tmp = mining_result[idx1];

      if (tmp->num_changed_val_cmps != 0) {
        free(tmp->changed_val_cmps);
      }
      free(tmp);

    }

    free(mining_result);
    return;
  }

  for (idx1 = 0; idx1 < afl->num_cmp; idx1++) {
    if (is_changed_cmp[idx1]) {
      struct cmp_queue_entry * cq = afl->cmp_queue_buf[idx1];
      if (cq->condition != 3) {
        if (cq->value_changing_tcs == NULL) {
          cq->value_changing_tcs_size = EXEC_TCS_SIZE;
          cq->value_changing_tcs = (u32 *) malloc (cq->value_changing_tcs_size * sizeof(u32));
        }
        cq->value_changing_tcs[cq->num_value_changing_tcs++] = afl->current_entry;
        if (unlikely(cq->num_value_changing_tcs >= cq->value_changing_tcs_size)) {
          cq->value_changing_tcs_size *= 2;
          cq->value_changing_tcs = (u32 *) realloc (cq->value_changing_tcs, cq->value_changing_tcs_size * sizeof(u32));
        }
      }
    }
  }

  //Save the mining result as serialized file
  
  mining_serialize(afl, mining_result, mining_idx);
  cur_q->num_mining_frag = mining_idx;
  cur_q->is_mined = (u32) -1;

  afl->num_mined ++;

  return;
}

static void get_close_tcs(afl_state_t * afl, u32 target_id, u32 * close_tcs, u32 * num_close_tc, u8 degree, u32 frag_len) {

  u32 i,j;
  u8 temp;

  if (unlikely(*num_close_tc >= CLOSE_TCS_SIZE)) return;

  struct queue_entry * cur_entry = afl->queue_buf[target_id];

  u32 cur_num_close_tcs = *close_tcs;

  u32 parent_id = cur_entry->parent_id;

  if (parent_id != (u32) -1) {

    struct queue_entry * parent_entry = afl->queue_buf[parent_id];

    if (parent_entry->is_mined < MAX_MINING_TRY) {
      mining_wrapper(afl, parent_id);
    }

    if ((parent_entry->is_mined == (u32) -1) && (afl->queue_buf[parent_id]->mining_frag_len == frag_len)) {
      temp = 0;
      for (j = 0; j < *num_close_tc; j++) {
        if (parent_id == close_tcs[j]) {
          temp = 1;
          break;
        }
      }
      if (!temp) {
        close_tcs[*num_close_tc] = parent_id;
        (*num_close_tc)++;
        if (unlikely(*num_close_tc >= CLOSE_TCS_SIZE)) return;
      }
    }
  }

  u32 * children = cur_entry->children;

  for (i = 0; i < cur_entry->num_children; i ++) {
    u32 child_id = children[i];
    struct queue_entry * child_entry = afl->queue_buf[child_id];

    if (child_entry->is_mined < MAX_MINING_TRY) {
      mining_wrapper(afl, child_id);
    }

    if ((child_entry->is_mined == (u32) -1) && (afl->queue_buf[child_id]->mining_frag_len == frag_len)) {
      temp = 0;
      for (j = 0; j < *num_close_tc; j++) {
        if (cur_entry->children[i] == close_tcs[j]) {
          temp = 1;
          break;
        }
      }
      if(temp) continue;
      close_tcs[*num_close_tc] = cur_entry->children[i];
      (*num_close_tc)++;
      if (unlikely(*num_close_tc >= CLOSE_TCS_SIZE)) return;
    }
  }

  if (degree > 1) {
    for (i = cur_num_close_tcs; i < *num_close_tc; i ++) {
      get_close_tcs(afl, close_tcs[i], close_tcs, num_close_tc, degree - 1, frag_len);
    }
  }

  return;
}

void write_friend_stats (afl_state_t * afl) {
  u8    fn[PATH_MAX];
  FILE *f;
  u32 idx1, idx2, idx3;
  s32 fd;

  if (afl->func_exec_count_table) {
    
    snprintf(fn, PATH_MAX, "%s/FRIEND/func_exec_table.csv", afl->out_dir);
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
      if (afl->func_exec_count_table[idx1]) {
        for (idx2 = 0; idx2 < afl->num_func ; idx2++){
            fprintf(f, "%u,", afl->func_exec_count_table[idx1][idx2]);
        }
      } else {
        for (idx2 = 0; idx2 < afl->num_func ; idx2++){
            fprintf(f, "0,");
        }
      }
      fprintf(f, "\n");
    }
    fclose(f);
    
  }

  snprintf(fn, PATH_MAX, "%s/FRIEND/cmp_exec_table.csv", afl->out_dir);
  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  f = fdopen(fd, "w");
  for (idx1 = 0; idx1 < afl->num_func; idx1++) {
    if (afl->func_cmp_exec_count_table[idx1]) {
      struct func_cmp_info * cur_func_info = afl->func_cmp_map[idx1];
      u32 num_cmp = cur_func_info->cmp_id_end - cur_func_info->cmp_id_begin;
      fprintf(f, "Func : %u, %u:%u,\n", idx1, cur_func_info->cmp_id_begin, cur_func_info->cmp_id_end);
      for (idx2 = 0; idx2 < num_cmp; idx2++) {
        for(idx3 = 0; idx3 < num_cmp; idx3++) {
          fprintf(f, "%u,", afl->func_cmp_exec_count_table[idx1][idx2][idx3]);
        }
        fprintf(f,"\n");
      }
    } else {
      fprintf(f, "Func : %u, no exec\n", idx1);
    }
  }
  fclose(f);

  // FRIEND related stats
  snprintf(fn, PATH_MAX, "%s/FRIEND/FRIEND.stat", afl->out_dir);
  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);

  f = fdopen(fd, "w");
  fprintf(f, "# of func :%u\n", afl->num_func);
  fprintf(f, "# of cmp :%u\n", afl->num_cmp);
  fprintf(f, "# of covered branch:%u\n", afl->covered_branch);
  fprintf(f, "cmp queue size :%u\n", afl->cmp_queue_size);
  fprintf(f, "Avg. length of tcs : %llu/%u=%.1f", afl->tc_len_sum, afl->queued_paths,
    (double)afl->tc_len_sum / afl->queued_paths);
  fclose(f);

  snprintf(fn, PATH_MAX, "%s/FRIEND/cmp_queue.stat", afl->out_dir);
  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  f = fdopen(fd, "w");

  struct cmp_queue_entry * q = afl->cmp_queue->next;

  q = afl->cmp_queue;
  fprintf(f, "cmp queue size :%u\n", afl->cmp_queue_size);
  fprintf(f, "cmpid, condition, mutating tc idx,"
             " # of changing tcs, num_fuzzed, num_skipped\n");

  while (q != NULL) {
    fprintf(f, "%u,%u,%u,%u,%u,%u\n",
      q->id, q->condition,q->mutating_tc_idx,
      q->num_value_changing_tcs, q->num_fuzzed, q->num_skipped);
    q = q->next;
  }

  fclose(f);

  snprintf(fn, PATH_MAX, "%s/FRIEND/findings.stat", afl->out_dir);
  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);

  u8 val_buf[6][STRINGIFY_VAL_SIZE_MAX];
#define IB(i) (val_buf[(i)])

  f = fdopen(fd, "w");
  fprintf(f, "havoc/splice : %s/%s, %s/%s\n", 
        u_stringify_int(IB(0), afl->stage_finds[STAGE_HAVOC]),
        u_stringify_int(IB(2), afl->stage_cycles[STAGE_HAVOC]),
        u_stringify_int(IB(3), afl->stage_finds[STAGE_SPLICE]),
        u_stringify_int(IB(4), afl->stage_cycles[STAGE_SPLICE]));
  
  fprintf(f, "havoc_func : %s/%s, %s/%s\n",
        u_stringify_int(IB(0), afl->stage_finds[STAGE_HAVOC_FUNC]),
        u_stringify_int(IB(2), afl->stage_cycles[STAGE_HAVOC_FUNC]),
        u_stringify_int(IB(3), afl->stage_finds[STAGE_MINING]),
        u_stringify_int(IB(4), afl->stage_cycles[STAGE_MINING]));

  fprintf(f, "argv : %s/%s\n",
    u_stringify_int(IB(0), afl->stage_finds[STAGE_ARGV]),
    u_stringify_int(IB(1), afl->stage_cycles[STAGE_ARGV]));

  fclose(f);

  snprintf(fn, PATH_MAX, "%s/FRIEND/argv_words", afl->out_dir);
  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  f = fdopen(fd, "w");
  for (idx1 = 0; idx1 < 4; idx1++) {
    fprintf(f, "argv keywords class : %u\n", idx1);
    for (idx2 = 0; idx2 < afl->num_argv_word_buf_words[idx1]; idx2++) {
      struct argv_word_entry * arg = afl->argv_words_bufs[idx1][idx2];
      fprintf(f, "%s\n",arg->word);
    }
  }
  fclose(f);

  snprintf(fn, PATH_MAX, "%s/FRIEND/argvs", afl->out_dir);
  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  f = fdopen(fd, "w");
  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    struct argv_word_entry ** argv = afl->argvs_buf[idx1]->args;
    idx2 = 0;
    while(argv[idx2]) {
      fprintf(f, "%s ", argv[idx2]->word);
      idx2++;
    }
    fprintf(f, "\n");
  }
  fclose(f);

  return;
}

void fuzz_one_func (afl_state_t *afl) {

  u32 len, temp_len;
  u32 idx1, idx2, idx3;
  u8 *out_buf, *orig_in;
  u64 havoc_queued = 0, orig_hit_cnt, new_hit_cnt;
  u32 perf_score = 100;

  struct cmp_queue_entry * cq = afl->cmp_queue_cur;

  struct queue_entry * cur_tc = afl->queue_cur;
  u32 cur_tc_id = afl->current_entry;

  len = (u32) cur_tc->len;
  
  orig_in = queue_testcase_get(afl, cur_tc);

  out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
  if (unlikely(!out_buf)) { PFATAL("alloc"); }

  memcpy(out_buf, orig_in, len);

  perf_score = calculate_score(afl, cur_tc);

  u32 target_cmp_id = cq->id;

  if (cur_tc->is_mined < MAX_MINING_TRY) {
    mining_wrapper(afl, cur_tc_id);
  }

  if (cur_tc->is_mined != (u32) -1) {
    return;
  }

  //get related funcs
  memset(afl->func_list, 0, sizeof(u8) * afl->num_func);
  u32 * cmp_func_map = afl->cmp_func_map;
  u32 target_func = cmp_func_map[target_cmp_id];
  //u32 target_func_begin_id = afl->func_cmp_map[target_func]->cmp_id_begin;
  //u32 target_cmp_id_in_func = target_cmp_id - target_func_begin_id;
  u32 ** func_exec_count_table = afl->func_exec_count_table;
  //float target_cmp_exec = (float) afl->func_cmp_exec_count_table[target_func][target_cmp_id_in_func][target_cmp_id_in_func];
  u32 * target_func_exec_count = func_exec_count_table[target_func];
  if (unlikely(target_func_exec_count == NULL)) {
    func_exec_count_table[target_func] = target_func_exec_count = (u32 *) calloc(afl->num_func, sizeof(u32));
  }
  float target_func_exec = (float) target_func_exec_count[target_func];
  
  // No D/0
  if (unlikely(target_func_exec == 0.0)) target_func_exec = 1.0;
  u32 num_frag = cur_tc->num_mining_frag;
  u32 frag_len = cur_tc->mining_frag_len;

  if (unlikely(num_frag == 0)) {
    return;
  }

  if (num_frag > afl->frag_score_size) {
    afl->frag_score = (float *) realloc(afl->frag_score, num_frag * sizeof(float));
    afl->num_frag_score_sum = (float *) realloc(afl->num_frag_score_sum, num_frag * sizeof(float));
    afl->frag_buf = (u32 *) realloc (afl->frag_buf, num_frag * sizeof(u32) * 4);
    afl->frag_score_size = num_frag;
  }

  u32 frag_buf_size = num_frag * 4;

  float * frag_score = afl->frag_score;
  float * num_frag_score_sum = afl->num_frag_score_sum;
  u32 * frag_buf = afl->frag_buf;
  
  memset(frag_score, 0, sizeof(float) * num_frag);
  memset(num_frag_score_sum, 0, sizeof(float) * num_frag);

  struct byte_cmp_set ** mining_result = mining_deserialize(afl, cur_tc_id);

  for (idx1 = 0; idx1 < num_frag; idx1++) {
    u32 num_cmp = mining_result[idx1]->num_changed_val_cmps;
    for (idx2 = 0; idx2 < num_cmp; idx2++) {
      u32 val_changed_cmp_id = mining_result[idx1]->changed_val_cmps[idx2];
      u32 val_changed_cmp_func_id = cmp_func_map[val_changed_cmp_id];
      float common_exec_count = (float) target_func_exec_count[val_changed_cmp_func_id];
      if (unlikely(func_exec_count_table[val_changed_cmp_func_id] == NULL)) {
        func_exec_count_table[val_changed_cmp_func_id] = (u32 *) calloc(afl->num_func, sizeof(u32));
      }
      float val_changed_func_exec_count = (float) func_exec_count_table[val_changed_cmp_func_id][val_changed_cmp_func_id];
      if (unlikely(val_changed_func_exec_count == 0.0)) val_changed_func_exec_count = 1.0;

      float rel = common_exec_count * common_exec_count / target_func_exec / val_changed_func_exec_count;
      if (unlikely(afl->rand_funcrel)) {
        rel = ((float) rand_below(afl, 1000)) / 1000.0;
      }
      
      frag_score[idx1] += rel;
      num_frag_score_sum[idx1] += 1.0;
    }
  }

  mining_deserialize_free(mining_result, num_frag);
  

  u32 * close_tcs = afl->close_tcs;
  memset(close_tcs, 255, sizeof(u32) * CLOSE_TCS_SIZE);
  u32 num_close_tc = 0;

  get_close_tcs(afl, cur_tc_id, close_tcs, &num_close_tc, CLOSE_TC_THRESHOLD, frag_len);

  if (unlikely(afl->rand_close_tc)) {
    u32 tmp_num_close_tc = 0;
    while (tmp_num_close_tc < num_close_tc) {
      u32 rand_tc_id = rand_below(afl, afl->queued_paths);
      if (afl->queue_buf[rand_tc_id]->is_mined == (u32) -1) {
        close_tcs[tmp_num_close_tc++] = rand_tc_id;
      }
    }
  }

  // Eval frags
  for (idx1 = 0; idx1 < num_close_tc; idx1++) {
    if (NUM_CLOSE_TC_TO_USE >= rand_below(afl, num_close_tc)) {
      continue;
    }

    u32 cur_mined_tc_id = close_tcs[idx1];

    struct queue_entry * mined_entry = afl->queue_buf[cur_mined_tc_id];

    mining_result = mining_deserialize(afl, cur_mined_tc_id);

    u32 cur_num_frag = num_frag;
    if (num_frag > mined_entry->num_mining_frag) {
      cur_num_frag = mined_entry->num_mining_frag;
    }

    for (idx2 = 0; idx2 < cur_num_frag; idx2++) {
      u32 num_cmp = mining_result[idx2]->num_changed_val_cmps;
      for (idx3 = 0; idx3 < num_cmp; idx3++) {
        u32 val_changed_cmp_id = mining_result[idx2]->changed_val_cmps[idx3];
        u32 val_changed_cmp_func_id = cmp_func_map[val_changed_cmp_id];
        float common_exec_count = (float) target_func_exec_count[val_changed_cmp_func_id];
        if (unlikely(func_exec_count_table[val_changed_cmp_func_id] == NULL)) {
          func_exec_count_table[val_changed_cmp_func_id] = (u32 *) calloc(afl->num_func, sizeof(u32));
        }
        float val_changed_func_exec_count = (float) func_exec_count_table[val_changed_cmp_func_id][val_changed_cmp_func_id];
        if (unlikely(val_changed_func_exec_count == 0.0)) val_changed_func_exec_count = 1.0;

        float rel = common_exec_count * common_exec_count / target_func_exec / val_changed_func_exec_count;
        if (unlikely(afl->rand_funcrel)) {
          rel = ((float) rand_below(afl, 1000)) / 1000.0;
        }
        
        frag_score[idx2] += rel;
        num_frag_score_sum[idx2] += 1.0;
      }
    }

    mining_deserialize_free(mining_result, mined_entry->num_mining_frag);
  }

  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  havoc_queued = afl->queued_paths;

  afl->stage_name = "havoc_func";
  afl->stage_short = "havoc_func";
  afl->stage_max = HAVOC_CYCLES * perf_score / afl->havoc_div / 100;

  if (afl->stage_max < HAVOC_MIN) { afl->stage_max = HAVOC_MIN; }

  afl->stage_max /= 2;

  float min_score = FLT_MAX;
  float max_score = FLT_MIN;
  float score_sum = 0.0;
  u32 max_frag = 0;
  for (idx1 = 0; idx1 < num_frag; idx1++) {
    if (num_frag_score_sum[idx1]) {
      float score = frag_score[idx1] / num_frag_score_sum[idx1];
      frag_score[idx1] = score;
      score_sum += score;
      if (score < min_score) {
        min_score = score;
      }
      if (score > max_score) {
        max_score = score;
        max_frag = idx1;
      }
    }
  }

  for (idx1 = 0; idx1 < num_frag; idx1++) {
    if (!num_frag_score_sum[idx1]) {
      frag_score[idx1] = min_score;
      score_sum += min_score;
    }
  }

  score_sum = score_sum - (float) num_frag * min_score;

  u32 frag_buf_idx = 0;

  for (idx1 = 0; idx1 < num_frag; idx1++) {
    u32 num_prop = (u32) ((float) frag_buf_size * (frag_score[idx1] - min_score) / score_sum) + frag_buf_idx + 1;
    if (unlikely(num_prop > frag_buf_size)) {
      num_prop = frag_buf_size;
    }
    while (frag_buf_idx < num_prop) {
      frag_buf[frag_buf_idx++] = idx1;
    }
  }

  while (frag_buf_idx < frag_buf_size) {
    frag_buf[frag_buf_idx++] = max_frag;
  }

  u32 mut_frag_idx = 0, frag_begin_idx = 0;
  temp_len = len;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    if (afl->stop_soon) break;

    u32 use_stacking1 = 1 << (1 + rand_below(afl, HAVOC_STACK_POW2));
    u32 rand_value;
    afl->stage_cur_val = use_stacking1;

    for (idx1 = 0; idx1 < use_stacking1; idx1++) {

      mut_frag_idx = frag_buf[rand_below(afl, frag_buf_size)];

      frag_begin_idx = mut_frag_idx * frag_len;
      temp_len = frag_len;

      if (unlikely(frag_begin_idx + frag_len > len)) {
        temp_len = len - frag_begin_idx;
        if (unlikely(temp_len < 4)) continue;
      }

      afl->mutated_frag_idx[idx1] = frag_begin_idx;

      u32 use_stacking2 = 1 << (1 + rand_below(afl, HAVOC_STACK_POW2));

      for (idx2 = 0; idx2 < use_stacking2 ; idx2++) {

        switch (rand_below(afl, 11)) {

          case 0:

            /* Flip a single bit somewhere. Spooky! */
            
            rand_value = (frag_begin_idx << 3) + rand_below(afl, temp_len << 3);
            FLIP_BIT(out_buf, rand_value);
            break;

          case 1:

            /* Set byte to interesting value. */
            rand_value = frag_begin_idx + rand_below(afl, temp_len);
            out_buf[rand_value] =
                interesting_8[rand_below(afl, sizeof(interesting_8))];
                //num_mutated_bytes++;
            break;

          case 2:

            /* Set word to interesting value, randomly choosing endian. */

            if (rand_below(afl, 2)) {

              rand_value = frag_begin_idx + rand_below(afl, temp_len);
              if(unlikely(rand_value >= len - 1)) rand_value = len - 2;
              *(u16 *)(out_buf + rand_value) =
                  interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)];
                  //num_mutated_bytes+=2;

            } else {

              rand_value = frag_begin_idx + rand_below(afl, temp_len);
              if(unlikely(rand_value >= len - 1)) rand_value = len - 2;
              *(u16 *)(out_buf + rand_value) = SWAP16(
                  interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)]);
                  //num_mutated_bytes+=2;

            }

            break;

          case 3:

            /* Set dword to interesting value, randomly choosing endian. */

            rand_value = frag_begin_idx + rand_below(afl, temp_len);
            if(unlikely(rand_value >= len - 3)) rand_value = len - 4;

            if (rand_below(afl, 2)) {
              *(u32 *)(out_buf + rand_value) =
                  interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)];
            } else {
              *(u32 *)(out_buf + rand_value) = SWAP32(
                  interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)]);
            }

            break;

          case 4:

            /* Randomly subtract from byte. */
            rand_value = frag_begin_idx + rand_below(afl, temp_len);
            out_buf[rand_value] -= 1 + rand_below(afl, ARITH_MAX);
            break;

          case 5:

            /* Randomly add to byte. */
            rand_value = frag_begin_idx + rand_below(afl, temp_len);
            out_buf[rand_value] += 1 + rand_below(afl, ARITH_MAX);
            break;

          case 6:

            /* Randomly subtract from word, random endian. */
            rand_value = frag_begin_idx + rand_below(afl, temp_len);
            if(unlikely(rand_value >= len - 1)) rand_value = len - 2;
            if (rand_below(afl, 2)) {

              *(u16 *)(out_buf + rand_value) -= 1 + rand_below(afl, ARITH_MAX);
              //num_mutated_bytes+=2;

            } else {

              u16 num = 1 + rand_below(afl, ARITH_MAX);
              *(u16 *)(out_buf + rand_value) =
                  SWAP16(SWAP16(*(u16 *)(out_buf + rand_value)) - num);
                  //num_mutated_bytes+=2;

            }

            break;

          case 7:

            /* Randomly add to word, random endian. */
            
            rand_value = frag_begin_idx + rand_below(afl, temp_len);
            if(unlikely(rand_value >= len - 1)) rand_value = len - 2;
            if (rand_below(afl, 2)) {

              *(u16 *)(out_buf + rand_value) += 1 + rand_below(afl, ARITH_MAX);
              //num_mutated_bytes+=2;

            } else {

              u16 num = 1 + rand_below(afl, ARITH_MAX);

              *(u16 *)(out_buf + rand_value) =
                  SWAP16(SWAP16(*(u16 *)(out_buf + rand_value)) + num);
                  //num_mutated_bytes+=2;

            }

            break;

          case 8:

            /* Randomly subtract from dword, random endian. */

            rand_value = frag_begin_idx + rand_below(afl, temp_len);
            if(unlikely(rand_value >= len - 3)) rand_value = len - 4;
            
            if (rand_below(afl, 2)) {

              *(u32 *)(out_buf + rand_value) -= 1 + rand_below(afl, ARITH_MAX);
              //num_mutated_bytes+=4;

            } else {

              u32 num = 1 + rand_below(afl, ARITH_MAX);

              *(u32 *)(out_buf + rand_value) =
                  SWAP32(SWAP32(*(u32 *)(out_buf + rand_value)) - num);
                  //num_mutated_bytes+=4;

            }

            break;

          case 9:

            /* Randomly add to dword, random endian. */

            rand_value = frag_begin_idx + rand_below(afl, temp_len);
            if(unlikely(rand_value >= len - 3)) rand_value = len - 4;

            if (rand_below(afl, 2)) {

              *(u32 *)(out_buf + rand_value) += 1 + rand_below(afl, ARITH_MAX);
              //num_mutated_bytes+=4;

            } else {

              u32 num = 1 + rand_below(afl, ARITH_MAX);

              *(u32 *)(out_buf + rand_value) =
                  SWAP32(SWAP32(*(u32 *)(out_buf + rand_value)) + num);
                  //num_mutated_bytes+=4;

            }

            break;

          case 10:

            /* Just set a random byte to a random value. Because,
              why not. We use XOR with 1-255 to eliminate the
              possibility of a no-op. */

            rand_value = frag_begin_idx + rand_below(afl, temp_len);
            out_buf[rand_value] ^= 1 + rand_below(afl, 255);
            break;
        }
      }
    } // end of for (idx1 = 0; idx1 < use_stacking1; idx1++)

    common_fuzz_stuff(afl, out_buf, len, cur_tc->argv_idx);

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    for (idx1 = 0; idx1 < use_stacking1; idx1++) {

      frag_begin_idx = afl->mutated_frag_idx[idx1];
      temp_len = frag_len;
      
      if (unlikely(frag_begin_idx + frag_len > len)) {
        temp_len = len - frag_begin_idx;
        if (unlikely(temp_len < 4)) continue;
      }

      memcpy(out_buf + frag_begin_idx, orig_in + frag_begin_idx, temp_len);
    }

    if (afl->queued_paths != havoc_queued) {

      if (perf_score <= afl->havoc_max_mult * 100) {

        afl->stage_max *= 2;
        perf_score *= 2;

      }

      havoc_queued = afl->queued_paths;

    }
  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes - orig_hit_cnt;

  afl->stage_finds[STAGE_HAVOC_FUNC] += new_hit_cnt;
  afl->stage_cycles[STAGE_HAVOC_FUNC] += afl->stage_max;
  return ;
}