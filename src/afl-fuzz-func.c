

#include "afl-fuzz.h"
#include "funclog.h"

void func_exec_child(afl_forkserver_t *fsrv, char **argv) {
  execv(fsrv->func_binary, argv);
}


void init_func(afl_state_t* afl) {

  u8    fn[PATH_MAX];
  FILE * f = fopen(afl->func_info_txt, "r");

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
  
  ck_free(afl->func_info_txt);

  afl->func_exec_count_table =
    (u32 **) calloc (sizeof(u32*), afl->num_func);
  if (!afl->func_exec_count_table) PFATAL("Can't alloc func_exec_count_table");

  afl->func_cmp_exec_count_table = (u32 ***) calloc (afl->num_func, sizeof (u32 **));
  if (!afl->func_cmp_exec_count_table) PFATAL("Can't alloc func_cmp_exec_count_table");

  afl->func_list = (u8 *) malloc (sizeof(u8) * afl->num_func);
  if (!afl->func_list) PFATAL("Can't alloc func_exec_exec");

  afl->cmp_queue_entries_ptr = (struct cmp_queue_entry **) calloc(afl->num_cmp, sizeof(struct cmp_queue_entry*));
  if (afl->cmp_queue_entries_ptr == NULL) PFATAL("Can't alloc cmp_queue_entries");
  for (i = 0 ; i < afl->num_cmp; i++) {
    afl->cmp_queue_entries_ptr[i] = (struct cmp_queue_entry *) calloc(1, sizeof(struct cmp_queue_entry));
    afl->cmp_queue_entries_ptr[i]->id = i;
  }

  afl->tc_graph = (struct tc_graph_entry **) calloc(INIT_TC_GRAPH_SIZE, sizeof(struct tc_graph_entry *));
  if (afl->tc_graph == NULL) PFATAL("Can't alloc tc_graph");
  afl->tc_graph_size = INIT_TC_GRAPH_SIZE;

  snprintf(fn, PATH_MAX, "%s/FRIEND_debug.txt", afl->out_dir);
  s32 fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  afl->debug_file = fdopen(fd, "w");
}

void init_trim_and_func(afl_state_t * afl) {
  printf("init trimming starts\n");

  s32 fd, len;
  u8 * in_buf;
  //u8 res;

  u64 cur_time = get_cur_time();

  u32 tc_idx = 0;

  for(tc_idx = 0; tc_idx < afl->queued_paths; tc_idx++) {
    printf("%u/%u\n",tc_idx, afl->queued_paths);

    struct queue_entry * q = afl->queue_buf[tc_idx];

    if (q->disabled) {
      continue;
    }

    fd = open(q->fname, O_RDONLY);
    if (unlikely(fd < 0)) PFATAL("Unable to open '%s'", q->fname);

    len = q->len;
    in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (unlikely(in_buf == MAP_FAILED)) PFATAL("Unable to mmap '%s' with len %d", q->fname, len);

    close(fd);

    //res = trim_case(afl, q, in_buf);
    //if (unlikely(res == FSRV_RUN_ERROR)) FATAL("Unable to execute target application");

    q->trim_done = 1;

    update_tc_graph_and_branch_cov(afl, tc_idx, (u32) -1, (u32) -1, in_buf, len);
   
    munmap(in_buf, len);
  }

  afl->mining_done_idx = (u32) -1;

  printf("init trimming done, took %llus", (get_cur_time() - cur_time) / 1000);

  return;
}

void mining_wrapper(afl_state_t * afl) {

  s32  len;
  u8 * in_buf;

  afl->mining_done_idx++;

  struct queue_entry * q = afl->queue_buf[afl->mining_done_idx];

  if (q->disabled) return;

  len = q->len;
  in_buf = queue_testcase_get(afl, q);

  mining_bytes(afl, in_buf, len, afl->mining_done_idx);

}


u32 func_choose_block_len(afl_state_t *afl, u32 limit, u32 len) {

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

void update_tc_graph_and_branch_cov(afl_state_t * afl, u32 tc_idx, u32 parent_idx, u32 parent2_idx, u8 * buf, u32 len) {

  u8    fn[PATH_MAX];
  FILE *f;
  s32 fd;
  u32 i1,i2,i3;

  if ((tc_idx >= afl->tc_graph_size) ||
    ((parent_idx != (u32) -1) && parent_idx >= afl->tc_graph_size) ||
    ((parent2_idx != (u32) -1) && (parent2_idx >= afl->tc_graph_size))) {
    afl->tc_graph_size += INIT_TC_GRAPH_SIZE;
    afl->tc_graph = (struct tc_graph_entry **) realloc(afl->tc_graph,
      sizeof(struct tc_graph_entry *) * (afl->tc_graph_size));
    memset(afl->tc_graph + afl->tc_graph_size - INIT_TC_GRAPH_SIZE,
      0, sizeof(struct tc_graph_entry *) * INIT_TC_GRAPH_SIZE);
  }

  if (afl->tc_graph[tc_idx] == NULL) {
    afl->tc_graph[tc_idx] = (struct tc_graph_entry *) calloc(1, sizeof(struct tc_graph_entry));
  }

  struct tc_graph_entry * new_tc = afl->tc_graph[tc_idx];

  new_tc->parents[0] = parent_idx;
  new_tc->num_parents = 0;

  if (parent_idx != (u32) -1) {
      if (likely(parent_idx < tc_idx)) {
      struct tc_graph_entry * parent = afl->tc_graph[parent_idx];
      if (parent == NULL) {
        afl->tc_graph[parent_idx] = (struct tc_graph_entry *) calloc(1, sizeof(struct tc_graph_entry));
        parent = afl->tc_graph[parent_idx];
      }
      if (parent->children == NULL) { 
        parent->children = (u32 *) malloc (sizeof(u32) * TC_CHILDREN_SIZE);
        parent->children_size = TC_CHILDREN_SIZE;
      }
      parent->children[parent->num_children++] = tc_idx;
      if(unlikely(parent->num_children >= parent->children_size)){
        parent->children_size += TC_CHILDREN_SIZE;
        parent->children = realloc(parent->children, parent->children_size * sizeof(u32));
      }

      new_tc->num_parents = 1;
    } else {
      //TODO : why?
    }
  }
  
  if (parent2_idx != (u32) -1) {
    if (likely(parent2_idx < tc_idx)) {
      struct tc_graph_entry * parent = afl->tc_graph[parent2_idx];
      if (parent == NULL) {
        afl->tc_graph[parent2_idx] = (struct tc_graph_entry *) calloc(1, sizeof(struct tc_graph_entry));
        parent = afl->tc_graph[parent2_idx];
      }
      new_tc->parents[new_tc->num_parents++] = parent2_idx;
      if (parent->children == NULL) {
        parent->children = (u32 *) malloc (sizeof(u32) * TC_CHILDREN_SIZE);
        parent->children_size = TC_CHILDREN_SIZE;
      }

      parent->children[parent->num_children++] = tc_idx;
      if(unlikely(parent->num_children >= parent->children_size)){
        parent->children_size += TC_CHILDREN_SIZE;
        parent->children = realloc(parent->children, parent->children_size * sizeof(u32));
      }
    } else {
      //TODO : why?
    }
  }

  u32 cmp_id;
  struct cmp_func_entry * entries = afl->shm.func_map;

  for (cmp_id = 0; cmp_id < afl->num_cmp ; cmp_id++) {
    entries[cmp_id].executed = 0;
    entries[cmp_id].condition = 0;
  }

  write_to_testcase(afl, buf, len);
  u8 fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout);

  if (fault == FSRV_RUN_TMOUT) {
    //what?
    WARNF("input in the queue timed out on func log");
    return;
  }

  u8 precondition, postcondition;
  struct cmp_queue_entry * cur_queue_entry;
  memset(afl->func_list, 0, sizeof(u8) * afl->num_func);

  //update branch coverage/cmp queue
  for (cmp_id = 0; cmp_id < afl->num_cmp; cmp_id++) {
    if (entries[cmp_id].executed) {

      afl->func_list[afl->cmp_func_map[cmp_id]] = 1;

      cur_queue_entry = afl->cmp_queue_entries_ptr[cmp_id];
      precondition = cur_queue_entry->condition;

      if (precondition == 3) continue;

      cur_queue_entry->condition |= entries[cmp_id].condition;
      postcondition = cur_queue_entry->condition;

      if ((precondition == 0) && (postcondition != 3)) {
        //new target
        if (likely(afl->cmp_queue)) {
          afl->cmp_queue_top->next = cur_queue_entry;
          afl->cmp_queue_top = cur_queue_entry;
        } else {
          afl->cmp_queue = afl->cmp_queue_top = afl->cmp_queue_cur = cur_queue_entry;
        }
        afl->cmp_queue_size++;
        afl->covered_branch++;
      } else if ((precondition == 0) && (postcondition == 3)) {
        afl->covered_branch += 2;
      } else if ((precondition != 3) && (postcondition == 3)) {
        afl->covered_branch++;
      }

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
    }
  }

  //update func rel/ cmp rel
  for (i1 = 0; i1 < afl->num_func; i1++) {
    if (afl->func_list[i1]) {
      if (unlikely(afl->func_exec_count_table[i1] == NULL)) {
        afl->func_exec_count_table[i1] = (u32 *) calloc(sizeof (u32), afl->num_func);
        if (unlikely(afl->func_exec_count_table[i1] == NULL))
          PFATAL("Can't alloc func_exec_count_table[i1]");
      }
      for (i2 = 0; i2 < afl->num_func; i2++) {
        afl->func_exec_count_table[i1][i2] += afl->func_list[i2]; 
      }

      struct func_cmp_info * cur_func_info = afl->func_cmp_map[i1];
      u32 num_cmp = cur_func_info->cmp_id_end - cur_func_info->cmp_id_begin;
      if (unlikely(afl->func_cmp_exec_count_table[i1] == NULL)) {        
        afl->func_cmp_exec_count_table[i1] = (u32 **) calloc(num_cmp, sizeof (u32 *));
        for (i2 = 0; i2 < num_cmp; i2++) {
          afl->func_cmp_exec_count_table[i1][i2] = (u32 *) calloc (num_cmp, sizeof (u32));
        }
      }

      for (i2 = 0; i2 < num_cmp; i2++) {
        if (entries[i2 + cur_func_info->cmp_id_begin].executed) {
          for (i3 = 0; i3 < num_cmp; i3++) {
            afl->func_cmp_exec_count_table[i1][i2][i3] += entries[i3 + cur_func_info->cmp_id_begin].executed;
          }
        }
      }
    }
  }

  //write tc_graph for syncing, TODO
  /*
  snprintf(fn, PATH_MAX, "%s/tc_graph/id:%06u", afl->out_dir, tc_idx);
  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  f = fdopen(fd, "w");

  u32 max_parents = 1 << (CLOSE_TC_THRESHOLD + 1);

  u32 * parents = (u32 *) malloc(sizeof(u32) * max_parents);
  memset(parents, 255, sizeof(u32) * max_parents);

  u32 * parents_weight = (u32 *) malloc(sizeof(u32) * max_parents);
  u32 num_parents = 0;
  
  struct tc_graph_entry * parent;
  parents[0] = tc_idx;
  parents_weight[0] = 0;

  while((num_parents < max_parents) && (parents[num_parents] != (u32) -1)) {
    
    fprintf(f, "%u,%u\n", parents_weight[num_parents], parents[num_parents]);
    parent = afl->tc_graph[parents[num_parents]];
    if (parent && (parents_weight[num_parents] < CLOSE_TC_THRESHOLD)) {
      for (i1 = 0; i1 < parent->num_parents; i1++) {
        parents[num_parents + i1 + 1] = parent->parents[i1];
        parents_weight[num_parents + i1 + 1] = parents_weight[num_parents] + 1;
      }
    }
    
    num_parents++;
  }

  fclose(f);
  free(parents);
  free(parents_weight);
  */
  return;
}

void mining_serialize(afl_state_t *afl, struct byte_cmp_set ** mining_result, u32 num_mining_set, u32 tc_idx) {
  u32 idx1;
  u8 * fn = alloc_printf("%s/FRIEND/mining/id:%06u", afl->out_dir, tc_idx);
  FILE * f = fopen(fn, "w");

  fwrite(&num_mining_set, sizeof(u32), 1, f);

  for (idx1 = 0; idx1 < num_mining_set; idx1++) {

    struct byte_cmp_set * tmp = mining_result[idx1];

    fwrite(&(tmp->num_changed_cmps), sizeof(u32), 1, f);
    fwrite(&(tmp->num_abandoned_cmps), sizeof(u32), 1, f);
    fwrite(&(tmp->timeout), sizeof(u8), 1, f);
    if (tmp->timeout == 0) {
      fwrite(tmp->changed_cmps, sizeof(u32), tmp->num_changed_cmps, f);
      fwrite(tmp->abandoned_cmps, sizeof(u32), tmp->num_abandoned_cmps, f);
      free(tmp->changed_cmps);
      free(tmp->abandoned_cmps);
    }
    free(tmp);

  }

  free(mining_result);

  ck_free(fn);
  fclose(f);
}

struct byte_cmp_set ** mining_deserialize(afl_state_t * afl, u32 tc_idx) {
  u32 buffer[8];
  u32 idx1;
  u8 * fn = alloc_printf("%s/FRIEND/mining/id:%06u", afl->out_dir, tc_idx);
  FILE * f = fopen(fn, "r");


  u32 read_size = fread(buffer, sizeof(u32), 1, f);
  assert(likely(read_size == 1));
  u32 num_mining_set = buffer[0];

  u32 num_changed_cmps, num_abandoned_cmps;
  struct byte_cmp_set ** mining_result =
    (struct byte_cmp_set **) malloc(sizeof(struct byte_cmp_set *) * num_mining_set);

  for (idx1 = 0; idx1 < num_mining_set; idx1++) {
    struct byte_cmp_set * tmp = (struct byte_cmp_set *) malloc(sizeof(struct byte_cmp_set));
    mining_result[idx1] = tmp;
    read_size = fread(buffer, sizeof(u32), 2, f);
    assert(likely(read_size == 2));
    num_changed_cmps = buffer[0];
    num_abandoned_cmps = buffer[1];
    read_size = fread(buffer, sizeof(u8), 1, f);
    assert(likely(read_size == 1));
    tmp->timeout = ((u8 *) buffer)[0];

    if (tmp->timeout == 0) {
      tmp->num_changed_cmps = num_changed_cmps;
      tmp->num_abandoned_cmps = num_abandoned_cmps;
      if (num_changed_cmps) {
        tmp->changed_cmps = (u32 *) malloc(sizeof(u32) * num_changed_cmps);
        read_size = fread(tmp->changed_cmps, sizeof(u32), num_changed_cmps, f);
        assert(likely(read_size == num_changed_cmps));
      } else {
        tmp->changed_cmps = NULL;
      }
      if (num_abandoned_cmps) {
        tmp->abandoned_cmps = (u32 *) malloc(sizeof(u32) * num_abandoned_cmps);
        read_size = fread(tmp->abandoned_cmps, sizeof(u32), num_abandoned_cmps, f);
        assert(likely(read_size == num_abandoned_cmps));
      } else {
        tmp->abandoned_cmps = NULL;
      }
    } else {
      tmp->changed_cmps = NULL;
      tmp->abandoned_cmps = NULL;
    }
  }

  ck_free(fn);
  fclose(f);
  return mining_result;
}

void mining_deserialize_free(struct byte_cmp_set ** mining_result, u32 num_mining_set) {
  u32 idx1;

  for (idx1 = 0; idx1< num_mining_set; idx1++) {
    struct byte_cmp_set * tmp = mining_result[idx1];
    if (tmp->changed_cmps) free(tmp->changed_cmps);
    if (tmp->abandoned_cmps) free(tmp->abandoned_cmps);
    free(tmp);
  }

  free(mining_result);
}

void mining_bytes(afl_state_t *afl, u8 * out_buf, u32 len, u32 tc_idx) {

  u32 i1, i2, cmp_id;
  struct cmp_func_entry * entries = afl->shm.func_map;
  struct tc_graph_entry * new_tc = afl->tc_graph[tc_idx];

  for (i1 = 0; i1 < afl->num_cmp ; i1++) {
    entries[i1].condition = 0;
    entries[i1].precondition = 0;
    entries[i1].executed = 0;
  }

  write_to_testcase(afl, out_buf, len);

  u8 fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout);

  if (fault == FSRV_RUN_TMOUT) {
    //what?
    WARNF("input in the queue timed out on func log");
    return;
  }

  //get condition values of the new test input
  for (i1 = 0; i1 < afl->num_cmp; i1++) {
    entries[i1].precondition = entries[i1].condition;
  }
  
  u8 * out_buf2 = afl_realloc(AFL_BUF_PARAM(mining), len);
  memcpy(out_buf2, out_buf, len);

  u32 byte_mining_frag_len = (len / (MINING_MUT_TIME) + 1;
  u32 len_pow2 = MINING_FRAG_LEN_MIN_POW2;
  if (byte_mining_frag_len < (1u << len_pow2)) {
    byte_mining_frag_len = 1u << len_pow2;
  } else {
    while((1u << len_pow2) < byte_mining_frag_len) {
      len_pow2 ++;
    }
  }
  new_tc->mining_frag_len = 1 << len_pow2;
  new_tc->mining_frag_offset = rand_below(afl, (1 << len_pow2) - 4) + 4;

  struct byte_cmp_set ** mining_result = malloc(sizeof(struct byte_cmp_set*) * (MINING_MUT_TIME + 1));

  //mutate and get new byte/cmps sets
  u32 r, cur_offset = 0, cur_len =  new_tc->mining_frag_offset;

#define FLIP_BIT(_ar, _b)                 \
do {                                      \
                                          \
  u8 *_arf = (u8 *)(_ar);                 \
  u32 _bf = (_b);                         \
  _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                          \
} while (0)

  u32 mining_idx = 0;
  while(cur_offset < len) {

    if (unlikely(mining_idx == 1)) {
      cur_len = new_tc->mining_frag_len;
    }

    if (unlikely(cur_offset + cur_len > len)) {
      cur_len = len - cur_offset;
      if (cur_len < 4) {
        break;
      }
    }

    u32 use_stacking = 1 << (1 + rand_below(afl, HAVOC_STACK_POW2_FUNC));
    u32 rand_value;

    for (i2 = 0; i2 < use_stacking; ++i2) {
      
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
          while (tid == afl->current_entry || afl->queue_buf[tid]->len < 4);

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
    } // end of for (i2 = 0; i2 < use_stacking ; i2++)

    //get byte cmps set

    func_common_fuzz_stuff(afl, out_buf2, len, tc_idx);

    //execute
    for (i2 = 0; i2 < afl->num_cmp; i2++) {
      afl->shm.func_map[i2].executed = 0;
      afl->shm.func_map[i2].condition = 0;
    }

    fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout);

    fprintf(stderr, "mining_idx : %u/%u, frag_len : %u, len : %u, offset : %u\n", mining_idx, MINING_MUT_TIME + 1, new_tc->mining_frag_len, len, new_tc->mining_frag_offset);
    assert(mining_idx < (MINING_MUT_TIME + 1));

    mining_result[mining_idx] = (struct byte_cmp_set *) calloc(1, sizeof(struct byte_cmp_set));
    cur_offset += cur_len;

    if (fault == FSRV_RUN_TMOUT) {
      //penalty
      mining_result[mining_idx++]->timeout = 1;
      memcpy(out_buf2, out_buf, len);
      continue;
    }

    u32 num_changed_cmps = 0, num_abandoned_cmps = 0;
    u32 changed_cmps_buf_size = CMP_BUF_SIZE, abandoned_cmps_buf_size = CMP_BUF_SIZE;

    mining_result[mining_idx]->changed_cmps = (u32 *) malloc (sizeof(u32) * changed_cmps_buf_size);
    mining_result[mining_idx]->abandoned_cmps = (u32 *) malloc (sizeof(u32) * abandoned_cmps_buf_size);

    u8 precondition, postcondition;

    for (cmp_id = 0; cmp_id < afl->num_cmp; cmp_id ++) {
      if(entries[cmp_id].executed) {
        precondition = entries[cmp_id].precondition;
        postcondition = entries[cmp_id].condition;

        if(precondition && (precondition != postcondition)) {
          mining_result[mining_idx]->changed_cmps[num_changed_cmps++] = cmp_id;
          if (unlikely(num_changed_cmps >= changed_cmps_buf_size)) {
            changed_cmps_buf_size += CMP_BUF_SIZE;
            mining_result[mining_idx]->changed_cmps = (u32 *) realloc (mining_result[mining_idx]->changed_cmps, sizeof(u32) * changed_cmps_buf_size);
          }
        }
      } else if (entries[cmp_id].precondition) {
        mining_result[mining_idx]->abandoned_cmps[num_abandoned_cmps++] = cmp_id;
        if (unlikely(num_abandoned_cmps >= abandoned_cmps_buf_size)) {
          abandoned_cmps_buf_size += CMP_BUF_SIZE;
          mining_result[mining_idx]->abandoned_cmps = (u32 *) realloc (mining_result[mining_idx]->abandoned_cmps, sizeof(u32) * abandoned_cmps_buf_size);
        }
      }
    }

    mining_result[mining_idx]->num_changed_cmps = num_changed_cmps;
    mining_result[mining_idx]->num_abandoned_cmps = num_abandoned_cmps;

    if (num_changed_cmps == 0 && num_abandoned_cmps == 0) {
      free(mining_result[mining_idx]->changed_cmps);
      free(mining_result[mining_idx]->abandoned_cmps);
      mining_result[mining_idx]->changed_cmps = NULL;
      mining_result[mining_idx]->abandoned_cmps = NULL;
      mining_result[mining_idx]->timeout = 1;
    }

    memcpy(out_buf2, out_buf, len);
    mining_idx++;
  }

  //Save the mining result as serialized file
  
  mining_serialize(afl, mining_result, mining_idx, tc_idx);
  new_tc->num_mining_set = mining_idx;

  new_tc->initialized = 1;

  return;
}

void get_close_tcs(afl_state_t * afl, u32 target_id, u32 * close_tcs, u32 * num_close_tc, u8 degree, u8 get_parent) {

  u32 i,j;
  u8 temp;

  if (unlikely(*num_close_tc >= CLOSE_TCS_SIZE)) return;
  if (unlikely(target_id >= afl->tc_graph_size)) return;

  struct tc_graph_entry * cur_entry = afl->tc_graph[target_id];
  
  if (cur_entry->initialized) {
    //put target itself
    temp = 0;
    for (j = 0; j < *num_close_tc; j++) {
      if (target_id == close_tcs[j]) {
        temp = 1;
        break;
      }
    }

    if (!temp) {
      close_tcs[*num_close_tc] = target_id;
      (*num_close_tc)++;
      if (unlikely(*num_close_tc >= CLOSE_TCS_SIZE)) return;
    }
  }

  if (degree == 1) {
    if (get_parent) {
      for (i = 0; i < cur_entry->num_parents; i ++) {
        temp = 0;
        for (j = 0; j < *num_close_tc; j++) {
          if (cur_entry->parents[i] == close_tcs[j]) {
            temp = 1;
            break;
          }
        }
        if (temp) continue;
        close_tcs[*num_close_tc] = cur_entry->parents[i];
        (*num_close_tc)++;
        if (unlikely(*num_close_tc >= CLOSE_TCS_SIZE)) return;
      }
    }

    u32 num_children = cur_entry->num_children;

    for (i = 0; i < num_children; i ++) {
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

    return;
  }

  for (i = 0; i < cur_entry->num_parents; i ++) {
    get_close_tcs(afl, cur_entry->parents[i], close_tcs, num_close_tc, degree - 1, 1);
  }
  
  u32 num_children = cur_entry->num_children;

  for (i = 0; i < num_children; i ++) {
    get_close_tcs(afl, cur_entry->children[i], close_tcs, num_close_tc, degree - 1, 0);
  }

  return;
}

void write_func_stats (afl_state_t * afl) {
  u8    fn[PATH_MAX];
  FILE *f;
  u32 idx1, idx2;
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

  // FRIEND related stats
  if (afl->func_binary) {
    snprintf(fn, PATH_MAX, "%s/FRIEND/FRIEND.stat", afl->out_dir);
    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);

    f = fdopen(fd, "w");
    fprintf(f, "# of func :%u\n", afl->num_func);
    fprintf(f, "# of cmp :%u\n", afl->num_cmp);
    fprintf(f, "# of covered branch:%u\n", afl->covered_branch);
    fprintf(f, "cmp queue size :%u\n", afl->cmp_queue_size);
    fprintf(f, "Avg. length of tcs : %llu/%u=%.1f", afl->tc_len_sum, afl->queued_paths, (double)afl->tc_len_sum / afl->queued_paths);
    fclose(f);

    snprintf(fn, PATH_MAX, "%s/FRIEND/cmp_queue.stat", afl->out_dir);
    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    f = fdopen(fd, "w");

    fprintf(f, "cmp queue size :%u\n", afl->cmp_queue_size);
    struct cmp_queue_entry * q = afl->cmp_queue;
    fprintf(f, "cmpid, condition, # changed tcs, # executing tcs, executing tcs, mutating tc idx, exec_max_reached, num_fuzzed, num_skipped\n");
    while (q != NULL) {
      fprintf(f, "%u,%u,%u,%u,%u,%u,%u\n",
        q->id, q->condition, q->num_executing_tcs, q->mutating_tc_idx, q->exec_max_reached, q->num_fuzzed, q->num_skipped);

      q = q->next;
    }
    fclose(f);

    snprintf(fn, PATH_MAX, "%s/FRIEND/tc_graph.stat", afl->out_dir);
    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);

    f = fdopen(fd, "w");
    fprintf(f, "# of queued_tcs : %u\n", afl->queued_paths);
    struct tc_graph_entry * e;
    for(idx1= 0; idx1 < afl->queued_paths ; idx1++) {
      e = afl->tc_graph[idx1];
      if (e != NULL)
        fprintf(f, "tc_idx:%u,num_children:%u\n", idx1, e->num_children);
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

    fclose(f);
  }

  if (afl->byte_scores_sum) {
    snprintf(fn, PATH_MAX, "%s/FRIEND/scores.csv", afl->out_dir);
    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);

    f = fdopen(fd, "w");

    for (idx1 = 0; idx1 < afl->byte_scores_sum_size; idx1++) {
      fprintf(f, "%.2f\n", afl->byte_scores_sum[idx1] / afl->byte_scores_sum_record);
    }
    fclose(f);
  }

  return;
}


void destroy_func(afl_state_t * afl) {
  u32 idx1, idx2;

  if (afl->debug_file)
    fclose(afl->debug_file);

  for (idx1 = 0; idx1 < afl->num_cmp; idx1++) {
    if (afl->cmp_queue_entries_ptr[idx1]) {
      if (afl->cmp_queue_entries_ptr[idx1]->executing_tcs != NULL)
        free(afl->cmp_queue_entries_ptr[idx1]->executing_tcs);
      free(afl->cmp_queue_entries_ptr[idx1]);
    }
  }
  free(afl->cmp_queue_entries_ptr);

  for (idx1 = 0; idx1 < afl->tc_graph_size ; idx1++ ) {
    if (afl->tc_graph[idx1]) {
      if (afl->tc_graph[idx1]->children != NULL)
        free(afl->tc_graph[idx1]->children);
      }
      free(afl->tc_graph[idx1]);
  }

  free(afl->tc_graph);
  ck_free(afl->func_binary);

  if (afl->cmp_func_map)
    free(afl->cmp_func_map);

  if (afl->func_list)
    free(afl->func_list);
  
  if(afl->func_exec_count_table) {
    for (idx1 = 0; idx1 < afl->num_func ; idx1 ++ ) {
      if (afl->func_exec_count_table[idx1])
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

  if (afl->byte_scores) {
    free(afl->byte_scores);
  }

  if (afl->fuzz_one_func_byte_offsets) {
    free(afl->fuzz_one_func_byte_offsets);
  }
  
  if(afl->byte_scores_sum)
    free(afl->byte_scores_sum);
}

void func_common_fuzz_stuff(afl_state_t *afl, u8 *out_buf, u32 len, u32 parent_id) {

  u8 fault;

  write_to_testcase(afl, out_buf, len);

  fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

  if (afl->stop_soon) { return; }

  if (fault == FSRV_RUN_TMOUT) {

    if (afl->subseq_tmouts++ > TMOUT_LIMIT) {

      ++afl->cur_skipped_paths;
      return;

    }

  } else {

    afl->subseq_tmouts = 0;

  }

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (afl->skip_requested) {

    afl->skip_requested = 0;
    ++afl->cur_skipped_paths;
    return;

  }

  /* This handles FAULT_ERROR for us: */

  afl->queued_discovered += save_if_interesting(afl, out_buf, len, fault, parent_id, (u32) -1);

  return ;
}

void fuzz_one_func (afl_state_t *afl) {

  s32 fd;
  u32 len, temp_len;
  u32 i, j, k;
  u8 *out_buf, *orig_in;
  u64 havoc_queued = 0, orig_hit_cnt, new_hit_cnt;
  u32 perf_score = 100;

  // Map the tc into memory
  fd = open(afl->cmp_queue_cur->tc->fname, O_RDONLY);

  if (unlikely(fd < 0)) 
    PFATAL("Unable to open '%s'",afl->cmp_queue_cur->tc->fname);

  len = (u32) afl->cmp_queue_cur->tc->len;
  
  orig_in = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (unlikely(orig_in == MAP_FAILED))
    PFATAL("Unable to mmap '%s' with len %d", afl->cmp_queue_cur->tc->fname, len);

  close(fd);

  out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
  if (unlikely(!out_buf)) { PFATAL("alloc"); }

  memcpy(out_buf, orig_in, len);

  perf_score = calculate_score(afl, afl->cmp_queue_cur->tc);

  afl->stage_name = "havoc_func";
  afl->stage_short = "havoc_func";
  afl->stage_max = HAVOC_CYCLES * perf_score / afl->havoc_div / 100;

  if (afl->stage_max < HAVOC_MIN) { afl->stage_max = HAVOC_MIN; }

  temp_len = len;

  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  havoc_queued = afl->queued_paths;

  u32 target_cmp_id = afl->cmp_queue_cur->id;

  //get related funcs
  memset(afl->func_list, 0, sizeof(u8) * afl->num_func);
  u32 target_func = afl->cmp_func_map[target_cmp_id];
  u32 target_func_begin_id = afl->func_cmp_map[target_func]->cmp_id_begin;
  u32 target_cmp_id_in_func = target_cmp_id - target_func_begin_id;
  float target_cmp_exec = (float) afl->func_cmp_exec_count_table[target_func][target_cmp_id_in_func][target_cmp_id_in_func];
  float target_func_exec = (float) afl->func_exec_count_table[target_func][target_func];

  u32 * close_tcs = (u32 *) malloc(sizeof(u32) * CLOSE_TCS_SIZE);
  memset(close_tcs, 255, sizeof(u32) * CLOSE_TCS_SIZE);
  u32 num_close_tc = 0;

  get_close_tcs(afl, afl->cmp_queue_cur->tc->id, close_tcs, &num_close_tc, CLOSE_TC_THRESHOLD, 1);

  u32 num_mut_bytes = (u32) ((float) len * FUZZ_ONE_FUNC_BYTE_SIZE_RATIO);

  if (unlikely(afl->fuzz_one_func_byte_offsets == NULL)) {
    afl->fuzz_one_func_byte_offsets = (u32 *) malloc(sizeof(u32) * num_mut_bytes);
    afl->fuzz_one_func_byte_offsets_size = num_mut_bytes;
  } else if (unlikely(num_mut_bytes > afl->fuzz_one_func_byte_offsets_size)) {
    free(afl->fuzz_one_func_byte_offsets);
    afl->fuzz_one_func_byte_offsets = (u32 *) malloc(sizeof(u32) * num_mut_bytes);
    afl->fuzz_one_func_byte_offsets_size = num_mut_bytes;
  }


  // Select bytes
  afl->func_cur_num_bytes = 0;


  if(unlikely(afl->byte_scores == NULL)) {
    afl->byte_scores = (float *) malloc(sizeof(float) * len);
    afl->byte_score_size = len;
  } else if (unlikely(afl->byte_score_size < len)) {
    free(afl->byte_scores);
    afl->byte_scores = (float *) malloc(sizeof(float) * len);
    afl->byte_score_size = len;
  }

  memset(afl->byte_scores, 0, sizeof(float) * len);

  for (i = 0; i < num_close_tc; i++) {  
    u32 tc_id = close_tcs[i];
    //TODO: why?
    if (unlikely(tc_id >= afl->tc_graph_size)) continue;
    struct tc_graph_entry * cur_tc = afl->tc_graph[tc_id];

    if (unlikely(!cur_tc->initialized)) continue;

    struct byte_cmp_set ** close_tc_mining_result = mining_deserialize(afl, tc_id);

    u32 num_mining_set = cur_tc->num_mining_set;
    u32 byte_offset = 0;
    u32 byte_len = cur_tc->mining_frag_offset;
    if (unlikely(byte_len > len)) byte_len = len;

    for (j = 0; j < num_mining_set; j++) {
      if (close_tc_mining_result[j]->timeout) {
        for(k = byte_offset; k < byte_offset + byte_len; k ++) {
          afl->byte_scores[k] -= 1.0; //TODO : value?
        }
      } else {
        u32 num_changed_cmps = close_tc_mining_result[j]->num_changed_cmps;
        u32 num_abandoned_cmps = close_tc_mining_result[j]->num_abandoned_cmps;

        float cur_cmp_rel_avg = 0.0;

        for (k = 0; k < num_changed_cmps; k++) {
          u32 cmp_id = close_tc_mining_result[j]->changed_cmps[k];
          u32 cmp_func_id = afl->cmp_func_map[cmp_id];
          if (cmp_func_id == target_func) {
            cur_cmp_rel_avg += 1.0;
            cur_cmp_rel_avg += (float) afl->func_cmp_exec_count_table[target_func][target_cmp_id_in_func][cmp_id - target_func_begin_id]
              / target_cmp_exec;
          } else {
            cur_cmp_rel_avg += (float) afl->func_exec_count_table[target_func][cmp_func_id]
              / target_func_exec;
          }
        }

        if (num_changed_cmps > 0) {
          cur_cmp_rel_avg /= num_changed_cmps;
        }

        float cur_abandoned_rel_avg = 0.0;

        for (k = 0; k < num_abandoned_cmps; k++) {
          u32 cmp_id = close_tc_mining_result[j]->abandoned_cmps[k];
          u32 cmp_func_id = afl->cmp_func_map[cmp_id];
          if (cmp_func_id == target_func) {
            cur_abandoned_rel_avg += 1.0;
            cur_abandoned_rel_avg += (float) afl->func_cmp_exec_count_table[target_func][target_cmp_id_in_func][cmp_id - target_func_begin_id]
              / target_cmp_exec;
          } else {
            cur_abandoned_rel_avg += (float) afl->func_exec_count_table[target_func][cmp_func_id]
              / target_func_exec;
          }
        }

        if (num_abandoned_cmps > 0) {
          cur_abandoned_rel_avg /= num_abandoned_cmps;
        }

        cur_cmp_rel_avg -= cur_abandoned_rel_avg;

        for(k = byte_offset; k < byte_offset + byte_len; k ++) {
          afl->byte_scores[k] += cur_cmp_rel_avg; //TODO : value?
        }
      }

      byte_offset += byte_len;
      if (unlikely(j == 1)) {
        byte_len = cur_tc->mining_frag_len;
      }

      if (unlikely(byte_offset >= len)) {
        break;
      }

      if (unlikely(byte_offset + byte_len > len)) {
        byte_len = len - byte_offset;
      }
    }

    mining_deserialize_free(close_tc_mining_result, num_mining_set);
  }
  free(close_tcs);

  float max_score = 0.0;
  float min_score = FLT_MAX;

  if(unlikely(afl->byte_scores_sum == NULL)) {
    afl->byte_scores_sum = calloc(len, sizeof(float));
    afl->byte_scores_sum_size = len;
  } else if (afl->byte_scores_sum_size < len) {
    afl->byte_scores_sum = realloc(afl->byte_scores_sum, sizeof(float) * len);
    memset(afl->byte_scores_sum + afl->byte_scores_sum_size, 0, sizeof(float) * (len - afl->byte_scores_sum_size));
    afl->byte_scores_sum_size = len;
  }

  for (i = 0; i < len; i++) {
    float score = afl->byte_scores[i];
    if (score > max_score) {
      max_score = score;
    }
    if (score < min_score) {
      min_score = score;
    }
    afl->byte_scores_sum[i] += score;
  }
  afl->byte_scores_sum_record ++;

  float threshold = (max_score - min_score) * afl->score_threshold + min_score;

  for (i = 0; i < len; i++) {
    if (afl->byte_scores[i] > threshold) {
      afl->fuzz_one_func_byte_offsets[afl->func_cur_num_bytes++] = i;

      if(unlikely(afl->func_cur_num_bytes >= num_mut_bytes)) {
        break;
      }
    }
  }

  if (afl->func_cur_num_bytes <= 100) {
    afl->score_threshold -= 0.01;
  } else if (afl->func_cur_num_bytes >= num_mut_bytes) {
    afl->score_threshold += 0.01;
  }

  if (afl->score_threshold < 0.0) {
    afl->score_threshold = 0.1;
  } else if (afl->score_threshold > 1.0) {
    afl->score_threshold = 0.9;
  }

  fprintf(afl->debug_file, "mut bytes : %u/%u, num_close_tc %u, score: %.2f,", afl->func_cur_num_bytes, len, num_close_tc, afl->score_threshold);

  //u32 num_mutated_bytes = 0;
  
  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    u32 use_stacking = 1 << (1 + rand_below(afl, HAVOC_STACK_POW2_FUNC));
    u32 rand_value;
    afl->stage_cur_val = use_stacking;

    if (afl->func_cur_num_bytes == 0) break;

    for (i = 0; i < use_stacking; ++i) {

      switch (rand_below(afl, 11)) {

        case 0:

          /* Flip a single bit somewhere. Spooky! */
          
          rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
          rand_value = (rand_value << 3) + rand_below(afl, 8);
          FLIP_BIT(out_buf, rand_value);
          //num_mutated_bytes++;
          break;

        case 1:

          /* Set byte to interesting value. */
          rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
          out_buf[rand_value] =
              interesting_8[rand_below(afl, sizeof(interesting_8))];
              //num_mutated_bytes++;
          break;

        case 2:

          /* Set word to interesting value, randomly choosing endian. */

          if (temp_len < 2) { break; }

          if (rand_below(afl, 2)) {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 1)) rand_value -= 1;
            *(u16 *)(out_buf + rand_value) =
                interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)];
                //num_mutated_bytes+=2;

          } else {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 1)) rand_value -= 1;
            *(u16 *)(out_buf + rand_value) = SWAP16(
                interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)]);
                //num_mutated_bytes+=2;

          }

          break;

        case 3:

          /* Set dword to interesting value, randomly choosing endian. */

          if (temp_len < 4) { break; }

          if (rand_below(afl, 2)) {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 3)) rand_value = temp_len - 4;
            *(u32 *)(out_buf + rand_value) =
                interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)];
                //num_mutated_bytes+=2;

          } else {
            
            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 3)) rand_value = temp_len - 4;
            *(u32 *)(out_buf + rand_value) = SWAP32(
                interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)]);
                //num_mutated_bytes+=2;
          }

          break;

        case 4:

          /* Randomly subtract from byte. */

          rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
          out_buf[rand_value] -= 1 + rand_below(afl, ARITH_MAX);
          //num_mutated_bytes++;
          break;

        case 5:

          /* Randomly add to byte. */

          rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
          out_buf[rand_value] += 1 + rand_below(afl, ARITH_MAX);
          //num_mutated_bytes++;
          break;

        case 6:

          /* Randomly subtract from word, random endian. */

          if (temp_len < 2) { break; }

          if (rand_below(afl, 2)) {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 1)) rand_value -= 1;
            *(u16 *)(out_buf + rand_value) -= 1 + rand_below(afl, ARITH_MAX);
            //num_mutated_bytes+=2;

          } else {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 1)) rand_value -= 1;
            u16 num = 1 + rand_below(afl, ARITH_MAX);

            *(u16 *)(out_buf + rand_value) =
                SWAP16(SWAP16(*(u16 *)(out_buf + rand_value)) - num);
                //num_mutated_bytes+=2;

          }

          break;

        case 7:

          /* Randomly add to word, random endian. */

          if (temp_len < 2) { break; }

          if (rand_below(afl, 2)) {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 1)) rand_value -= 1;

            *(u16 *)(out_buf + rand_value) += 1 + rand_below(afl, ARITH_MAX);
            //num_mutated_bytes+=2;

          } else {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 1)) rand_value -= 1;
            u16 num = 1 + rand_below(afl, ARITH_MAX);

            *(u16 *)(out_buf + rand_value) =
                SWAP16(SWAP16(*(u16 *)(out_buf + rand_value)) + num);
                //num_mutated_bytes+=2;

          }

          break;

        case 8:

          /* Randomly subtract from dword, random endian. */

          if (temp_len < 4) { break; }

          if (rand_below(afl, 2)) {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 3)) rand_value = temp_len - 4;

            *(u32 *)(out_buf + rand_value) -= 1 + rand_below(afl, ARITH_MAX);
            //num_mutated_bytes+=4;

          } else {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 3)) rand_value = temp_len - 4;
            u32 num = 1 + rand_below(afl, ARITH_MAX);

            *(u32 *)(out_buf + rand_value) =
                SWAP32(SWAP32(*(u32 *)(out_buf + rand_value)) - num);
                //num_mutated_bytes+=4;

          }

          break;

        case 9:

          /* Randomly add to dword, random endian. */

          if (temp_len < 4) { break; }

          if (rand_below(afl, 2)) {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 3)) rand_value = temp_len - 4;
            *(u32 *)(out_buf + rand_value) += 1 + rand_below(afl, ARITH_MAX);
            //num_mutated_bytes+=4;

          } else {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 3)) rand_value = temp_len - 4;
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

          rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
          out_buf[rand_value] ^= 1 + rand_below(afl, 255);
          //num_mutated_bytes++;
          break;
      }

    }

    common_fuzz_stuff(afl, out_buf, temp_len);

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
    if (unlikely(!out_buf)) { PFATAL("alloc"); }
    temp_len = len;
    memcpy(out_buf, orig_in, len);

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
  fprintf(afl->debug_file, "new path : %llu\n", new_hit_cnt);
  
  munmap(orig_in, afl->cmp_queue_cur->tc->len);

  return ;
}
