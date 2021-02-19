

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

  afl->num_change_cmp_limit = (u32) ((float) afl->num_cmp * CHANGED_CMPS_SIZE_RATIO);
  if (afl->num_change_cmp_limit < CHANGED_CMPS_SIZE_MIN) afl->num_change_cmp_limit = CHANGED_CMPS_SIZE_MIN;

  if (afl->num_cmp > CMP_FUNC_MAP_SIZE) {
    FATAL("# of cmp (%u) is bigger than CMP_FUNC_MAP_SIZE(%u)", afl->num_cmp, CMP_FUNC_MAP_SIZE);
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
  
  ck_free(afl->func_info_txt);

  afl->func_exec_count_table =
    (u32 **) calloc (sizeof(u32*), afl->num_func);
  if (!afl->func_exec_count_table) PFATAL("Can't alloc func_exec_count_table");

  afl->func_list = (u8 *) malloc (sizeof(u8) * afl->num_func);
  if (!afl->func_list) PFATAL("Can't alloc func_exec_exec");

  afl->cmp_queue_entries = (struct cmp_queue_entry *) calloc(afl->num_cmp, sizeof(struct cmp_queue_entry));
  if (afl->cmp_queue_entries == NULL) PFATAL("Can't alloc cmp_queue_entries");

  afl->tc_graph = (struct tc_graph_entry **) calloc(INIT_TC_GRAPH_SIZE, sizeof(struct tc_graph_entry *));
  if (afl->tc_graph == NULL) PFATAL("Can't alloc tc_graph");
  afl->tc_graph_size = INIT_TC_GRAPH_SIZE;

  snprintf(fn, PATH_MAX, "%s/FRIEND_debug.txt", afl->out_dir);
  s32 fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  afl->debug_file = fdopen(fd, "w");

  //fprintf(afl->debug_file, "target_cmp, mutating_tc, # of close tc, # of bytes, tc len, # rel func,\n");

  //fprintf(afl->debug_file, "change limit : %u\n",afl->num_change_cmp_limit);
}

void init_trim_and_func(afl_state_t * afl) {
  printf("init trimming starts\n");

  struct queue_entry * q = afl->queue;
  s32 fd, len;
  u8 * in_buf;
  u8 res;

  u64 cur_time = get_cur_time();

  u32 tc_idx = 0;

  while(q) {

    if (q->abandoned) {
      q = q->next;
      tc_idx++;
      continue;
    }

    fd = open(q->fname, O_RDONLY);
    if (unlikely(fd < 0)) PFATAL("Unable to open '%s'", q->fname);

    len = q->len;
    in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (unlikely(in_buf == MAP_FAILED)) PFATAL("Unable to mmap '%s' with len %d", q->fname, len);

    close(fd);

    res = trim_case(afl, q, in_buf);
    if (unlikely(res == FSRV_RUN_ERROR)) FATAL("Unable to execute target application");

    q->trim_done = 1;

    update_tc_graph(afl, tc_idx, (u32) -1, (u32) -1);

    q = q->next;
    tc_idx++;
   
    munmap(in_buf, len);
  }

  afl->mining_done_idx = tc_idx - 1;

  printf("init trimming done, took %llus", (get_cur_time() - cur_time) / 1000);

  return;
}

void get_byte_cmps_main(afl_state_t * afl) {

  s32 fd, len;
  u8 * in_buf;

  afl->mining_done_idx++;

  struct queue_entry * q = afl->queue_buf[afl->mining_done_idx];

  fd = open(q->fname, O_RDONLY);
  if (unlikely(fd < 0)) PFATAL("Unable to open '%s'", q->fname);

  len = q->len;
  in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (unlikely(in_buf == MAP_FAILED)) PFATAL("Unable to mmap '%s' with len %d", q->fname, len);

  close(fd);

  get_byte_cmps(afl, in_buf, len, afl->mining_done_idx);

  munmap(in_buf, len);
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

void update_tc_graph(afl_state_t * afl, u32 tc_idx, u32 parent_idx, u32 parent2_idx) {

  //fprintf(afl->debug_file, "****,updated index : %u, p1 : %u, p2: %u\n", tc_idx, parent_idx, parent2_idx);

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

  if (parent_idx == (u32) -1) return;

  new_tc->parents[0] = parent_idx;

  if (likely(parent_idx < tc_idx)) {
    struct tc_graph_entry * parent = afl->tc_graph[parent_idx];
    if (parent == NULL) {
      afl->tc_graph[parent_idx] = (struct tc_graph_entry *) calloc(1, sizeof(struct tc_graph_entry));
      parent = afl->tc_graph[parent_idx];
    }
    if (parent->children == NULL)
      parent->children = (u32 *) malloc (sizeof(u32) * TC_CHILDREN_MAX);
    parent->children[parent->num_children++] = tc_idx;
    if(unlikely(parent->num_children >= TC_CHILDREN_MAX)){
      parent->children_max_reached = 1;
      parent->num_children = 0;
    }
    new_tc->num_parents = 1;
  } else {
    //TODO : why?
  }
  
  if (parent2_idx != (u32) -1) {
    if (likely(parent2_idx < tc_idx)) {
      struct tc_graph_entry * parent = afl->tc_graph[parent2_idx];
      if (parent == NULL) {
        afl->tc_graph[parent2_idx] = (struct tc_graph_entry *) calloc(1, sizeof(struct tc_graph_entry));
        parent = afl->tc_graph[parent2_idx];
      }
      new_tc->parents[new_tc->num_parents++] = parent2_idx;
      if (parent->children == NULL)
        parent->children = (u32 *) malloc (sizeof(u32) * TC_CHILDREN_MAX);
      parent->children[parent->num_children++] = tc_idx;
      if(unlikely(parent->num_children >= TC_CHILDREN_MAX)){
        parent->children_max_reached = 1;
        parent->num_children = 0;
      }
    } else {
      //TODO : why?
    }
  }

  return;
}

void get_byte_cmps(afl_state_t *afl, u8 * out_buf, u32 len, u32 tc_idx) {

  u32 i1, i2, cmp_id;
  struct cmp_func_entry * entries = afl->shm.func_map->entries;

  for (i1 = 0; i1 < afl->num_cmp ; i1++) {
    entries[i1].condition = 0;
    entries[i1].precondition = 0;
    entries[i1].executed = 0;
  }

  struct tc_graph_entry * new_tc = afl->tc_graph[tc_idx];

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

  u8 precondition, postcondition;
  
  struct cmp_queue_entry * queue_entries = afl->cmp_queue_entries;
  struct cmp_queue_entry * cur_queue_entry ;

  memset(afl->func_list, 0, sizeof(u8) * afl->num_func);

  for (cmp_id = 0; cmp_id < afl->num_cmp; cmp_id++) {
    if (entries[cmp_id].executed) {
      afl->func_list[afl->cmp_func_map[cmp_id]] = 1;
      cur_queue_entry = &(queue_entries[cmp_id]);
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
          cur_queue_entry->num_executing_tcs = 0;
          cur_queue_entry->executing_tcs_size = EXEC_TCS_SIZE;
        }
        
        cur_queue_entry->executing_tcs[cur_queue_entry->num_executing_tcs++] = tc_idx;
        if (unlikely(cur_queue_entry-> num_executing_tcs >= cur_queue_entry->executing_tcs_size)) {
          cur_queue_entry->executing_tcs_size += EXEC_TCS_SIZE;
          cur_queue_entry->executing_tcs = (u32 *) realloc(
            cur_queue_entry->executing_tcs,
            sizeof(u32) * cur_queue_entry->executing_tcs_size);
        }

        if ((afl->queued_paths > CMP_CHECK_MAX_EXEC_TC_TRESHOLD) &&
            unlikely((((float) cur_queue_entry->num_executing_tcs) / ((float) afl->queued_paths)) 
              > CMP_MAX_EXEC_TC_TRESHOLD)) {
                cur_queue_entry->exec_max_reached = 1;
                free(cur_queue_entry->executing_tcs);
                cur_queue_entry->executing_tcs = NULL;
            }
      }
    }
  }

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
    }
  }

  u32 num_change_bytes = (u32) ((float) len * BYTE_CHANGE_RATIO);

  if (unlikely(num_change_bytes <= 0)) {
    return;
  } 

  u8 * out_buf2 = (u8 *) malloc(sizeof(u8) * len);
  memcpy(out_buf2, out_buf, len);

  new_tc->byte_cmp_sets_ptr = (struct byte_cmp_set **) malloc(sizeof(struct byte_cmp_set *) * NUM_BYTES_SETS);

  afl->cur_bytes = (u32 *) malloc(sizeof(u32) * (num_change_bytes + 10)); //buffer 10bytes
  //mutate and get new byte/cmps sets
  u32 r;

#define FLIP_BIT(_ar, _b)                   \
do {                                      \
                                          \
  u8 *_arf = (u8 *)(_ar);                 \
  u32 _bf = (_b);                         \
  _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                          \
} while (0)


  i1 = 0;
  u32 num_try = 0;
  while(i1 < NUM_BYTES_SETS) {

    if (num_try >= NUM_TRY_MAXIMUM) break;

    u32 use_stacking = 1 << (1 + rand_below(afl, HAVOC_STACK_POW2_FUNC));
    u32 rand_value;
    afl->cur_num_bytes = 0;

    for (i2 = 0; i2 < use_stacking; ++i2) {
      
      switch (r = rand_below(afl, 13)) {

        case 0:
        
          rand_value = rand_below(afl, len << 3);
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value >> 3;
          if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
            i2 = use_stacking;
          }
          FLIP_BIT(out_buf2, rand_value);
          break;

        case 1:

          rand_value = rand_below(afl, len);
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value;
          if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
            i2 = use_stacking;
          }
          out_buf2[rand_value] =
              interesting_8[rand_below(afl, sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value, randomly choosing endian. */

          if (len < 2) { break; }

          if (rand_below(afl, 2)) {
            rand_value = rand_below(afl, len - 1);
            *(u16 *)(out_buf2 + rand_value) =
                interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)];

          } else {
            rand_value = rand_below(afl, len - 1);
            *(u16 *)(out_buf2 + rand_value) = SWAP16(
                interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)]);

          }

          afl->cur_bytes[afl->cur_num_bytes++] = rand_value;
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value + 1;
          if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
            i2 = use_stacking;
          }

          break;

        case 3:

          /* Set dword to interesting value, randomly choosing endian. */

          if (len < 4) { break; }

          if (rand_below(afl, 2)) {

            rand_value = rand_below(afl, len - 3);
            *(u32 *)(out_buf2 + rand_value) =
                interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)];

          } else {
            
            rand_value = rand_below(afl, len - 3);
            *(u32 *)(out_buf2 + rand_value) = SWAP32(
                interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)]);

          }

          afl->cur_bytes[afl->cur_num_bytes++] = rand_value;
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value + 1;
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value + 2;
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value + 3;
          if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
            i2 = use_stacking;
          }

          break;

        case 4:

          /* Randomly subtract from byte. */

          rand_value = rand_below(afl, len);
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value;
          if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
            i2 = use_stacking;
          }
          out_buf2[rand_value] -= 1 + rand_below(afl, ARITH_MAX);
          break;

        case 5:

          /* Randomly add to byte. */

          rand_value = rand_below(afl, len);
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value;
          if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
            i2 = use_stacking;
          }
          out_buf2[rand_value] += 1 + rand_below(afl, ARITH_MAX);
          break;

        case 6:

          /* Randomly subtract from word, random endian. */

          if (len < 2) { break; }

          if (rand_below(afl, 2)) {

            rand_value = rand_below(afl, len - 1);
            *(u16 *)(out_buf2 + rand_value) -= 1 + rand_below(afl, ARITH_MAX);

          } else {

            rand_value = rand_below(afl, len - 1);
            u16 num = 1 + rand_below(afl, ARITH_MAX);

            *(u16 *)(out_buf2 + rand_value) =
                SWAP16(SWAP16(*(u16 *)(out_buf2 + rand_value)) - num);

          }

          afl->cur_bytes[afl->cur_num_bytes++] = rand_value;
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value + 1;
          if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
            i2 = use_stacking;
          }

          break;

        case 7:

          /* Randomly add to word, random endian. */

          if (len < 2) { break; }

          if (rand_below(afl, 2)) {

            rand_value = rand_below(afl, len - 1);

            *(u16 *)(out_buf2 + rand_value) += 1 + rand_below(afl, ARITH_MAX);

          } else {

            rand_value = rand_below(afl, len - 1);
            u16 num = 1 + rand_below(afl, ARITH_MAX);

            *(u16 *)(out_buf2 + rand_value) =
                SWAP16(SWAP16(*(u16 *)(out_buf2 + rand_value)) + num);

          }

          afl->cur_bytes[afl->cur_num_bytes++] = rand_value;
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value + 1;
          if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
            i2 = use_stacking;
          }

          break;

        case 8:

          /* Randomly subtract from dword, random endian. */

          if (len < 4) { break; }

          if (rand_below(afl, 2)) {

            rand_value = rand_below(afl, len - 3);

            *(u32 *)(out_buf2 + rand_value) -= 1 + rand_below(afl, ARITH_MAX);

          } else {

            rand_value = rand_below(afl, len - 3);
            u32 num = 1 + rand_below(afl, ARITH_MAX);

            *(u32 *)(out_buf2 + rand_value) =
                SWAP32(SWAP32(*(u32 *)(out_buf + rand_value)) - num);

          }

          afl->cur_bytes[afl->cur_num_bytes++] = rand_value;
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value + 1;
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value + 2;
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value + 3;
          if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
            i2 = use_stacking;
          }

          break;

        case 9:

          /* Randomly add to dword, random endian. */

          if (len < 4) { break; }

          if (rand_below(afl, 2)) {

            rand_value = rand_below(afl, len - 3);
            *(u32 *)(out_buf2 + rand_value) += 1 + rand_below(afl, ARITH_MAX);

          } else {

            rand_value = rand_below(afl, len - 3);
            u32 num = 1 + rand_below(afl, ARITH_MAX);

            *(u32 *)(out_buf2 + rand_value) =
                SWAP32(SWAP32(*(u32 *)(out_buf + rand_value)) + num);

          }

          afl->cur_bytes[afl->cur_num_bytes++] = rand_value;
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value + 1;
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value + 2;
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value + 3;
          if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
            i2 = use_stacking;
          }

          break;

        case 10:

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          rand_value = rand_below(afl, len);
          afl->cur_bytes[afl->cur_num_bytes++] = rand_value;
          if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
            i2 = use_stacking;
          }
          out_buf2[rand_value] ^= 1 + rand_below(afl, 255);
          break;

        case 11: {

          /* Overwrite bytes with a randomly selected chunk (75%) or fixed
             bytes (25%). */

          u32 copy_from, copy_to, copy_len;

          if (len < 2) { break; }

          copy_len = func_choose_block_len(afl, len - 1, len);

          copy_from = rand_below(afl, len - copy_len + 1);
          copy_to = rand_below(afl, len - copy_len + 1);

          u32 i3;
          for (i3 = 0; i3 < copy_len; i3++) {
            afl->cur_bytes[afl->cur_num_bytes++] = copy_to + i3;
            if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
              i2 = use_stacking;
              break;
            }
          }

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

        case 12:
          /* Overwrite bytes with an extra. */

          if (!afl->extras_cnt ||
              (afl->a_extras_cnt && rand_below(afl, 2))) {

            /* No user-specified extras or odds in our favor. Let's use an
                auto-detected one. */

            u32 use_extra = rand_below(afl, afl->a_extras_cnt);
            u32 extra_len = afl->a_extras[use_extra].len;
            u32 insert_at;

            if (extra_len > len) { break; }

            insert_at = rand_below(afl, len - extra_len + 1);
            
            u32 i3;
            for (i3 = 0; i3 < extra_len; i3++) {
              afl->cur_bytes[afl->cur_num_bytes++] = insert_at + i3;
              if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
                i2 = use_stacking;
                break;
              }
            }

            memcpy(out_buf2 + insert_at, afl->a_extras[use_extra].data,
                    extra_len);

          } else if (afl->extras_cnt) {

            /* No auto extras or odds in our favor. Use the dictionary. */

            u32 use_extra = rand_below(afl, afl->extras_cnt);
            u32 extra_len = afl->extras[use_extra].len;
            u32 insert_at;

            if (extra_len > len) { break; }

            
            insert_at = rand_below(afl, len - extra_len + 1);
            u32 i3;
            for (i3 = 0; i3 < extra_len; i3++) {
              afl->cur_bytes[afl->cur_num_bytes++] = insert_at + i3;
              if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
                i2 = use_stacking;
                break;
              }
            }

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
          while (tid == afl->current_entry);

          struct queue_entry *target = afl->queue_buf[tid];

          /* Make sure that the target has a reasonable length. */

          while (target && (target->len < 2 || target == afl->queue_cur))
            target = target->next;

          if (!target) break;

          /* Read the testcase into a new buffer. */

          s32 fd = open(target->fname, O_RDONLY);

          if (unlikely(fd < 0)) {

            PFATAL("Unable to open '%s'", target->fname);

          }

          u32 new_len = target->len;
          u8 *new_buf = afl_realloc(AFL_BUF_PARAM(in_scratch), new_len);
          if (unlikely(!new_buf)) { PFATAL("alloc"); }

          ck_read(fd, new_buf, new_len, target->fname);

          close(fd);

          u32 copy_from, copy_to, copy_len;

          copy_len = func_choose_block_len(afl, new_len - 1, len );
          if (copy_len > len) copy_len = len;

          copy_from = rand_below(afl, new_len - copy_len + 1);
          copy_to = rand_below(afl, len - copy_len + 1);

          u32 i3;
          for (i3 = 0; i3 < copy_len; i3++) {
            afl->cur_bytes[afl->cur_num_bytes++] = copy_to + i3;
            if (unlikely(afl->cur_num_bytes >= num_change_bytes)) {
              i2 = use_stacking;
              break;
            }
          }

          memmove(out_buf2 + copy_to, new_buf + copy_from, copy_len);

          break;
      } // end of switch
    } // end of for (i2 = 0; i2 < use_stacking ; i2++)

    //get byte cmps set

    func_common_fuzz_stuff(afl, out_buf2, len, tc_idx);

    //execute
    for (i2 = 0; i2 < afl->num_cmp; i2++) {
      afl->shm.func_map->entries[i2].executed = 0;
      afl->shm.func_map->entries[i2].condition = 0;
    }

    fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout);

    if (fault == FSRV_RUN_TMOUT) {
      memcpy(out_buf2, out_buf, len);
      continue;
    }

    u32 num_changed_cmps = 0;
    u32 is_max = 0;

    new_tc->byte_cmp_sets_ptr[i1] = (struct byte_cmp_set *) malloc(sizeof(struct byte_cmp_set));

    new_tc->byte_cmp_sets_ptr[i1]->changed_cmps = (u32 *) malloc (sizeof(u32) * afl->num_change_cmp_limit);

    for (cmp_id = 0; cmp_id < afl->num_cmp; cmp_id ++) {
      if(entries[cmp_id].executed) {
        precondition = entries[cmp_id].precondition;
        postcondition = entries[cmp_id].condition;

        if(precondition && (precondition != postcondition)) {
          cur_queue_entry = &(queue_entries[cmp_id]);

          new_tc->byte_cmp_sets_ptr[i1]->changed_cmps[num_changed_cmps++] = cmp_id;
          if (unlikely(num_changed_cmps >= afl->num_change_cmp_limit)) {
            is_max = 1;
            break;
          }
        }
      }
    }

    if (is_max || num_changed_cmps == 0) {
      //changed too many cmps instrs!
      free(new_tc->byte_cmp_sets_ptr[i1]->changed_cmps);
      free(new_tc->byte_cmp_sets_ptr[i1]);
      memcpy(out_buf2, out_buf, len);
      num_try ++;
      continue;
    }

    new_tc->byte_cmp_sets_ptr[i1]->num_changed_cmps = num_changed_cmps;
    new_tc->byte_cmp_sets_ptr[i1]->changed_cmps = (u32 *) realloc(
      new_tc->byte_cmp_sets_ptr[i1]->changed_cmps, sizeof(u32) * num_changed_cmps);
    //assert(num_changed_cmps < CHANGED_CMPS_SIZE);

    u32 num_changed_bytes = afl->cur_num_bytes;
    new_tc->byte_cmp_sets_ptr[i1]->num_changed_bytes = num_changed_bytes;
    new_tc->byte_cmp_sets_ptr[i1]->changed_bytes = (u32 *) malloc (sizeof(u32) * num_changed_bytes);
    memcpy(new_tc->byte_cmp_sets_ptr[i1]->changed_bytes, afl->cur_bytes, sizeof(u32) * num_changed_bytes);

    //fprintf(afl->debug_file,"**,mutated %u, changed %u cmps\n",num_changed_bytes, num_changed_cmps);
    
    memcpy(out_buf2, out_buf, len);
    i1++;
  }

  //fprintf(afl->debug_file, "*,num_try : %d, num_byte_cmp_sets : %u\n",num_try, i1);

  new_tc->num_byte_cmp_sets = i1;

  if (i1 == 0) {
    free(new_tc->byte_cmp_sets_ptr);
    new_tc->byte_cmp_sets_ptr = NULL;
    new_tc->initialized = 0;
  } else {
    new_tc->initialized = 1;
    if (i1 < NUM_BYTES_SETS) {
      new_tc->byte_cmp_sets_ptr = (struct byte_cmp_set **) realloc(
        new_tc->byte_cmp_sets_ptr,
        sizeof(struct byte_cmp_set *) * i1);
    }
  }

  free(out_buf2);
  free(afl->cur_bytes);

  return;
}

void get_close_tcs(afl_state_t * afl, u32 target_id, u32 * close_tcs, u32 * num_close_tc, u8 degree) {

  u32 i,j;
  u8 temp;

  if (unlikely(*num_close_tc >= CLOSE_TCS_SIZE)) return;
  if (unlikely(target_id >= afl->tc_graph_size)) return;

  struct tc_graph_entry * cur_entry = afl->tc_graph[target_id];

  if (unlikely(!cur_entry->initialized)) return;
  
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

  if (degree == 1) {
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

    u32 num_children = cur_entry->num_children;
    if (cur_entry->children_max_reached) num_children = TC_CHILDREN_MAX;

    if (unlikely(cur_entry->children == NULL)) num_children = 0;

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
      get_close_tcs(afl, cur_entry->parents[i], close_tcs, num_close_tc, degree - 1);
  }
  
  u32 num_children = cur_entry->num_children;
  if (cur_entry->children_max_reached) num_children = TC_CHILDREN_MAX;

  if (unlikely(cur_entry->children == NULL)) num_children = 0;

  for (i = 0; i < num_children; i ++) {
      get_close_tcs(afl, cur_entry->children[i], close_tcs, num_close_tc, degree - 1);
  }

  return;
}

void write_func_stats (afl_state_t * afl) {
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
      fprintf(f, "%ld,%u,%u,%u,%u,%u,%u\n",
        q - afl->cmp_queue_entries, q->condition, q->num_executing_tcs, q->mutating_tc_idx, q->exec_max_reached, q->num_fuzzed, q->num_skipped);

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
      fprintf(f, "tc_idx:%u,num_children:%u\n", idx1, e->num_children);
      for (idx2 = 0; idx2 < e->num_byte_cmp_sets ; idx2++) {
        fprintf(f, "byte_cmp_set_entry_idx:%u\n",idx2);
        if(e->byte_cmp_sets_ptr != NULL) {
          fprintf(f, "num_changed_cmps:%u,num_changed_bytes:%u\n",
            e->byte_cmp_sets_ptr[idx2]->num_changed_cmps, e->byte_cmp_sets_ptr[idx2]->num_changed_bytes);
          if (e->byte_cmp_sets_ptr[idx2]->changed_cmps) {
            for(idx3 = 0; idx3 < e->byte_cmp_sets_ptr[idx2]->num_changed_cmps; idx3++) {
              fprintf(f, "%u,",e->byte_cmp_sets_ptr[idx2]->changed_cmps[idx3]);
            }
            fprintf(f, "\n");
          }
          if (e->byte_cmp_sets_ptr[idx2]->changed_bytes) {
            for(idx3 = 0; idx3 < e->byte_cmp_sets_ptr[idx2]->num_changed_bytes; idx3++) {
              fprintf(f, "%u,",e->byte_cmp_sets_ptr[idx2]->changed_bytes[idx3]);
            }
            fprintf(f, "\n");
          }
        }
      }
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
          u_stringify_int(IB(3), afl->stage_cycles[STAGE_MINIG]),
          u_stringify_int(IB(4), afl->stage_cycles[STAGE_MINIG]));

    fclose(f);
  }

  return;
}


void destroy_func(afl_state_t * afl) {
  u32 idx1, idx2;

  if (afl->debug_file)
    fclose(afl->debug_file);

  for (idx1 = 0; idx1 < afl->num_cmp; idx1++) {
    if (afl->cmp_queue_entries[idx1].executing_tcs != NULL)
      free(afl->cmp_queue_entries[idx1].executing_tcs);
  }
  free(afl->cmp_queue_entries);

  for (idx1 = 0; idx1 < afl->tc_graph_size ; idx1++ ) {
    if (afl->tc_graph[idx1]) {
      if (afl->tc_graph[idx1]->byte_cmp_sets_ptr) {
        for (idx2 = 0; idx2 < afl->tc_graph[idx1]->num_byte_cmp_sets; idx2++) {
          if (afl->tc_graph[idx1]->byte_cmp_sets_ptr[idx2]->changed_cmps)
            free(afl->tc_graph[idx1]->byte_cmp_sets_ptr[idx2]->changed_cmps);
          if (afl->tc_graph[idx1]->byte_cmp_sets_ptr[idx2]->changed_bytes)
            free(afl->tc_graph[idx1]->byte_cmp_sets_ptr[idx2]->changed_bytes);
          free(afl->tc_graph[idx1]->byte_cmp_sets_ptr[idx2]);
        }
        free(afl->tc_graph[idx1]->byte_cmp_sets_ptr);
      }
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

  u32 r_max, r;

  if (unlikely(afl->expand_havoc)) {

    /* add expensive havoc cases here, they are activated after a full
       cycle without finds happened */

    r_max = 16 + ((afl->extras_cnt + afl->a_extras_cnt) ? 2 : 0);

  } else {

    r_max = 15 + ((afl->extras_cnt + afl->a_extras_cnt) ? 2 : 0);

  }

  u32 target_cmp_id = afl->cmp_queue_cur - afl->cmp_queue_entries;
  //get related funcs
  memset(afl->func_list, 0, sizeof(u8) * afl->num_func);
  u32 target_func = afl->cmp_func_map[target_cmp_id];
  u32 target_func_exec = afl->func_exec_count_table[target_func][target_func];
  u32 num_rel_funcs = 0;
  u32 num_exec_funcs = 0;
  for (i = 0; i < afl->num_func; i++) {
    if (((float) afl->func_exec_count_table[target_func][i] / target_func_exec)
         >= REL_FUNC_THRESHOLD ) {
      afl->func_list[i] = 1; 
      num_rel_funcs++;
    }
    if (afl->func_exec_count_table[i]) num_exec_funcs ++;
  }

  u32 * close_tcs = (u32 *) malloc(sizeof(u32) * CLOSE_TCS_SIZE);
  memset(close_tcs, 255, sizeof(u32) * CLOSE_TCS_SIZE);
  u32 num_close_tc = 0;

  get_close_tcs(afl, afl->cmp_queue_cur->tc->id, close_tcs, &num_close_tc, CLOSE_TC_THRESHOLD);

  u32 num_mut_bytes = (u32) ((float) len * FUZZ_ONE_FUNC_BYTE_SIZE_RATIO);

  afl->fuzz_one_func_byte_offsets = (u32 *) malloc(sizeof(u32) * num_mut_bytes);

  // Select bytes
  afl->func_cur_num_bytes = 0;

  //debug
  //u32 * selected_set_idx  = (u32 *) malloc (sizeof(u32) * num_close_tc);
  //u32 * selected_set_rel  = (u32 *) malloc (sizeof(u32) * num_close_tc);
  //u32 * selected_set_size  = (u32 *) malloc (sizeof(u32) * num_close_tc);

  for (i = 0; i < num_close_tc; i++) {  
    u32 tc_id = close_tcs[i];
    //TODO: why?
    if (unlikely(tc_id >= afl->tc_graph_size)) continue;
    struct tc_graph_entry * cur_tc = afl->tc_graph[tc_id];
    u32 contains_rel_cmp = 0;

    if (unlikely(!cur_tc->initialized)) continue;
    if (cur_tc->byte_cmp_sets_ptr == NULL) continue;

    u32 num_changed_cmps;
    u32 num_changed_cmp_max = 0;
    u32 max_idx = (u32) -1;

    for (j = 0 ; j < cur_tc->num_byte_cmp_sets; j++) {
      num_changed_cmps = cur_tc->byte_cmp_sets_ptr[j]->num_changed_cmps;
      contains_rel_cmp = 0;

      if (cur_tc->byte_cmp_sets_ptr[j]->changed_cmps == NULL) continue;

      for (k = 0; k < num_changed_cmps; k++) {
        if (afl->func_list[afl->cmp_func_map[cur_tc->byte_cmp_sets_ptr[j]->changed_cmps[k]]]) {
          contains_rel_cmp++;
        }
      }

      if (contains_rel_cmp) {
        if (num_changed_cmp_max < contains_rel_cmp) {
          num_changed_cmp_max = contains_rel_cmp;
          max_idx = j;
        }
      }
    }

    if (max_idx == (u32) -1) continue;
    //selected_set_idx[i] = max_idx;
    //selected_set_rel[i] = num_changed_cmp_max;
    //selected_set_size[i] = cur_tc->byte_cmp_sets[max_idx].num_changed_cmps;

    if (unlikely(!cur_tc->byte_cmp_sets_ptr[max_idx]->changed_bytes)) continue;

    k = 0;
    while (k < cur_tc->byte_cmp_sets_ptr[max_idx]->num_changed_bytes) {
      if (cur_tc->byte_cmp_sets_ptr[max_idx]->changed_bytes[k] < temp_len) {
        afl->fuzz_one_func_byte_offsets[afl->func_cur_num_bytes++]
          = cur_tc->byte_cmp_sets_ptr[max_idx]->changed_bytes[k];
        if(unlikely(afl->func_cur_num_bytes >= num_mut_bytes)) {
          break;
        }
      }
      k++;
    }

    if(afl->func_cur_num_bytes >= num_mut_bytes) {
      break;
    }
  }
  free(close_tcs);

  //fprintf(afl->debug_file, "*,%u,%u,%u,%u,%u,%u/%u\n", 
  //  target_cmp_id, afl->cmp_queue_cur->tc->id, num_close_tc,  afl->func_cur_num_bytes, len, num_rel_funcs, num_exec_funcs);

  //for (i = 0; i < num_close_tc; i++) {
  //  fprintf(afl->debug_file, "%u:%u/%u,", selected_set_idx[i], selected_set_rel[i], selected_set_size[i]);
  //}
  //fprintf(afl->debug_file, "\n");
  //free(selected_set_idx);
  //free(selected_set_rel);
  //free(selected_set_size);

  //fprintf(afl->debug_file, "***,mutating %u/%u\n", afl->func_cur_num_bytes, num_mut_bytes);

  if (afl->func_cur_num_bytes == 0) {
    munmap(orig_in, len);
    free(afl->fuzz_one_func_byte_offsets);
    return;
  }
  
  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    u32 use_stacking = 1 << (1 + rand_below(afl, HAVOC_STACK_POW2));
    u32 rand_value;
    afl->stage_cur_val = use_stacking;

    if (afl->func_cur_num_bytes == 0) break;

    for (i = 0; i < use_stacking; ++i) {

      switch (r = rand_below(afl, r_max)) {

        case 0:

          /* Flip a single bit somewhere. Spooky! */
          
          rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
          rand_value = (rand_value << 3) + rand_below(afl, 8);
          FLIP_BIT(out_buf, rand_value);
          break;

        case 1:

          /* Set byte to interesting value. */
          rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
          out_buf[rand_value] =
              interesting_8[rand_below(afl, sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value, randomly choosing endian. */

          if (temp_len < 2) { break; }

          if (rand_below(afl, 2)) {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 1)) rand_value -= 1;
            *(u16 *)(out_buf + rand_value) =
                interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)];

          } else {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 1)) rand_value -= 1;
            *(u16 *)(out_buf + rand_value) = SWAP16(
                interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)]);

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

          } else {
            
            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 3)) rand_value = temp_len - 4;
            *(u32 *)(out_buf + rand_value) = SWAP32(
                interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)]);

          }

          break;

        case 4:

          /* Randomly subtract from byte. */

          rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
          out_buf[rand_value] -= 1 + rand_below(afl, ARITH_MAX);
          break;

        case 5:

          /* Randomly add to byte. */

          rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
          out_buf[rand_value] += 1 + rand_below(afl, ARITH_MAX);
          break;

        case 6:

          /* Randomly subtract from word, random endian. */

          if (temp_len < 2) { break; }

          if (rand_below(afl, 2)) {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 1)) rand_value -= 1;
            *(u16 *)(out_buf + rand_value) -= 1 + rand_below(afl, ARITH_MAX);

          } else {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 1)) rand_value -= 1;
            u16 num = 1 + rand_below(afl, ARITH_MAX);

            *(u16 *)(out_buf + rand_value) =
                SWAP16(SWAP16(*(u16 *)(out_buf + rand_value)) - num);

          }

          break;

        case 7:

          /* Randomly add to word, random endian. */

          if (temp_len < 2) { break; }

          if (rand_below(afl, 2)) {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 1)) rand_value -= 1;

            *(u16 *)(out_buf + rand_value) += 1 + rand_below(afl, ARITH_MAX);

          } else {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 1)) rand_value -= 1;
            u16 num = 1 + rand_below(afl, ARITH_MAX);

            *(u16 *)(out_buf + rand_value) =
                SWAP16(SWAP16(*(u16 *)(out_buf + rand_value)) + num);

          }

          break;

        case 8:

          /* Randomly subtract from dword, random endian. */

          if (temp_len < 4) { break; }

          if (rand_below(afl, 2)) {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 3)) rand_value = temp_len - 4;

            *(u32 *)(out_buf + rand_value) -= 1 + rand_below(afl, ARITH_MAX);

          } else {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 3)) rand_value = temp_len - 4;
            u32 num = 1 + rand_below(afl, ARITH_MAX);

            *(u32 *)(out_buf + rand_value) =
                SWAP32(SWAP32(*(u32 *)(out_buf + rand_value)) - num);

          }

          break;

        case 9:

          /* Randomly add to dword, random endian. */

          if (temp_len < 4) { break; }

          if (rand_below(afl, 2)) {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 3)) rand_value = temp_len - 4;
            *(u32 *)(out_buf + rand_value) += 1 + rand_below(afl, ARITH_MAX);

          } else {

            rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
            if(unlikely(rand_value >= temp_len - 3)) rand_value = temp_len - 4;
            u32 num = 1 + rand_below(afl, ARITH_MAX);

            *(u32 *)(out_buf + rand_value) =
                SWAP32(SWAP32(*(u32 *)(out_buf + rand_value)) + num);

          }

          break;

        case 10:

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          rand_value = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
          out_buf[rand_value] ^= 1 + rand_below(afl, 255);
          break;

        case 11 ... 12: {

          /* Delete bytes. We're making this a bit more likely
             than insertion (the next option) in hopes of keeping
             files reasonably small. */

          u32 del_from, del_len;

          if (temp_len < 2) { break; }

          /* Don't delete too much. */

          del_len = func_choose_block_len(afl, temp_len - 1, len);

          del_from = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
          if(del_from > (temp_len - del_len)) continue;

          memmove(out_buf + del_from, out_buf + del_from + del_len,
                  temp_len - del_from - del_len);

          temp_len -= del_len;

          for (i = 0; i < afl->func_cur_num_bytes; i++) {
            if (afl->fuzz_one_func_byte_offsets[i] >= temp_len) {
              afl->fuzz_one_func_byte_offsets[i] = afl->fuzz_one_func_byte_offsets[--(afl->func_cur_num_bytes)];
              i--;
            }
          }

          break;

        }

        case 13:

          /* Clone bytes (75%) or insert a block of constant bytes (25%). */

          {
            u8  actually_clone = rand_below(afl, 4);
            u32 clone_from, clone_to, clone_len;
            u8 *new_buf;

            if (likely(actually_clone)) {

              clone_len = func_choose_block_len(afl, temp_len, len);
              clone_from = rand_below(afl, temp_len - clone_len + 1);

            } else {

              clone_len = func_choose_block_len(afl, (u32) (len * FUNC_HAVOC_BLK_XL_RATIO), len);
              clone_from = 0;

              if (clone_len + temp_len >= MAX_FILE) {
                break;
              }

            }

            clone_to = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl->func_cur_num_bytes)];
            if (clone_to > temp_len) clone_to = temp_len;

            new_buf =
                afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len);
            if (unlikely(!new_buf)) { PFATAL("alloc"); }

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            if (likely(actually_clone)) {

              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);

            } else {

              memset(new_buf + clone_to,
                      rand_below(afl, 2) ? rand_below(afl, 256)
                                        : out_buf[rand_below(afl, temp_len)],
                      clone_len);

            }

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                    temp_len - clone_to);

            afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
            out_buf = new_buf;
            new_buf = NULL;
            temp_len += clone_len;

            break;
          }

        case 14: {

          /* Overwrite bytes with a randomly selected chunk (75%) or fixed
             bytes (25%). */

          // TODO : which bytes to record?

          u32 copy_from, copy_to, copy_len;

          if (temp_len < 2) { break; }

          copy_len = func_choose_block_len(afl, temp_len - 1, len);

          copy_from = rand_below(afl, temp_len - copy_len + 1);
          copy_to = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
          if(copy_to >= (temp_len - copy_len + 1)) copy_to = temp_len - copy_len;

          if (likely(rand_below(afl, 4))) {

            if (copy_from != copy_to) {

              memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

            }

          } else {

            memset(out_buf + copy_to,
                   rand_below(afl, 2) ? rand_below(afl, 256)
                                      : out_buf[rand_below(afl, temp_len)],
                   copy_len);

          }

          break;

        }

        default:

          if (likely(r <= 16 && (afl->extras_cnt || afl->a_extras_cnt))) {

            /* Values 15 and 16 can be selected only if there are any extras
               present in the dictionaries. */

            if (r == 15) {

              /* Overwrite bytes with an extra. */

              if (!afl->extras_cnt ||
                  (afl->a_extras_cnt && rand_below(afl, 2))) {

                /* No user-specified extras or odds in our favor. Let's use an
                   auto-detected one. */

                u32 use_extra = rand_below(afl, afl->a_extras_cnt);
                u32 extra_len = afl->a_extras[use_extra].len;
                u32 insert_at;

                if (extra_len > temp_len) { break; }

                insert_at = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
                if(insert_at >= (temp_len - extra_len + 1)) insert_at = temp_len - extra_len;

                memcpy(out_buf + insert_at, afl->a_extras[use_extra].data,
                       extra_len);

              } else {

                /* No auto extras or odds in our favor. Use the dictionary. */

                u32 use_extra = rand_below(afl, afl->extras_cnt);
                u32 extra_len = afl->extras[use_extra].len;
                u32 insert_at;

                if (extra_len > temp_len) { break; }

                insert_at = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
                if(insert_at >= (temp_len - extra_len + 1)) insert_at = temp_len - extra_len;

                memcpy(out_buf + insert_at, afl->extras[use_extra].data,
                       extra_len);

              }

              break;

            } else {  // case 16

              u32 use_extra, extra_len,
                  insert_at;
              u8 *ptr;

              insert_at = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];

              /* Insert an extra. Do the same dice-rolling stuff as for the
                 previous case. */

              if (!afl->extras_cnt ||
                  (afl->a_extras_cnt && rand_below(afl, 2))) {

                use_extra = rand_below(afl, afl->a_extras_cnt);
                extra_len = afl->a_extras[use_extra].len;
                ptr = afl->a_extras[use_extra].data;

              } else {

                use_extra = rand_below(afl, afl->extras_cnt);
                extra_len = afl->extras[use_extra].len;
                ptr = afl->extras[use_extra].data;

              }

              if (temp_len + extra_len >= MAX_FILE) { break; }

              if (unlikely(insert_at >= temp_len)) insert_at = temp_len;

              out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len + extra_len);
              if (unlikely(!out_buf)) { PFATAL("alloc"); }

              /* Tail */
              memmove(out_buf + insert_at + extra_len, out_buf + insert_at,
                      temp_len - insert_at);

              /* Inserted part */
              memcpy(out_buf + insert_at, ptr, extra_len);

              temp_len += extra_len;

              break;

            }

          } else {

            /*
                        switch (r) {

                          case 15:  // fall through
                          case 16:
                          case 17: {*/

            /* Overwrite bytes with a randomly selected chunk from another
               testcase or insert that chunk. */

            if (afl->queued_paths < 4) break;

            /* Pick a random queue entry and seek to it. */

            u32 tid;
            do
              tid = rand_below(afl, afl->queued_paths);
            while (tid == afl->current_entry);

            struct queue_entry *target = afl->queue_buf[tid];

            /* Make sure that the target has a reasonable length. */

            while (target && (target->len < 2 || target == afl->cmp_queue_cur->tc))
              target = target->next;

            if (!target) break;

            /* Read the testcase into a new buffer. */

            fd = open(target->fname, O_RDONLY);

            if (unlikely(fd < 0)) {

              PFATAL("Unable to open '%s'", target->fname);

            }

            u32 new_len = target->len;
            u8 *new_buf = afl_realloc(AFL_BUF_PARAM(in_scratch), new_len);
            if (unlikely(!new_buf)) { PFATAL("alloc"); }

            ck_read(fd, new_buf, new_len, target->fname);

            close(fd);

            u8 overwrite = 0;
            if (temp_len >= 2 && rand_below(afl, 2))
              overwrite = 1;
            else if (temp_len + len * FUNC_HAVOC_BLK_XL_RATIO >= MAX_FILE) {

              if (temp_len >= 2)
                overwrite = 1;
              else
                break;

            }

            if (overwrite) {

              u32 copy_from, copy_to, copy_len;

              copy_len = func_choose_block_len(afl, new_len - 1, len);
              if (copy_len > temp_len) copy_len = temp_len;

              copy_from = rand_below(afl, new_len - copy_len + 1);
              copy_to = rand_below(afl, temp_len - copy_len + 1);

              copy_to = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
              if(copy_to >= (temp_len - copy_len + 1)) copy_to = temp_len - copy_len;

              memmove(out_buf + copy_to, new_buf + copy_from, copy_len);

            } else {

              u32 clone_from, clone_to, clone_len;

              clone_len = func_choose_block_len(afl, new_len, len);
              clone_from = rand_below(afl, new_len - clone_len + 1);

              clone_to = afl->fuzz_one_func_byte_offsets[rand_below(afl, afl-> func_cur_num_bytes)];
              if(clone_to > temp_len) clone_to = temp_len;

              u8 *temp_buf =
                  afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len);
              if (unlikely(!temp_buf)) { PFATAL("alloc"); }

              /* Head */

              memcpy(temp_buf, out_buf, clone_to);
              
              /* Inserted part */

              memcpy(temp_buf + clone_to, new_buf + clone_from, clone_len);

              /* Tail */
              memcpy(temp_buf + clone_to + clone_len, out_buf + clone_to,
                     temp_len - clone_to);

              afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
              out_buf = temp_buf;
              temp_len += clone_len;

            }

            break;

          }

          // end of default:

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

  //if (new_hit_cnt) {
  //  fprintf(afl->debug_file,"***,new path : %llu\n", new_hit_cnt);
  //}
  
  munmap(orig_in, afl->cmp_queue_cur->tc->len);
  free(afl->fuzz_one_func_byte_offsets);

  return ;
}
