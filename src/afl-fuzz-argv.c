#include "afl-fuzz.h"
#include "funclog.h"

void init_argv(afl_state_t * afl) {
  u8    fn[PATH_MAX];
  FILE * f;
  u32 idx1;

  afl->argvs_hash = (struct argv_entry **) calloc(1024 , sizeof(struct argv_entry *));
  afl->argvs_buf = (struct argv_entry **) calloc(1024 , sizeof(struct argv_entry *));
  afl->argvs_buf_size = 1024;

  afl->argv_words = (struct argv_word_entry **) calloc(1024, sizeof(struct argv_word_entry*));

  afl->argv_words_bufs[0] = (struct argv_word_entry **) calloc(1024 , sizeof(struct argv_word_entry *));
  afl->argv_words_bufs[1] = (struct argv_word_entry **) calloc(1024 , sizeof(struct argv_word_entry *));
  afl->argv_words_bufs[2] = (struct argv_word_entry **) calloc(1024 , sizeof(struct argv_word_entry *));
  afl->argv_words_bufs[3] = (struct argv_word_entry **) calloc(1024 , sizeof(struct argv_word_entry *));
  afl->argv_words_buf_size[0] = 1024;
  afl->argv_words_buf_size[1] = 1024;
  afl->argv_words_buf_size[2] = 1024;
  afl->argv_words_buf_size[3] = 1024;

  afl->tmp_words = (struct argv_word_entry **) malloc(TMP_WORD_SIZE * sizeof(struct argv_word_entry *));

  if(afl->argv_mut) {
    snprintf(fn, PATH_MAX, "%s/keywords.txt", afl->func_infos_dir);
    f = fopen(fn, "r");
    if (f == NULL) PFATAL("Can't open keywords file");
    
    u8 buffer[KEYWORD_MAX];
    memset(buffer, 0, KEYWORD_MAX);
    int res;
    while((res = fscanf(f, "%s\n", buffer)) != EOF) {
      size_t len = strlen(buffer);
      s8 * tmp = (s8 *) malloc(sizeof(s8) * (len + 1));
      memcpy(tmp, buffer, len);
      tmp[len] = 0;

      u32 hash = 0;
      bool has_minus = false;
      bool has_equal_middle = false;
      bool has_equal_last = buffer[len - 1] == '=';

      for (idx1 = 0; idx1 < len; idx1++) {
        s8 tmp_char = buffer[idx1];
        hash = hash + (tmp_char << idx1);
        has_minus |= (tmp_char == '-');
        has_equal_middle |= (tmp_char == '=');
      }
      hash = hash % 1024;

      struct argv_word_entry * tmp_entry = (struct argv_word_entry *) calloc(1, sizeof (struct argv_word_entry));
      
      if (afl->argv_words[hash] == NULL) {
        afl->argv_words[hash] = tmp_entry;
      } else {
        struct argv_word_entry * ptr = afl->argv_words[hash];
        while (ptr->next != NULL) {
          ptr = ptr->next;
        }
        ptr->next = tmp_entry;
      }
      u32 buf_index = 1;
      if (has_minus && has_equal_last) {
        buf_index = 3;
      } else if (has_minus && has_equal_middle) {
        buf_index = 2;
      } else if (has_minus) {
        buf_index = 0;
      }

      afl->argv_words_bufs[buf_index][afl->num_argv_word_buf_words[buf_index]++] = tmp_entry;
      afl->num_argv_words ++;

      if (unlikely(afl->num_argv_word_buf_words[buf_index] >= afl->argv_words_buf_size[buf_index])) {
        afl->argv_words_buf_size[buf_index] *= 2;
        afl->argv_words_bufs[buf_index] = realloc (afl->argv_words_bufs[buf_index], sizeof(struct argv_word_entry *) * afl->argv_words_buf_size[0]);
      }

      tmp_entry->word = tmp;
      memset(buffer, 0, len);
    }

    fclose(f);
  }
}

void destroy_argv(afl_state_t * afl) {
  u32 idx1, idx2;
  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    free(afl->argvs_buf[idx1]->args);
    free(afl->argvs_buf[idx1]);
  }

  free(afl->argvs_buf);

  for (idx1 = 0; idx1 < 4; idx1++) {
    for (idx2 = 0; idx2 < afl->num_argv_word_buf_words[idx1] ; idx2++) {
      free(afl->argv_words_bufs[idx1][idx2]->word);
      free(afl->argv_words_bufs[idx1][idx2]);
    }
    free(afl->argv_words_bufs[idx1]);
  }

  free(afl->tmp_words);
  free(afl->argv_words);
  free(afl->argvs_hash);
}

void fuzz_one_argv(afl_state_t * afl) {
  u32 len;
  u32 idx1, idx2;
  u8 *orig_in;
  u64 orig_hit_cnt, new_hit_cnt;

  struct queue_entry * cur_tc = afl->queue_cur;

  len = (u32) cur_tc->len;

  orig_in = queue_testcase_get(afl, cur_tc);

  struct argv_word_entry ** orig_args = afl->argvs_buf[cur_tc->argv_idx]->args;

  //recored coverage
  write_to_testcase(afl, orig_in, len, cur_tc->argv_idx);

  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_name = "argv";
  afl->stage_short = "argv";
  afl->stage_max = HAVOC_CYCLES * cur_tc->perf_score / afl->havoc_div / 200;

  u32 num_args = 0;

  struct argv_word_entry * prev = NULL;
  struct argv_word_entry * head = orig_args[0];
  struct argv_word_entry ** tmps = afl->tmp_words;
  struct argv_word_entry * ptr = head;
  
  while (orig_args[num_args]) {
    orig_args[num_args]->tmp_prev = prev;
    if (prev != NULL) {
      prev->tmp_next = orig_args[num_args];
    }
    prev = orig_args[num_args];
    num_args++;
  }

  afl->num_tmp_words = 0;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {
    
    u32 use_stacking1 = 1 << (1 + rand_below(afl, HAVOC_STACK_POW2_FUNC));
    afl->stage_cur_val = use_stacking1;

    struct argv_word_entry * rand_word;
    struct argv_word_entry * ptr;
    u32 rand_idx;

    u32 method = 0;
    u32 method2 = (u32) -1;

    for (idx1 = 0; idx1 < use_stacking1; idx1++) {
      switch ((method = rand_below(afl, 6))) {
        case 0 ... 1 :  //<-word>
          if (unlikely(afl->num_argv_word_buf_words[0] == 0)) break;

          rand_word = afl->argv_words_bufs[0][rand_below(afl,afl->num_argv_word_buf_words[0])];
          if (rand_word->tmp_next != NULL || rand_word->tmp_prev != NULL) break;

          rand_idx = rand_below(afl, num_args);

          if ((method2 = rand_below(afl, 3))) {
            //add <-word>
            if (rand_idx != 0) {
              ptr = head;
              for (idx2 = 0; idx2 < rand_idx ; idx2++) {
                ptr = ptr->tmp_next;
              }
              ptr->tmp_prev->tmp_next = rand_word;
              rand_word->tmp_next = ptr;
              rand_word->tmp_prev = ptr->tmp_prev;
              ptr->tmp_prev = rand_word;
            } else {
              head->tmp_prev = rand_word;
              rand_word->tmp_next = head;
              head = rand_word;
            }

            num_args ++;

          } else {
            //replace with <-word>
            if (rand_idx != 0) {
              ptr = head;
              for (idx2 = 0; idx2 < rand_idx ; idx2++) {
                ptr = ptr->tmp_next;
              }
              ptr->tmp_prev->tmp_next = rand_word;
              rand_word->tmp_prev = ptr->tmp_prev;
              rand_word->tmp_next = ptr->tmp_next;
              if (ptr->tmp_next) {
                ptr->tmp_next->tmp_prev = rand_word;
              }
              ptr->tmp_prev = NULL;
              ptr->tmp_next = NULL;
            } else {
              rand_word->tmp_next = head->tmp_next;
              if (rand_word->tmp_next) {
                rand_word->tmp_next->tmp_prev = rand_word;
              }
              head->tmp_next = NULL;
              head = rand_word;
            }
          }
          break;

        case 2 ... 3 : // <word>
          if (unlikely(afl->num_argv_word_buf_words[1] == 0)) break;

          rand_word = afl->argv_words_bufs[1][rand_below(afl,afl->num_argv_word_buf_words[1])];
          if (rand_word->tmp_next != NULL || rand_word->tmp_prev != NULL) break;

          rand_idx = rand_below(afl, num_args);

          if ((method2 = rand_below(afl, 3))) {
            //Add <word>
            if (rand_idx != 0) {
              ptr = head;
              for (idx2 = 0; idx2 < rand_idx ; idx2++) {
                ptr = ptr->tmp_next;
              }
              ptr->tmp_prev->tmp_next = rand_word;
              rand_word->tmp_next = ptr;
              rand_word->tmp_prev = ptr->tmp_prev;
              ptr->tmp_prev = rand_word;
            } else {
              head->tmp_prev = rand_word;
              rand_word->tmp_next = head;
              head = rand_word;
            }

            num_args ++;
          } else {
            if (rand_idx != 0) {
              ptr = head;
              for (idx2 = 0; idx2 < rand_idx ; idx2++) {
                ptr = ptr->tmp_next;
              }
              ptr->tmp_prev->tmp_next = rand_word;
              rand_word->tmp_prev = ptr->tmp_prev;
              rand_word->tmp_next = ptr->tmp_next;
              if (ptr->tmp_next) {
                ptr->tmp_next->tmp_prev = rand_word;
              }
              ptr->tmp_prev = NULL;
              ptr->tmp_next = NULL;
            } else {
              rand_word->tmp_next = head->tmp_next;
              if (rand_word->tmp_next) {
                rand_word->tmp_next->tmp_prev = rand_word;
              }
              head->tmp_next = NULL;
              head = rand_word;
            }
          }

          break;
        case 4 : //Create/add or replace <-word>=<word> with <-word=> + <word>
          if (unlikely(afl->num_argv_word_buf_words[1] == 0)) break;
          if (unlikely(afl->num_argv_word_buf_words[3] == 0)) break;
          if (unlikely(afl->num_tmp_words >= TMP_WORD_SIZE)) break;

          struct argv_word_entry * rand_word1 = afl->argv_words_bufs[1][rand_below(afl,afl->num_argv_word_buf_words[1])];
          struct argv_word_entry * rand_word3 = afl->argv_words_bufs[3][rand_below(afl,afl->num_argv_word_buf_words[3])];

          u32 word1_len = strlen(rand_word1->word);
          u32 word3_len = strlen(rand_word3->word);

          struct argv_word_entry * new_tmp_word = calloc(1, sizeof(struct argv_word_entry));
          new_tmp_word->word = malloc(sizeof(s8) * (word1_len + word3_len + 1));
          memcpy(new_tmp_word->word, rand_word3->word, word3_len);
          memcpy(new_tmp_word->word + word3_len, rand_word1->word, word1_len);
          new_tmp_word->word[word3_len + word1_len] = 0;
          new_tmp_word->is_tmp = 1;

          ptr = head;
          for (idx2 = 0; idx2 < num_args; idx2++) {
            if (!strcmp(new_tmp_word->word, ptr->word)) {
              break;
            }
            ptr = ptr->tmp_next;
          }

          //duplicate
          if (idx2 != num_args) {
            free(new_tmp_word->word);
            free(new_tmp_word);
            break;
          }

          tmps[afl->num_tmp_words++] = new_tmp_word;

          rand_idx = rand_below(afl, num_args);

          if ((method2 = rand_below(afl, 3))) {
            //add
            if (rand_idx != 0) {
              ptr = head;
              for (idx2 = 0; idx2 < rand_idx ; idx2++) {
                ptr = ptr->tmp_next;
              }
              ptr->tmp_prev->tmp_next = new_tmp_word;
              new_tmp_word->tmp_next = ptr;
              new_tmp_word->tmp_prev = ptr->tmp_prev;
              ptr->tmp_prev = new_tmp_word;
            } else {
              head->tmp_prev = new_tmp_word;
              new_tmp_word->tmp_next = head;
              head = new_tmp_word;
            }

            num_args ++;
          } else {
            //replace
            if (rand_idx != 0) {
              ptr = head;
              for (idx2 = 0; idx2 < rand_idx ; idx2++) {
                ptr = ptr->tmp_next;
              }
              ptr->tmp_prev->tmp_next = new_tmp_word;
              new_tmp_word->tmp_prev = ptr->tmp_prev;
              new_tmp_word->tmp_next = ptr->tmp_next;
              if (ptr->tmp_next) {
                ptr->tmp_next->tmp_prev = new_tmp_word;
              }
              ptr->tmp_prev = NULL;
              ptr->tmp_next = NULL;
            } else {
              new_tmp_word->tmp_next = head->tmp_next;
              if (new_tmp_word->tmp_next) {
                new_tmp_word->tmp_next->tmp_prev = new_tmp_word;
              }
              head->tmp_next = NULL;
              head = new_tmp_word;
            }
          }

          break;

        case 5 :  //Delete any one word
          if(unlikely(num_args <= 2)) break;

          rand_idx = rand_below(afl, num_args); 
          
          if (rand_idx != 0) {
            ptr = head;
            for (idx2 = 0; idx2 < rand_idx ; idx2++) {
              ptr = ptr->tmp_next;
            }
            ptr->tmp_prev->tmp_next = ptr->tmp_next;
            if (ptr->tmp_next) {
              ptr->tmp_next->tmp_prev = ptr->tmp_prev;
            }
            ptr->tmp_next = NULL;
            ptr->tmp_prev = NULL;
          } else {
            head->tmp_next->tmp_prev = NULL;
            ptr = head;
            head = head->tmp_next;
            ptr->tmp_next = NULL;
          }

          num_args --;
          break;
      }

    } // end of for (idx1 = 0; idx1 < use_stacking1; idx1++) {

    //add argv[0] and input file name
    ptr = head;
    bool exists1 = false, exists2 = false;
    while(ptr) {
      if (ptr == afl->prog_arg) {
        exists1 = true;
      } else if (ptr == afl->input_file_arg) {
        exists2 = true;
      }
      ptr = ptr->tmp_next;
    }

    if (!exists1) {
      afl->prog_arg->tmp_next = head;
      head->tmp_prev = afl->prog_arg;
      head = afl->prog_arg;
      num_args++;
    }

    if (!exists2) {
      rand_idx = rand_below(afl, num_args); 
         
      if (rand_idx != 0) {
        ptr = head;
        for (idx2 = 0; idx2 < rand_idx ; idx2++) {
          ptr = ptr->tmp_next;
        }
        ptr->tmp_prev->tmp_next = afl->input_file_arg;
        afl->input_file_arg->tmp_next = ptr;
        afl->input_file_arg->tmp_prev = ptr->tmp_prev;
        ptr->tmp_prev = afl->input_file_arg;
      } else {
        head->tmp_prev = afl->input_file_arg;
        afl->input_file_arg->tmp_next = head;
        head = afl->input_file_arg;
      }
      num_args++;
    }

    //execute

    unlink(afl->fsrv.argv_file);
    s32 fd = open(afl->fsrv.argv_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", afl->fsrv.argv_file); }

    ptr = head;

    while(ptr) {
      ck_write(fd, ptr->word, strlen(ptr->word) + 1 , afl->fsrv.argv_file);
      ptr = ptr->tmp_next;
    }

    close(fd);

    u8 fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

    if (fault == FSRV_RUN_TMOUT) {
      continue;
    }

    afl->queued_discovered += save_if_interesting(afl, orig_in, len, fault, afl->current_entry, (u32) -1, head, (u32) -1);

    if (!(afl->stage_cur % afl->stats_update_freq) ||
        afl->stage_cur + 1 == afl->stage_max) {
      show_stats(afl);
    }
    // initialization?
  }

  ptr = head;
  while(ptr) {
    ptr->tmp_prev = NULL;
    ptr = ptr->tmp_next;
    if (ptr) {
      ptr->tmp_prev->tmp_next = NULL;
    }
  }

  for (idx1 = 0; idx1 < afl->num_tmp_words; idx1++) {
    struct argv_word_entry * tmp_word = afl->tmp_words[idx1];
    if (tmp_word->is_tmp == 2) {
      tmp_word->is_tmp = 0;
      tmp_word->tmp_prev = NULL;
      tmp_word->tmp_next = NULL;
    } else {
      free(tmp_word->word);
      free(tmp_word);
    }
  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes - orig_hit_cnt;

  afl->stage_finds[STAGE_ARGV] += new_hit_cnt;
  afl->stage_cycles[STAGE_ARGV] += afl->stage_max;
  return;
}

void argv_select(afl_state_t * afl) {

  //assert(afl->num_argvs >= 2);
  if (afl->num_argvs <= 2) {
    return;
  }
 
  //status record
  char fn[PATH_MAX];
  u32 idx1, idx2, idx3, idx4;
  snprintf(fn, PATH_MAX, "%s/FRIEND/argvs_init", afl->out_dir);
  s32 fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  FILE * f = fdopen(fd, "w");
  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    fprintf(f, "%u : ", idx1);
    struct argv_word_entry ** argv = afl->argvs_buf[idx1]->args;
    idx2 = 0;
    while(argv[idx2]) {
      fprintf(f, "%s ", argv[idx2]->word);
      idx2++;
    }
    fprintf(f, "\n");
  }

  u32 * num_inputs = (u32 *) calloc(afl->num_argvs, sizeof(u32));
  u32 ** argv_inputs = (u32 **) calloc(afl->num_argvs, sizeof(u32 *));

  fprintf(f, "queue idx, argv idx\n");
  for (idx1 = 0; idx1 < afl->queued_paths; idx1++) {
    u32 argv_idx = afl->queue_buf[idx1]->argv_idx;
    fprintf(f, "%u, %u\n", idx1, argv_idx);
    if (num_inputs[argv_idx] == 0) {
      argv_inputs[argv_idx] = (u32 *) malloc(sizeof(u32) * 1024);
    } else if (num_inputs[argv_idx] >= 1024) {
      continue;
    }

    argv_inputs[argv_idx][num_inputs[argv_idx]++] = idx1;
  }

  fprintf(f, "idx, # of input\n");
  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    fprintf(f, "%u,%u\n", idx1, num_inputs[idx1]);
  }
  fclose(f);

  afl->stage_name = "argv_sel";
  afl->stage_short = "argv_sel";
  afl->stage_max = afl->num_argvs;

#define FLIP_BIT(_ar, _b)                 \
do {                                      \
                                          \
  u8 *_arf = (u8 *)(_ar);                 \
  u32 _bf = (_b);                         \
  _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                          \
} while (0)
  u8 ** func_calls = (u8 **) malloc(sizeof(u8 *) * afl->num_argvs);

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; afl->stage_cur++) {

    unlink(afl->fsrv.argv_file);
    s32 fd = open(afl->fsrv.argv_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", afl->fsrv.argv_file); }

    struct argv_word_entry ** ptr = afl->argvs_buf[afl->stage_cur]->args;
    idx1 = 0;
    while(ptr[idx1]) {
      ck_write(fd, ptr[idx1]->word, strlen(ptr[idx1]->word) + 1 , afl->fsrv.argv_file);
      idx1++;
    }

    close(fd);
 
    u8 * func_call = (u8 *) calloc(afl->num_func, sizeof(u8));
    func_calls[afl->stage_cur] = func_call;
    
    for (idx1 = 0; idx1 < 128; idx1++) {     
      u32 rand_queue_id = argv_inputs[afl->stage_cur][rand_below(afl, num_inputs[afl->stage_cur])];
      struct queue_entry * cur_tc = afl->queue_buf[rand_queue_id];
      u32 len = cur_tc->len;
      u8 * orig_in = queue_testcase_get(afl, cur_tc);
      u8 * out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
      u32 temp_len = len;
      memcpy (out_buf, orig_in, len);
      struct cmp_entry * entries = afl->shm.branch_map;

      for (idx2 = 0; idx2 < 4; idx2++) {
        u32 use_stacking = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));
        for (idx3 = 0; idx3 < use_stacking; ++idx3) {
          switch (rand_below(afl, 15)) {

            case 0:

              /* Flip a single bit somewhere. Spooky! */

              FLIP_BIT(out_buf, rand_below(afl, temp_len << 3));
              break;

            case 1:

              /* Set byte to interesting value. */

              out_buf[rand_below(afl, temp_len)] =
                  interesting_8[rand_below(afl, sizeof(interesting_8))];
              break;

            case 2:

              /* Set word to interesting value, randomly choosing endian. */

              if (temp_len < 2) { break; }

              if (rand_below(afl, 2)) {
                *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
                    interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)];

              } else {

                *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) = SWAP16(
                    interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)]);

              }

              break;

            case 3:

              /* Set dword to interesting value, randomly choosing endian. */

              if (temp_len < 4) { break; }

              if (rand_below(afl, 2)) {

                *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
                    interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)];

              } else {

                *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) = SWAP32(
                    interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)]);

              }

              break;

            case 4:

              /* Randomly subtract from byte. */

              out_buf[rand_below(afl, temp_len)] -= 1 + rand_below(afl, ARITH_MAX);
              break;

            case 5:

              /* Randomly add to byte. */

              out_buf[rand_below(afl, temp_len)] += 1 + rand_below(afl, ARITH_MAX);
              break;

            case 6:

              /* Randomly subtract from word, random endian. */

              if (temp_len < 2) { break; }

              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 1);
                *(u16 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 1);
                u16 num = 1 + rand_below(afl, ARITH_MAX);

                *(u16 *)(out_buf + pos) =
                    SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);

              }

              break;

            case 7:

              /* Randomly add to word, random endian. */

              if (temp_len < 2) { break; }

              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 1);

                *(u16 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 1);
                u16 num = 1 + rand_below(afl, ARITH_MAX);

                *(u16 *)(out_buf + pos) =
                    SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);

              }

              break;

            case 8:

              /* Randomly subtract from dword, random endian. */

              if (temp_len < 4) { break; }

              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 3);

                *(u32 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 3);
                u32 num = 1 + rand_below(afl, ARITH_MAX);

                *(u32 *)(out_buf + pos) =
                    SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

              }

              break;

            case 9:

              /* Randomly add to dword, random endian. */

              if (temp_len < 4) { break; }

              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 3);

                *(u32 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 3);
                u32 num = 1 + rand_below(afl, ARITH_MAX);

                *(u32 *)(out_buf + pos) =
                    SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

              }

              break;

            case 10:

              /* Just set a random byte to a random value. Because,
                why not. We use XOR with 1-255 to eliminate the
                possibility of a no-op. */

              out_buf[rand_below(afl, temp_len)] ^= 1 + rand_below(afl, 255);
              break;

            case 11 ... 12: {

              /* Delete bytes. We're making this a bit more likely
                than insertion (the next option) in hopes of keeping
                files reasonably small. */

              u32 del_from, del_len;

              if (temp_len < 2) { break; }

              /* Don't delete too much. */

              del_len = choose_block_len(afl, temp_len - 1);

              del_from = rand_below(afl, temp_len - del_len + 1);

              memmove(out_buf + del_from, out_buf + del_from + del_len,
                      temp_len - del_from - del_len);

              temp_len -= del_len;

              break;

            }

            case 13:

              if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

                /* Clone bytes (75%) or insert a block of constant bytes (25%). */

                u8  actually_clone = rand_below(afl, 4);
                u32 clone_from, clone_to, clone_len;
                u8 *new_buf;

                if (likely(actually_clone)) {

                  clone_len = choose_block_len(afl, temp_len);
                  clone_from = rand_below(afl, temp_len - clone_len + 1);

                } else {

                  clone_len = choose_block_len(afl, HAVOC_BLK_XL);
                  clone_from = 0;

                }

                clone_to = rand_below(afl, temp_len);

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

                out_buf = new_buf;
                afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
                temp_len += clone_len;

              }

              break;

            case 14: {

              /* Overwrite bytes with a randomly selected chunk (75%) or fixed
                bytes (25%). */

              u32 copy_from, copy_to, copy_len;

              if (temp_len < 2) { break; }

              copy_len = choose_block_len(afl, temp_len - 1);

              copy_from = rand_below(afl, temp_len - copy_len + 1);
              copy_to = rand_below(afl, temp_len - copy_len + 1);

              if (likely(rand_below(afl, 4))) {

                if (likely(copy_from != copy_to)) {

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
          }
        }

        common_fuzz_stuff(afl, out_buf, len, (u32) -1);

        u32 cmp_id;

        for (cmp_id = 0; cmp_id < afl->num_cmp ; cmp_id++) {
          entries[cmp_id].condition = 0;
        }

        write_to_testcase(afl, out_buf, temp_len, (u32) -1);
        u8 fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout);

        if (fault == FSRV_RUN_TMOUT) {
          //what?
          WARNF("input in the queue timed out on func log");
          continue;
        }

        for (cmp_id = 0; cmp_id < afl->num_cmp; cmp_id++) {
          if (entries[cmp_id].condition) {
            func_call[afl->cmp_func_map[cmp_id]] = 1;
          }
        }

        if (unlikely(afl->stop_soon)) break;
      }

      show_stats(afl);
      if (unlikely(afl->stop_soon)) break;
    }

    if (unlikely(afl->stop_soon)) break;
  }

  if (unlikely(afl->stop_soon)) {
    return;
  }

  /*
  //Find minimized subset of argvs that can cover all executed functions.

  u32 * argv_num_func = (u32 *) calloc(afl->num_argvs, sizeof(u32));
  u8 * func_set = (u8 *) calloc(afl->num_func, sizeof(u8));

  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    u32 num_call = 0;
    u8 * calls = func_calls[idx1];
    for (idx2 = 0; idx2 < afl->num_func; idx2++) {
      num_call += calls[idx2];
      func_set[idx2] |= calls[idx2];
    }
    argv_num_func[idx1] = num_call;
  }

  u32 total_covered = 0;
  for (idx1 = 0; idx1 < afl->num_func; idx1++) {
    total_covered += func_set[idx1];
  }
  
  memset(func_set, 0, sizeof(u8) * afl->num_func);
  
  u8 * argv_set = (u8 *) calloc(afl->num_argvs, sizeof(u8));
  u32 num_covered = 0;
  
  u32 min_call = (u32) -1;
  u32 min_idx = 0;

  u32 num_all_cov_argvs = 0;

  
  while (num_covered != total_covered) {
    for (idx1 = 0; idx1 < afl->num_argvs ; idx1++) {
      if (!argv_set[idx1] && (min_call > argv_num_func[idx1])) {
        min_call = argv_num_func[idx1];
        min_idx = idx1;
      }
    }

    argv_set[min_idx] = 1;
    u8 * calls = func_calls[min_idx];
    for (idx2 = 0; idx2 < afl->num_func; idx2++) {
      if (calls[idx2] && !func_set[idx2]) {
        func_set[idx2] = 1;
        argv_set[min_idx] = 2;
        num_covered ++;
      }
    }
    if (argv_set[min_idx] == 2) {
      num_all_cov_argvs ++;
    }

    min_call = (u32) -1;
  }

  u32 * all_cov_argvs = (u32 *) malloc (sizeof(u32) * num_all_cov_argvs);

  idx2 = 0;
  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    if (argv_set[idx1] == 2) {
      all_cov_argvs[idx2++] = idx1;
    }
  }

  //assert(idx2 == num_all_cov_argvs);

  */

  float ** argv_rel = (float **) malloc(sizeof (float *) * afl->num_argvs);
  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    argv_rel[idx1] = (float *) malloc(sizeof(float) * afl->num_argvs);
  }

  u32 ** func_exec_count = (u32 **) afl->func_exec_count_table;

  float min_rel = FLT_MAX;
  float max_rel = FLT_MIN;
  u32 min_rel_idx1 = 0, min_rel_idx2 = 0;

  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    float * tmp = argv_rel[idx1];
    u32 argv_1 = idx1;
    u8 * argv_1_func_call = func_calls[argv_1];
    tmp[idx1] = 0.0;
    for (idx2 = idx1 + 1; idx2 < afl->num_argvs; idx2++) {
      float rel_sum = 0.0;
      float num_rel = 0.0;
      u32 argv_2 = idx2;
      u8 * argv_2_func_call = func_calls[argv_2];
      for (idx3 = 0; idx3 < afl->num_func; idx3++) {
        if (argv_1_func_call[idx3]) {
          float func_idx3_count = (float) func_exec_count[idx3][idx3];
          for (idx4 = 0; idx4 < afl->num_func; idx4 ++) {
            if (argv_2_func_call[idx4]) {
              float idx3_idx4_count = (float) func_exec_count[idx3][idx4];
              rel_sum += idx3_idx4_count * idx3_idx4_count / func_idx3_count / ((float) func_exec_count[idx4][idx4]);
              num_rel += 1.0;
            }
          }
        }
      }
      float rel_res = rel_sum / num_rel;
      tmp[idx2] = argv_rel[idx2][idx1] = rel_res;
      if (rel_res < min_rel) { 
        min_rel = rel_res;
        min_rel_idx1 = idx1;
        min_rel_idx2 = idx2;
      } else if (rel_res > max_rel) {
        max_rel = rel_res;
      }
    }
  }

  snprintf(fn, PATH_MAX, "%s/FRIEND/argv_rels", afl->out_dir);
  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  f = fdopen(fd, "w");
  /*
  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    fprintf(f, "%u,", all_cov_argvs[idx1]);
  }
  fprintf(f, "\n");
  */

  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    for (idx2 = 0; idx2 < afl->num_argvs; idx2++) {
      fprintf(f, "%f,", argv_rel[idx1][idx2]);
    }
    fprintf(f, "\n");
  }
  fclose(f);

  u8 * selected_argvs_bits = (u8 *) calloc(afl->num_argvs, sizeof(u8));
  u32 * selected_argvs = (u32 *) malloc(sizeof(u32) * afl->num_argvs);
  selected_argvs_bits[min_rel_idx1] = 1;
  selected_argvs_bits[min_rel_idx2] = 1;
  selected_argvs[0] = min_rel_idx1;
  selected_argvs[1] = min_rel_idx2;
  u32 num_selected = 2;

  float threshold = (max_rel + min_rel) / 2.0;

  bool added = true;
  while (added) {
    added = false;
    for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
      if (selected_argvs_bits[idx1]) continue;
      bool not_close = true;
      for (idx2 = 0; idx2 < num_selected; idx2++) {
        if (argv_rel[idx1][selected_argvs[idx2]] > threshold) {
          not_close = false;
          break;
        }
      }
      if (not_close) {
        added = true;
        selected_argvs[num_selected++] = idx1;
        selected_argvs_bits[idx1] = 1;
        break;
      }
    }
  }

  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    free(argv_rel[idx1]);
  }
  free(argv_rel);
  free(selected_argvs_bits);

  snprintf(fn, PATH_MAX, "%s/FRIEND/num_func_calls", afl->out_dir);
  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  f = fdopen(fd, "w");

  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    for (idx2 = 0; idx2 < afl->num_func; idx2++) {
      fprintf(f, "%u,", func_calls[idx1][idx2]);
    }
    fprintf(f, "\n");
  }
  fclose(f);

  snprintf(fn, PATH_MAX, "%s/FRIEND/argvs_selected", afl->out_dir);
  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  f = fdopen(fd, "w");

  for (idx1 = 0; idx1 < num_selected; idx1++) {
    fprintf(f, "%u,", selected_argvs[idx1]);
  }

  fclose(f);

  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    free(func_calls[idx1]);
  }
  free(func_calls);

  /*
  free(argv_num_func);
  free(func_set);
  free(argv_set);
  */

  //initialize
  memset(afl->virgin_bits, 255, afl->fsrv.map_size);

  //remove cached testcases
  for (idx1 = 0; idx1 < afl->queued_paths; idx1++) {
    struct queue_entry *q;
    q = afl->queue_buf[idx1];
    if (q->testcase_buf) free(q->testcase_buf);
    q->testcase_buf = NULL;
  }

  for (idx1 = 0; idx1 < afl->q_testcase_max_cache_entries; idx1++) {
    afl->q_testcase_cache[idx1] = NULL;
  }

  afl->q_testcase_cache_count = 0;
  afl->q_testcase_cache_size = 0;
  afl->q_testcase_smallest_free = 0;
  afl->q_testcase_max_cache_count = 0;

  u32 cur_queued_path = 0;
  struct queue_entry ** tmp_buf = malloc(sizeof (struct queue_entry *) * 128 * num_selected);

  u32 * saved_queue = (u32 *) malloc (sizeof (u32) * afl->queued_paths);
  memset(saved_queue, 255, sizeof(u32) * afl->queued_paths);

  for (idx1 = 0; idx1 < 128; idx1++) {
    if (unlikely(afl->stop_soon)) break;

    for (idx2 = 0; idx2 < num_selected; idx2++) {
      u32 argv_idx = selected_argvs[idx2];
      u32 rand_queue_id = argv_inputs[argv_idx][rand_below(afl, num_inputs[argv_idx])];
      struct queue_entry * cur_tc = afl->queue_buf[rand_queue_id];
      u32 len = cur_tc->len;
      u8 * out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
      int fd = open(cur_tc->fname, O_RDONLY);
      if (unlikely(fd < 0)) { PFATAL("Unable to open '%s'", cur_tc->fname); }
      ck_read(fd, out_buf, len, cur_tc->fname);
      close(fd);
      u32 temp_len = len;

      write_to_testcase(afl, out_buf, temp_len, argv_idx);
      u8 fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
      
      //just update bitmap
      has_new_bits_unclassified(afl, afl->virgin_bits);

      u32 cur_id = cur_queued_path;

      if (saved_queue[cur_tc->id] == (u32) -1) {
        saved_queue[cur_tc->id] = cur_id;

        s8 * queue_fn = alloc_printf(
          "%s/queue2/id:%06u,%s", afl->out_dir, cur_queued_path,
          describe_op(afl, 0, NAME_MAX - strlen("id:000000,"), (u32) -1, (u32) -1, argv_idx));

        s32 fd = open(queue_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", queue_fn); }
        ck_write(fd, out_buf, temp_len, queue_fn);
        close(fd);

        struct queue_entry *q = ck_alloc(sizeof(struct queue_entry));

        q->fname = queue_fn;
        q->len = temp_len;
        q->depth = 0;
        q->passed_det = 0;
        q->trace_mini = NULL;
        q->testcase_buf = NULL;
        q->mother = NULL;
        q->argv_idx = argv_idx;

        tmp_buf[cur_queued_path] = q;
        q->id = cur_queued_path;
        cur_queued_path ++;

        q->exec_cksum =
          hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

        calibrate_case(afl, q, out_buf, afl->queue_cycle - 1, 0);
        queue_testcase_store_mem(afl, q, out_buf);
      } else {
        cur_id = saved_queue[cur_tc->id];
      }

      u32 use_stacking = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));
      for (idx3 = 0; idx3 < use_stacking; ++idx3) {
        switch (rand_below(afl, 15)) {

          case 0:

            /* Flip a single bit somewhere. Spooky! */

            FLIP_BIT(out_buf, rand_below(afl, temp_len << 3));
            break;

          case 1:

            /* Set byte to interesting value. */

            out_buf[rand_below(afl, temp_len)] =
                interesting_8[rand_below(afl, sizeof(interesting_8))];
            break;

          case 2:

            /* Set word to interesting value, randomly choosing endian. */

            if (temp_len < 2) { break; }

            if (rand_below(afl, 2)) {
              *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
                  interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)];

            } else {

              *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) = SWAP16(
                  interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)]);

            }

            break;

          case 3:

            /* Set dword to interesting value, randomly choosing endian. */

            if (temp_len < 4) { break; }

            if (rand_below(afl, 2)) {

              *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
                  interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)];

            } else {

              *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) = SWAP32(
                  interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)]);

            }

            break;

          case 4:

            /* Randomly subtract from byte. */

            out_buf[rand_below(afl, temp_len)] -= 1 + rand_below(afl, ARITH_MAX);
            break;

          case 5:

            /* Randomly add to byte. */

            out_buf[rand_below(afl, temp_len)] += 1 + rand_below(afl, ARITH_MAX);
            break;

          case 6:

            /* Randomly subtract from word, random endian. */

            if (temp_len < 2) { break; }

            if (rand_below(afl, 2)) {

              u32 pos = rand_below(afl, temp_len - 1);
              *(u16 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

            } else {

              u32 pos = rand_below(afl, temp_len - 1);
              u16 num = 1 + rand_below(afl, ARITH_MAX);

              *(u16 *)(out_buf + pos) =
                  SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);

            }

            break;

          case 7:

            /* Randomly add to word, random endian. */

            if (temp_len < 2) { break; }

            if (rand_below(afl, 2)) {

              u32 pos = rand_below(afl, temp_len - 1);

              *(u16 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

            } else {

              u32 pos = rand_below(afl, temp_len - 1);
              u16 num = 1 + rand_below(afl, ARITH_MAX);

              *(u16 *)(out_buf + pos) =
                  SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);

            }

            break;

          case 8:

            /* Randomly subtract from dword, random endian. */

            if (temp_len < 4) { break; }

            if (rand_below(afl, 2)) {

              u32 pos = rand_below(afl, temp_len - 3);

              *(u32 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

            } else {

              u32 pos = rand_below(afl, temp_len - 3);
              u32 num = 1 + rand_below(afl, ARITH_MAX);

              *(u32 *)(out_buf + pos) =
                  SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

            }

            break;

          case 9:

            /* Randomly add to dword, random endian. */

            if (temp_len < 4) { break; }

            if (rand_below(afl, 2)) {

              u32 pos = rand_below(afl, temp_len - 3);

              *(u32 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

            } else {

              u32 pos = rand_below(afl, temp_len - 3);
              u32 num = 1 + rand_below(afl, ARITH_MAX);

              *(u32 *)(out_buf + pos) =
                  SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

            }

            break;

          case 10:

            /* Just set a random byte to a random value. Because,
              why not. We use XOR with 1-255 to eliminate the
              possibility of a no-op. */

            out_buf[rand_below(afl, temp_len)] ^= 1 + rand_below(afl, 255);
            break;

          case 11 ... 12: {

            /* Delete bytes. We're making this a bit more likely
              than insertion (the next option) in hopes of keeping
              files reasonably small. */

            u32 del_from, del_len;

            if (temp_len < 2) { break; }

            /* Don't delete too much. */

            del_len = choose_block_len(afl, temp_len - 1);

            del_from = rand_below(afl, temp_len - del_len + 1);

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    temp_len - del_from - del_len);

            temp_len -= del_len;

            break;

          }

          case 13:

            if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

              /* Clone bytes (75%) or insert a block of constant bytes (25%). */

              u8  actually_clone = rand_below(afl, 4);
              u32 clone_from, clone_to, clone_len;
              u8 *new_buf;

              if (likely(actually_clone)) {

                clone_len = choose_block_len(afl, temp_len);
                clone_from = rand_below(afl, temp_len - clone_len + 1);

              } else {

                clone_len = choose_block_len(afl, HAVOC_BLK_XL);
                clone_from = 0;

              }

              clone_to = rand_below(afl, temp_len);

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

              out_buf = new_buf;
              afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
              temp_len += clone_len;

            }

            break;

          case 14: {

            /* Overwrite bytes with a randomly selected chunk (75%) or fixed
              bytes (25%). */

            u32 copy_from, copy_to, copy_len;

            if (temp_len < 2) { break; }

            copy_len = choose_block_len(afl, temp_len - 1);

            copy_from = rand_below(afl, temp_len - copy_len + 1);
            copy_to = rand_below(afl, temp_len - copy_len + 1);

            if (likely(rand_below(afl, 4))) {

              if (likely(copy_from != copy_to)) {

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
        }
        
        write_to_testcase(afl, out_buf, temp_len, argv_idx);

        fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

        if (afl->stop_soon) { break; }

        if (unlikely(fault != afl->crash_mode)) { continue; }

        u8 new_bits = has_new_bits_unclassified(afl, afl->virgin_bits);

        if (!new_bits) continue;

        s8 * queue_fn = alloc_printf(
          "%s/queue2/id:%06u,%s", afl->out_dir, cur_queued_path,
          describe_op(afl, new_bits, NAME_MAX - strlen("id:000000,"), cur_id, (u32) -1, argv_idx));

        s32 fd = open(queue_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", queue_fn); }
        ck_write(fd, out_buf, temp_len, queue_fn);
        close(fd);

        struct queue_entry *q = ck_alloc(sizeof(struct queue_entry));

        q->fname = queue_fn;
        q->len = temp_len;
        q->depth = 0;
        q->passed_det = 0;
        q->trace_mini = NULL;
        q->testcase_buf = NULL;
        q->mother = NULL;
        q->argv_idx = argv_idx;

        tmp_buf[cur_queued_path] = q;
        q->id = cur_queued_path;
        

        q->exec_cksum =
          hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

        calibrate_case(afl, q, out_buf, afl->queue_cycle - 1, 0);
        queue_testcase_store_mem(afl, q, out_buf);

        q->parent_id = cur_id;
        struct queue_entry * parent = tmp_buf[cur_id];
        if (parent->children == NULL) { 
          parent->children = (u32 *) malloc (sizeof(u32) * TC_CHILDREN_SIZE);
          parent->children_size = TC_CHILDREN_SIZE;
        }
        parent->children[parent->num_children++] = cur_queued_path;
        if(unlikely(parent->num_children >= parent->children_size)){
          parent->children_size *= 2;
          parent->children = realloc(parent->children, parent->children_size * sizeof(u32));
        }

        cur_queued_path ++;
      }
    }
  }

  //reset queue...
  memset(afl->top_rated, 0, sizeof(struct queue_entry *) * afl->fsrv.map_size);
  destroy_queue(afl);

  afl->queue = afl->queue_top = tmp_buf[0];
  afl->queue_buf = afl_realloc(
      AFL_BUF_PARAM(queue), cur_queued_path * sizeof(struct queue_entry *));

  memcpy(afl->queue_buf, tmp_buf, sizeof(struct queue_entry *) * cur_queued_path);

  afl->current_entry = 0;
  afl->queued_paths = cur_queued_path;
  afl->queue_cur = NULL;

  free(tmp_buf);

  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    free(argv_inputs[idx1]);
  }

  free(selected_argvs);
  free(argv_inputs);
  free(num_inputs);
  free(saved_queue);

  //initializeation func part
  afl->mining_done_idx = 0;
  for (idx1 = 0; idx1 < afl->num_cmp; idx1++) {
    struct cmp_queue_entry * cq = afl->cmp_queue_buf[idx1];
    free(cq->value_changing_tcs);
    cq->value_changing_tcs = NULL;
    cq->num_value_changing_tcs = 0;
    cq->value_changing_tcs_size = 0;
    cq->num_fuzzed = 0;
  }

}