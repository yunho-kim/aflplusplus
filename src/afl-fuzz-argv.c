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
    bool has_equal = false;

    for (idx1 = 0; idx1 < len; idx1++) {
      s8 tmp_char = buffer[idx1];
      hash = hash + (tmp_char << idx1);
      has_minus |= (tmp_char == '-');
      has_equal |= (tmp_char == '=');
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
    if (has_minus && has_equal) {
      buf_index = 3;
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

  {
    u32 idx;
    for (idx = 0; idx < 1024; idx++) {
      struct argv_word_entry * tmp = afl->argv_words[idx];
      while(tmp) {
        assert(tmp->tmp_next == NULL);
        assert(tmp->tmp_prev == NULL);
        tmp = tmp->next;
      }
    }
  }
  struct argv_word_entry * ptr = head;
  
  while (orig_args[num_args]) {
    orig_args[num_args]->tmp_prev = prev;
    if (prev != NULL) {
      prev->tmp_next = orig_args[num_args];
    }
    prev = orig_args[num_args];
    num_args++;
  }

  {
    u32 idx;
    for (idx = 0; idx < num_args; idx++) {
      u32 idxx;
      for (idxx = idx + 1 ; idxx < num_args; idxx++) {
        assert(orig_args[idx] != orig_args[idxx]);
      }
    }
  }

  {
    u32 idx;
    ptr = head;
    for (idx = 0; idx < num_args; idx++) {
      assert(orig_args[idx] == ptr);
      if (idx > 0 && idx < (num_args - 1)) {
        assert(orig_args[idx-1] == ptr->tmp_prev);
        assert(orig_args[idx + 1] == ptr->tmp_next);
      }
      ptr = ptr->tmp_next;
    }
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

      ptr = head;
      assert(head->tmp_prev == NULL);
      ptr = head->tmp_next;
      assert(ptr != NULL);
      for (idx2 = 0; idx2 < (num_args - 2); idx2++) {
        assert(ptr->tmp_next != NULL);
        assert(ptr->tmp_prev != NULL);
        assert(ptr->tmp_next->tmp_prev == ptr);
        assert(ptr->tmp_prev->tmp_next == ptr);
        ptr= ptr->tmp_next;
      }
      assert(ptr->tmp_next == NULL);

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

  u32 idx;
  for (idx = 0; idx < 1024; idx++) {
    struct argv_word_entry * tmp = afl->argv_words[idx];
    while(tmp) {
      assert(tmp->tmp_next == NULL);
      assert(tmp->tmp_prev == NULL);
      tmp = tmp->next;
    }
  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes - orig_hit_cnt;

  afl->stage_finds[STAGE_ARGV] += new_hit_cnt;
  afl->stage_cycles[STAGE_ARGV] += afl->stage_max;
  return;
}