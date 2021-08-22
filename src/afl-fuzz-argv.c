#include "afl-fuzz.h"
#include "funclog.h"

static void argv_random_fuzz(afl_state_t * afl);

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
  afl->argv_words_buf_size[0] = 1024;
  afl->argv_words_buf_size[1] = 1024;
  afl->argv_words_buf_size[2] = 1024;

  afl->tmp_words = (struct argv_word_entry **) malloc(TMP_WORD_SIZE * sizeof(struct argv_word_entry *));

  snprintf(fn, PATH_MAX, "%s/FRIEND_getopt_info", afl->func_infos_dir);
  f = fopen(fn, "r");
  if (f == NULL) PFATAL("Can't open func txt file");
  
  u8 buffer[KEYWORD_MAX];
  memset(buffer, 0, KEYWORD_MAX);
  int res;
  while((res = fscanf(f, "%s\n", buffer)) != EOF) {
    size_t len = strlen(buffer);
    s8 * tmp = (s8 *) malloc(sizeof(s8) * (len + 1));
    memcpy(tmp, buffer, len);
    tmp[len] = 0;

    u32 hash = 0;
    for (idx1 = 0; idx1 < len; idx1++) {
      hash = hash + (buffer[idx1] << idx1);
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

    afl->argv_words_bufs[0][afl->num_argv_word_buf_words[0]++] = tmp_entry;
    afl->num_argv_words ++;

    if (unlikely(afl->num_argv_word_buf_words[0] >= afl->argv_words_buf_size[0])) {
      afl->argv_words_buf_size[0] *= 2;
      afl->argv_words_bufs[0] = realloc (afl->argv_words_bufs[0], sizeof(struct argv_word_entry *) * afl->argv_words_buf_size[0]);
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

  for (idx1 = 0; idx1 < 3; idx1++) {
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

void argv_random_fuzz(afl_state_t * afl) {
  //TODO

  s8 * randoms[9] = {
    "-a",
    "-b",
    "-c",
    "-d",
    "-e",
    "-o",
    "-i",
    "-f",
    "-u"
  };

  u32 idx1, idx2;
  for (idx1 = 0; idx1 < 9; idx1++) {
    struct argv_word_entry * tmp_entry = (struct argv_word_entry *) calloc(1, sizeof (struct argv_word_entry));
    u32 hash = 0;
    s8 * str = randoms[idx1];
    u32 len = strlen(str);
    for (idx2 = 0; idx2 < len; idx2++) {
      hash = hash + (str[idx2] << idx2);
    }
    hash = hash % 1024;
    
    if (afl->argv_words[hash] == NULL) {
      afl->argv_words[hash] = tmp_entry;
    } else {
      struct argv_word_entry * ptr = afl->argv_words[hash];
      while (ptr->next != NULL) {
        ptr = ptr->next;
      }
      ptr->next = tmp_entry;
    }

    afl->argv_words_bufs[0][afl->num_argv_word_buf_words[0]++] = tmp_entry;
    afl->num_argv_words ++;

    s8 * tmp = (s8 *) malloc(sizeof(s8) * (len + 1));
    memcpy(tmp, str, len);
    tmp[len] = 0;
    tmp_entry->word = tmp;
  }


  //PFATAL("TODO %p", afl);
}

void fuzz_one_argv(afl_state_t * afl) {
  u32 len;
  u32 idx1, idx2;
  u8 *orig_in;
  u64 orig_hit_cnt, new_hit_cnt;

  struct queue_entry * cur_tc = afl->queue_cur;

  len = (u32) cur_tc->len;

  orig_in = queue_testcase_get(afl, cur_tc);

  *afl->shm.record_branch_map = 1;

  struct argv_word_entry ** orig_args = afl->argvs_buf[cur_tc->argv_idx]->args;

  //recored coverage
  write_to_testcase(afl, orig_in, len, cur_tc->argv_idx);
  u8 fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout * 5);

  if (fault == FSRV_RUN_TMOUT) {
    //what?
    WARNF("input in the queue timed out on func log");
    return;
  }

  *afl->shm.record_branch_map = 0;
  *afl->shm.check_branch_map = 1;

  /*
  if (unlikely(afl->num_argv_words <= 5)) {
    argv_random_fuzz(afl);
  }
  */

  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_name = "argv";
  afl->stage_short = "argv";
  afl->stage_max /= 2;

  u32 num_args = 0;

  struct argv_word_entry * prev = NULL;
  struct argv_word_entry * head = orig_args[0];
  struct argv_word_entry ** tmps = afl->tmp_words;
  
  while (orig_args[num_args]) {
    orig_args[num_args]->tmp_prev = prev;
    if (prev != NULL) {
      prev->tmp_next = orig_args[num_args];
    }
    prev = orig_args[num_args];
    num_args++;
  }

  afl->num_tmp_words = 0;

  struct argv_word_entry * ptr = head;
  u32 tmp_idx = 0;
  while (ptr) {
    tmp_idx ++;
    if (ptr->tmp_next) {
      assert(ptr->tmp_next->tmp_prev == ptr);
    }
    ptr = ptr->tmp_next;
  }
  assert(num_args == tmp_idx);

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {
    
    u32 use_stacking1 = 1 << (1 + rand_below(afl, HAVOC_STACK_POW2_FUNC));
    afl->stage_cur_val = use_stacking1;

    struct argv_word_entry * rand_word;
    struct argv_word_entry * ptr;
    u32 rand_idx;

    u32 method = 0;

    for (idx1 = 0; idx1 < use_stacking1; idx1++) {
      switch (method = rand_below(afl, 11)) {
        case 0-2 :  //Add <-word>
          if (unlikely(afl->num_argv_word_buf_words[0] == 0)) break;

          rand_word = afl->argv_words_bufs[0][rand_below(afl,afl->num_argv_word_buf_words[0])];
          if (rand_word->tmp_next != NULL || rand_word->tmp_prev != NULL) break;

          rand_idx = rand_below(afl, num_args); 
         
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

          break;
        case 3 :  //Replace with <-word>
          if (unlikely(afl->num_argv_word_buf_words[0] == 0)) break;
          rand_word = afl->argv_words_bufs[0][rand_below(afl,afl->num_argv_word_buf_words[0])];
          if (rand_word->tmp_next != NULL || rand_word->tmp_prev != NULL) break;
          rand_idx = rand_below(afl, num_args); 
          
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

          break;

        case 4-5 :  //Add <word>
          if (unlikely(afl->num_argv_word_buf_words[1] == 0)) break;

          rand_word = afl->argv_words_bufs[1][rand_below(afl,afl->num_argv_word_buf_words[1])];
          if (rand_word->tmp_next != NULL || rand_word->tmp_prev != NULL) break;

          rand_idx = rand_below(afl, num_args); 
         
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

          break;
        case 6 :  //Replace with <word>
          if (unlikely(afl->num_argv_word_buf_words[1] == 0)) break;

          rand_word = afl->argv_words_bufs[1][rand_below(afl,afl->num_argv_word_buf_words[1])];
          if (rand_word->tmp_next != NULL || rand_word->tmp_prev != NULL) break;
          rand_idx = rand_below(afl, num_args); 
          
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

          break;
        case 7 :  //Create/add <-word>=<word>
          if (unlikely(afl->num_argv_word_buf_words[0] == 0)) break;
          if (unlikely(afl->num_argv_word_buf_words[1] == 0)) break;
          if (unlikely(afl->num_tmp_words >= TMP_WORD_SIZE)) break;

          struct argv_word_entry * rand_word0 = afl->argv_words_bufs[0][rand_below(afl,afl->num_argv_word_buf_words[0])];
          struct argv_word_entry * rand_word1 = afl->argv_words_bufs[1][rand_below(afl,afl->num_argv_word_buf_words[1])];

          u32 word0_len = strlen(rand_word0->word);
          u32 word1_len = strlen(rand_word1->word);

          struct argv_word_entry * new_tmp_word = calloc(1, sizeof(struct argv_word_entry));
          new_tmp_word->word = malloc(sizeof(s8) * (word0_len + word1_len + 2));
          memcpy(new_tmp_word->word, rand_word0->word, word0_len);
          new_tmp_word->word[word0_len] = '=';
          memcpy(new_tmp_word->word + word0_len + 1, rand_word1->word, word1_len);
          new_tmp_word->word[word0_len + word1_len + 1] = 0;
          new_tmp_word->is_tmp = 2;

          tmps[afl->num_tmp_words++] = new_tmp_word;

          rand_idx = rand_below(afl, num_args); 
          
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

          break;
          
        case 8 :  //Create/replace with <-word>=<word>
          if (unlikely(afl->num_argv_word_buf_words[0] == 0)) break;
          if (unlikely(afl->num_argv_word_buf_words[1] == 0)) break;
          if (unlikely(afl->num_tmp_words >= TMP_WORD_SIZE)) break;

          rand_word0 = afl->argv_words_bufs[0][rand_below(afl,afl->num_argv_word_buf_words[0])];
          rand_word1 = afl->argv_words_bufs[1][rand_below(afl,afl->num_argv_word_buf_words[1])];

          word0_len = strlen(rand_word0->word);
          word1_len = strlen(rand_word1->word);

          new_tmp_word = calloc(1, sizeof(struct argv_word_entry));
          new_tmp_word->word = malloc(sizeof (s8) * (word0_len + word1_len + 2));
          memcpy(new_tmp_word->word, rand_word0->word, word0_len);
          new_tmp_word->word[word0_len] = '=';
          memcpy(new_tmp_word->word + word0_len + 1, rand_word1->word, word1_len);
          new_tmp_word->word[word0_len + word1_len + 1] = 0;
          new_tmp_word->is_tmp = 2;

          tmps[afl->num_tmp_words++] = new_tmp_word;

          rand_idx = rand_below(afl, num_args); 

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

          break;

        case 9 :  //Delete any one word
          if(unlikely(num_args <= 1)) break;

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

        case 10 :  //Create/add -<word>
          if (unlikely(afl->num_argv_word_buf_words[1] == 0)) break;
          if (unlikely(afl->num_tmp_words >= TMP_WORD_SIZE)) break;

          rand_word1 = afl->argv_words_bufs[1][rand_below(afl,afl->num_argv_word_buf_words[1])];
          word1_len = strlen(rand_word1->word);

          new_tmp_word = calloc(1, sizeof(struct argv_word_entry));
          new_tmp_word->word = malloc(sizeof(s8) * (word1_len + 2));
          new_tmp_word->word[0] = '-';
          memcpy(new_tmp_word->word, rand_word1->word, word1_len);
          new_tmp_word->word[word1_len + 1] = 0;
          new_tmp_word->is_tmp = 1;

          tmps[afl->num_tmp_words++] = new_tmp_word;

          rand_idx = rand_below(afl, num_args); 
          
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

          break;
      }

      ptr = head;
      u32 tmp_idx = 0;
      while (ptr) {
        tmp_idx ++;
        if (ptr->tmp_next) {
          assert(ptr->tmp_next->tmp_prev == ptr);
        }
        ptr = ptr->tmp_next;
      }
      assert(num_args == tmp_idx);
    } // end of for (idx1 = 0; idx1 < use_stacking1; idx1++) {

    // check input file arg

    
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

    memset(afl->shm.magic_bytes_map, 0, sizeof(u8) * BYTES_RECORD_LEN);

    fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

    if (fault == FSRV_RUN_TMOUT) {
      continue;
    }

    afl->queued_discovered += save_if_interesting(afl, orig_in, len, fault, afl->current_entry, (u32) -1, head, (u32) -1);

    if (!(afl->stage_cur % afl->stats_update_freq) ||
        afl->stage_cur + 1 == afl->stage_max) {
      show_stats(afl);
    }

    fault = fuzz_run_target(afl, &afl->func_fsrv, afl->fsrv.exec_tmout);

    if (fault == FSRV_RUN_TMOUT) {
      continue;
    }

    //gather new keywords
    u8 * magic_ptr = afl->shm.magic_bytes_map;

    magic_ptr = afl->shm.magic_bytes_map;

    while (*magic_ptr) {
      u32 len = strlen(magic_ptr);
      u32 hash = 0;
      for (idx1 = 0; idx1 < len; idx1++) {
        hash += magic_ptr[idx1] << idx1;
      }

      hash = hash % 1024;

      u32 word_buf_idx = magic_ptr[0] != '-';
      // would there be <-word>=<word> case?

      bool exists = false;
      struct argv_word_entry * hash_ptr = afl->argv_words[hash];
      if (hash_ptr) {
        ptr = hash_ptr;
        while(ptr) {
          if(!strcmp(magic_ptr, ptr->word)) {
            exists = true;
            break;
          }
          ptr = ptr->next;
        }
      }

      if (!exists) {
        struct argv_word_entry * new_entry = (struct argv_word_entry *) calloc (1, sizeof(struct argv_word_entry));
        new_entry->word = malloc(len + 1);
        memcpy(new_entry->word, magic_ptr, len + 1);
        if (hash_ptr) {
          ptr = hash_ptr;
          while (ptr->next) {
            ptr = ptr->next;
          }
          ptr->next = new_entry;
        } else {
          afl->argv_words[hash] = new_entry;
        }

        afl->argv_words_bufs[word_buf_idx][afl->num_argv_word_buf_words[word_buf_idx] ++] = new_entry;
        afl->num_argv_words++;

        if (unlikely(afl->num_argv_word_buf_words[word_buf_idx] >= afl->argv_words_buf_size[word_buf_idx])) {
          afl->argv_words_buf_size[word_buf_idx] *= 2;
          afl->argv_words_bufs[word_buf_idx] = realloc (afl->argv_words_bufs[word_buf_idx], sizeof(struct argv_word_entry *) * afl->argv_words_buf_size[word_buf_idx]);
        }

      }

      magic_ptr += len + 1;
    }

    // initialization?
  }

  for (idx1 = 0; idx1 < afl->num_tmp_words; idx1++) {
    free(afl->tmp_words[idx1]);
  }

  *afl->shm.check_branch_map = 0;

  ptr = head;
  while(ptr) {
    ptr->tmp_prev = NULL;
    ptr = ptr->tmp_next;
    if (ptr) {
      ptr->tmp_prev->tmp_next = NULL;
    }
  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes - orig_hit_cnt;

  afl->stage_finds[STAGE_ARGV] += new_hit_cnt;
  afl->stage_cycles[STAGE_ARGV] += afl->stage_max;
  return;
}