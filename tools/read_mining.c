#include<stdio.h>

#include<stdlib.h>

struct byte_cmp_set {
  unsigned int * changed_cmps;
  unsigned int * abandoned_cmps;
  unsigned int num_changed_cmps;
  unsigned int num_abandoned_cmps;
  unsigned char  timeout;
};

int main() {

  FILE * f = fopen("id:000004", "r");
  unsigned int * buffer = malloc(sizeof(unsigned int ) * 1000);
  unsigned int buffer_size = 1000;
  unsigned int read_size ;
  unsigned int num_changed_cmps = 0;
  unsigned int num_abandoned_cmps = 0;

  

  for (;;) {
    read_size = fread(buffer, sizeof(unsigned int), 2, f);
    if (read_size != 2) break;
    num_changed_cmps += buffer[0];
    num_abandoned_cmps += buffer[1];

    printf("num_changed cmps : %u, num abanadoned : %u\n",buffer[0], buffer[1]);
    
    read_size = fread(buffer, sizeof(unsigned char), 1, f);

    if (buffer_size < num_changed_cmps){
      free(buffer);
      buffer = malloc(sizeof(unsigned int) * num_changed_cmps);
    }
    if (buffer_size < num_abandoned_cmps) {
      free(buffer);
      buffer = malloc(sizeof(unsigned int) * num_abandoned_cmps);
    }

    read_size = fread(buffer, sizeof(unsigned int), num_changed_cmps, f);
    read_size = fread(buffer, sizeof(unsigned int), num_abandoned_cmps, f);
  }

  free(buffer);
  fclose(f);

  printf("num_changed cmps : %u, num abanadoned : %u\n", num_changed_cmps, num_abandoned_cmps);
  
  return 0;
}
