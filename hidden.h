#ifndef HIDDEN_H
#define HIDDEN_H
#include <sys/sem.h>
#include <sys/ipc.h>
extern const uint32_t haddr ;
extern const uint32_t hmask ;
extern const char * haddr_str;
#define MAX_MADDR_STR 2
extern const uint32_t maddr[MAX_MADDR_STR];
extern const uint32_t mmask[MAX_MADDR_STR];
extern const char * maddr_str[MAX_MADDR_STR];
extern pid_t proc_p;
extern pid_t mon_pid;
extern const char * proc_str;
extern const char * proc_args[];

extern const key_t key_mon;
extern int semid;
union semun
{
  int val;                      
  struct semid_ds *buf;        
  unsigned short int *array;  
  struct seminfo *__buf;     
};

#define KILL_SIG 15
#endif
