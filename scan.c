/* made by the hacker known as:
 *                              
 *    __ _  ___ _____      __
 *   / _` |/ __/ _ \ \ /\ / /
 *  | (_| | (_| (_) \ V  V / 
 *   \__,_|\___\___/ \_/\_/  
 *                           
 * (Aaron Cowley)
 *
 * Found https://github.com/droberson/udp-scan/blob/master/udp-scan.c
 * thought it was cool so i decided to make an extended version of it
 *
 * FEATURES:
 *   [x]   tcp scanning
 *   []    host range
 *   []    file input + output
 *   [x]   port range
 *   [x]   threading cuz speedy
 *   []    web interface, heavens no
 *   [x]   written in C so even more speedy
 *   []    user experience, idc about that
 *
 *   compile with:
 *     gcc -o executable_name scan.c -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DIE(x) { perror(x); exit (EXIT_FAILURE); }
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)

/*fancy terminal output*/
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN    "\x1b[36m"
#define RESET   "\x1b[0m"

int			threads = 0;
char opened[65535]; //an array that is assigned a 1 to its open ports
pthread_mutex_t		lock = PTHREAD_MUTEX_INITIALIZER;


struct scanargs {
  char			    *host;
  unsigned short	port;
  unsigned short    endport;
  char              proto;
};

/*====================TCP Port Scan====================*/
void scan_tcp(char *host, unsigned short port) {
    int sock, err, open, res;
    fd_set s;
    struct sockaddr_in	sin;
    struct timeval timeout;

    
    sin.sin_family = AF_INET; /*sets family to IPV4*/
    sin.sin_port = htons(port); /* The htons() function converts the unsigned short integer 
                                   hostshort from host byte order to network byte order.*/

    inet_pton(AF_INET, host, &sin.sin_addr.s_addr); /*The inet_pton() function converts an Internet address in 
                                                      its standard text format into its numeric binary form. */

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); /*setting up local TCP socket */

    /*kills socket if something goes wrong */
    if (sock == -1) 
      DIE("socket()");

    /* will return 0 if good */
    err = connect(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));

    if (err == 0){
        FD_ZERO(&s); /* sets up file descriptor */
        FD_SET(sock, &s); /* then sets socket process to it */
        
        /*sets timeout to 5 seconds */
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        
        /*sends a null packet of 100bytes*/
        send(sock, NULL, 0, 0);
        
        /*if result is good, port is open*/
        res = select(sock + 1, &s, NULL, NULL, &timeout);
        if (res < 0)
          DIE("select()");
        if (res == 0)
          open = 1;
    }


    close(sock);
    if (open == 1)
      opened[port] = 1;
}


/*====================UDP Port Scan====================*/

/* Most functionality is the same as TCP, 
 * check scan_tcp if you have questions */

void scan_udp(char *host, unsigned short port) {
    int	sock, err, open, res;
    fd_set s;
    struct sockaddr_in	sin;
    struct timeval timeout;


    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);     
    inet_pton(AF_INET, host, &sin.sin_addr.s_addr);
    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (sock == -1)
        DIE("socket()");

    err =connect(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));
    
    if (err == 0) {
        FD_ZERO(&s);
        FD_SET(sock, &s);

        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        send(sock, NULL, 0, 0);

        res = select(sock + 1, &s, NULL, NULL, &timeout);
        if (res < 0)
            DIE("select()");
        if (res == 0)
            open = 1;
    }

    close(sock);
    if (open == 1)
      opened[port] = 1;
}


/*====================Threading====================*/
void *thread_task(void *threadargs) {
  struct scanargs *args;

  args = threadargs;

  /*sets up threads for speediness */
  pthread_mutex_lock(&lock);
  threads++;
  pthread_mutex_unlock(&lock);
  pthread_detach(pthread_self());
  
  /*checks for protocol here*/
  if      (args->proto == 'u')
            scan_udp(args->host, args->port);
  else if (args->proto == 't')
            scan_tcp(args->host, args->port);

  /*once process finishes it removes the thread*/
  pthread_mutex_lock(&lock);
  threads--;
  pthread_mutex_unlock(&lock);

  pthread_exit(NULL);
}

void advance_cursor() {
  static int pos=0;
  char cursor[4]={'/','-','\\','|'};
  printf("%c\b", cursor[pos]);
  fflush(stdout);
  pos = (pos+1) % 4;
}

/*====================MAIN====================*/
int main(int argc, char *argv[]) {
  pthread_t	thread;
  struct scanargs args;

  int i;


  if (argc < 5) {
    fprintf(stderr, "usage: %s <host> <startport> <endport> <\"u\" or \"t\" for protocol>\n", argv[0]);
    return EXIT_SUCCESS;
  }

  if (argv[2] > argv[3]){
      fprintf(stderr, "please put lower port number first\n");
      return EXIT_SUCCESS;
  }
  
  /*implement host range next*/
  printf("scanning host: "MAGENTA"%s"RESET"\n", argv[1]);
  bzero(opened, sizeof(opened));
  for (i = atoi(argv[2]); i <= atoi(argv[3]); i++) {
    args.host = argv[1];
    args.port = i;
    args.proto = argv[4][0];
    advance_cursor();
    while (threads >= 200); /* keep the thread number fixed at 200 */
    pthread_create(&thread, NULL, thread_task, &args);
  }
  printf("results coming shortly\n");
  while (threads); /* wait for threads to finish */

  /* Display results */
  if (args.proto == 't')
      printf("Chosen protocol was "GREEN"TCP"RESET", here are your results...\n\n");
  if (args.proto == 'u')
      printf("Chosen protocol was "GREEN"UDP"RESET", here are your results...\n\n");
  printf("==============================================\n");
  for(i = 0; i < sizeof(opened); i++) {
    if (opened[i] == 1)
      printf("port: "RED"%d"RESET" is "BLUE"open"RESET"\n", i);
  }
  printf("==============================================\n");

  return EXIT_SUCCESS;
}
