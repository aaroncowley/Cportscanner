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
 *     gcc -o desired_executable_name scan.c -lpthread
 *
 * OTHER SOURCES:
 *     https://stackoverflow.com/questions/10283703/conversion-of-ip-address-to-integer
 *     https://stackoverflow.com/questions/1680365/integer-to-ip-address-c
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
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

int	threads = 0;
char opened[65535]; //an array that is assigned a 1 to its open ports
pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;


struct scanargs {
    char host[16];
    unsigned short port;
    char proto;
};

char** str_split(char* a_str, const char a_delim){
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp){
        if (a_delim == *tmp){
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char*) * count);

    if (result){
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token){
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}

/*====================TCP Port Scan====================*/
void scan_tcp(char *host, unsigned short port) {
    int sock, err, open, res;
    fd_set fd_arr;
    struct sockaddr_in	sin;
    struct timeval timeout;

    
    sin.sin_family = AF_INET; /*sets family to IPV4*/
    sin.sin_port = htons(port); /* The htons() function converts the unsigned short integer 
                                   hostshort from host byte order to network byte order.*/

    inet_pton(AF_INET, host, &sin.sin_addr.s_addr); /*The inet_pton() function converts an Internet address in 
                                                      its standard text format into its numeric binary form. */

    sock = socket(AF_INET, SOCK_STREAM, 0); /*setting up local TCP socket */

    /*kills socket if something goes wrong */
    if (sock == -1) 
      DIE("socket()");

    /* will return 0 if good */
    err = connect(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));

    if (err == 0){
        FD_ZERO(&fd_arr); /* sets up file descriptor */
        FD_SET(sock, &fd_arr); /* then sets socket process to it */
        
        /*sets timeout to 5 seconds */
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        
        /*sends a null packet of 100bytes*/
        send(sock, NULL, 0, 0);
        
        /*if result is good, port is open*/
        res = select(sock + 1, &fd_arr, NULL, NULL, &timeout);
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
    fd_set fd_arr;
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
        FD_ZERO(&fd_arr);
        FD_SET(sock, &fd_arr);

        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        send(sock, NULL, 0, 0);

        res = select(sock + 1, &fd_arr, NULL, NULL, &timeout);
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
    if (args->proto == 'u')
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
    printf("starting program\n");
    pthread_t	thread;
    struct scanargs args;
    int h, i, p;
    int startport, endport;
    char start_host[16], end_host[16], net_addr[13];
    char current_host[16];
    int range_start, range_end;
    char **start_host_addr;
    char **end_host_addr;
      
    printf("starting out\n");
    if (argc < 5) {
        fprintf(stderr, "usage: %s <starthost> <endhost> <startport> <endport> <\"u\" or \"t\" for protocol>\n", argv[0]);
        return EXIT_SUCCESS;
    }

    if (argv[3] > argv[4]){
        fprintf(stderr, "please put lower port number first\n");
        return EXIT_SUCCESS;
    }

    printf("before first ip to int\n");

    startport = atoi(argv[3]);
    endport = atoi(argv[4]);
    printf("before loops\n");

    start_host_addr = str_split(argv[1], '.'); 
    end_host_addr = str_split(argv[2], '.');
    
    range_start = atoi(start_host_addr[3]);
    range_end = atoi(end_host_addr[3]);

    if (range_start < 0 || range_end > 255){
        fprintf(stderr, "Invalid host range, max subnet is /24");
        return EXIT_SUCCESS;
    }

    sprintf(net_addr, "%s.%s.%s.", start_host_addr[0], start_host_addr[1], start_host_addr[2]);
    sprintf(start_host, "%s%s", net_addr, start_host_addr[3]);
    sprintf(end_host, "%s%s", net_addr, end_host_addr[3]);

    printf("Starting Host is: %s\n", start_host);
    printf("Ending Host is: %s\n", end_host);

    printf("Starting Scan...\n\n");

    for (h = range_start; h <= range_end; h++) {
        bzero(opened, sizeof(opened));
        sprintf(current_host, "%s%d", net_addr, h);
        printf("SCANNING: "RED"%s"RESET"\n", current_host);
        for (p = startport; p <= endport; p++) {
            sprintf(args.host, "%s%d", net_addr, h);
            args.port = p;
            args.proto = argv[5][0];
            advance_cursor(); /* spinny boi */
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
        while (threads != 0);
    }
    return EXIT_SUCCESS;
}
