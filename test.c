#include <stdio.h>
#include <stddef.h>
#include <stdalign.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci.h>

int dump_hex(char *logstr, unsigned char *buf, int length);

/*******************************************
Function main - Our main function: interpret commandline arguments, and keep the global flow
  argc : Amount of commandline arguments
  argv : Actual commandline arguments as an array of strings
returns: 0 if succesfull
*******************************************/
int main(int argc, char **argv) {
    char          bt_address[20] = "00:80:25:A4:B6:C2";
    int           bytes_read;
    int           status;
    int           i;                     
    int           sock;                  /* Socket with SunnyBoy */
    struct        sockaddr_rc dst_addr;  /* the remote Bluetooth Addres in binary format */
    unsigned char rcv_buf[1024];

    for (i = 1; i < argc; i++) {
        if(!strcmp(argv[i],"-?")) {
          printf("Synopsis: test -a bluetooth-address\n");
          printf("  e.g. test -a 00:80:25:A4:B6:C2\n");
        }
        if(!strcmp(argv[i],"-a")) {
            i++;
            if (i<argc) {
                strcpy(bt_address,argv[i]);
            }
        }
    }
    /* Check the processor */
    printf("Size of char:  %d (should be 1)\n",sizeof(char));
    printf("Size of int:   %d (should be 4)\n",sizeof(int));
    printf("Size of short: %d (should be 2)\n",sizeof(short));
    printf("Size of long:  %d (should be 8)\n",sizeof(long));
    unsigned int x = 0x76543210;
    char *c = (char*) &x;
    // printf ("*c is: 0x%x\n", *c);
    printf ("Underlying architecture is ");
    if (*c == 0x10)
      printf ("little endian");
    else
       printf ("big endian");
    printf (" (should be little endian).\n");
    /* check the default packing (pragma pack) */
    printf("alignof(char)                              = %zu (should be 1)\n", alignof(char));
    printf("alignof(max_align_t)                       = %zu (should be 16)\n", alignof(max_align_t));
    printf("alignof(float[10])                         = %zu (should be 4)\n", alignof(float[10]));
    printf("alignof(struct {char c; short s;  int i;}) = %zu (should be 4)\n", alignof(struct {char c; short s;  int i;}));
    /* set the connection parameters (who to connect to) */
    dst_addr.rc_family = AF_BLUETOOTH;
    dst_addr.rc_channel = (uint8_t) 1;
    str2ba(bt_address, &dst_addr.rc_bdaddr );
    /* allocate a sock */
    sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    /* connect to server */
    printf("\nChecking the connection\n");
    if(sock > 0) {
      status = connect(sock, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
      if(!status) {
        bytes_read = read(sock, rcv_buf, sizeof(rcv_buf));
        dump_hex("reading", rcv_buf, bytes_read);
        return bytes_read;
      }
      else
        printf(" - ERROR: Could not connect to SunnyBoy\n");
    }
    else
      printf(" - ERROR: Could not create BT socket\n");
}



/*******************************************
Function dump_hex - show a buffer in hexadecimal format, if the debug level is 2 or more
  logstr    : Description of the buffer being dumped
  buf       : buffer to be dumped in headecimal format
  length    : length of the message
*******************************************/
int dump_hex(char *logstr, unsigned char *buf, int length) {
    int i;
    printf( "\n%s: len=%d data=\n", logstr, length);
    for( i=0; i<length; i++ ) {
        if( i%16== 0 ) printf( "%s  %08x: ", (i>0 ? "\n" : ""), i);
        /* Make sure it is not reported as a negative value (starting with ffffff */
        printf( " %02x", buf[i]);
    }
    printf( "\n" );
    return 0;
}
