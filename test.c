#include <stdio.h>
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
    int           sock;                  /* Socket with SunnyBoy */
    struct        sockaddr_rc dst_addr;  /* the remote Bluetooth Addres in binary format */
    unsigned char rcv_buf[1024];

    /* set the connection parameters (who to connect to) */
    dst_addr.rc_family = AF_BLUETOOTH;
    dst_addr.rc_channel = (uint8_t) 1;
    str2ba(bt_address, &dst_addr.rc_bdaddr );

    /* allocate a sock */
    sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);

    /* connect to server */
    if(sock > 0)
        status = connect(sock, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
    if(sock > 0 && !status) {
      bytes_read = read(sock, rcv_buf, sizeof(rcv_buf));
      dump_hex("reading", rcv_buf, bytes_read);
      return bytes_read;
    }
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
