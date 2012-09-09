/*

sb_bt
=====

Tool to read power production data for SMA Sunnyboy power invertors on a Linux machine.
Copyright 2012, Creagraphy / Ernst de Moor.

SunnyBoy Bluetooth communications. Reads actual values in a reliable way, and adds them to a CSV file.

This software is to be called from a Cron job, e.g. every 5 minutes.
It will add the current values to a .csv file, with the date as part of the filename.

Examples of filesnames that are created:
 - test2012-09-05.csv (with -f option of -f test )
 - /tmp/pv-2-2012-09-05.csv (with -f option of -f /tmp/pv-2- )


Optionally this program will set the internal clock of the SunnyBoy, either once a day or every 5 minutes.
This is not necessary for this tool, but might be useful to read the graphs lateron with SunnyExplorer.

Tested with a SMA SunnyBoy 2100TL, but expected to be used with all SunnyBoy inverters with a piggyback Bluetooth module.


Commandline options:
--------------------
Usage: sb_bt [OPTION]...
Read information from SunnyBoy inverter via BlueTooth
Optionally set the internal clock (not necessary for us, but for SMA Sunny Explorer

Mandatory arguments:
  - -a ADDRESS        : Bluetooth address of the inverter
  - -p PASSWORD       : User level password of the inverter (default: 0000)

Optional arguments
  - -f FILENAME       : Output filename lead-in (date and csv extension is added, default: /tmp/pv-2- )
  - -t SETTIME        : Set the time of the converter, 1: Once a day, 2: every request
  - -v                : verbose. if off, the application is silent for cron
  - -d LEVEL          : activate debug, 1: status info, 2: additional hexdumps, 3: additional translations
  - -h                : this help info


Versions:
---------
  - 0.9   : Initial version
  - 0.9.1 : Updated readme, added GNU license text
  - 0.9.2 : readme info fed back to sourcecode
  - 0.9.3 : Remove unnecessary "secret inverter code"
  - 0.9.4 : Some improvements in the Readme file
  - 0.9.5 : Recognise if the SunnyBoy returns a status message instead of data, and retry (better implementation)


Limitations: 
------------
  - A Little-Endian processor is assumed, because data structure are built directly in memory (using structs).
     Don't worry, most Linux machines are Little Endian, at least the Intel and ARM processors.
  - Probably only works with SunnyBoy inverters with a piggyback BlueTooth module, not with the newer ones with built-in BT.


Technical notes:
----------------
  - I have put a lot of effort in understanding the communications protocol, and detect CRC errors in messages from the Sunnyboy
    Therefore the BT communications is very reliable, chances of reading wrong values are very small.
  - I have chosen to communicate with small messages, rather than reading lots of data at once.
    This makes the communications more reliable too.
  - This software uses global data, as it has a very specific use.
      - The config structure contains settings from the commandline.
      - The comms structure holds communications settings like addresses, and the send/receive buffers.
      - The results structure contains the results of querying the Sunnyboys, values for Watt etc.

    making these structures global, keeps the software fast and easy to understand.
    Note however that the functions are _NOT_ re-entrent because of this.
    So if you want to use these functions in a multithreading program, or if you want to write a program 
    that communicates with more than one SunnyBoy, you will have to modify the code!


Special thanks:
---------------
Thanks to the following sources for showing the structuring of data:
  - Yasdi tool of SMA themselves
  - Dean Fogarty : https://github.com/angrytongan/dfinvrelay/
  - Wim Hofman and Stephen Collier : http://code.google.com/p/sma-bluetooth/

Data package structure (example Wh data request):
-------------------------------------------------
00000000:  7e 3e 00 40 14 95 69 3a 00 00 c2 b6 a4 25 80 00
      Sync, Len2, Len1, Chksum, src_addr(6b), dest_addr(6b)
00000010:  01 00 7e ff 03 60 65 09 a0 ff ff ff ff ff ff 00
      Cmd2, Cmd1, Sync, dataheader (4b), C1, C2, ff (6x), A
00000020:  00 ff ff ff ff ff ff 00 00 00 00 00 00 01 80 00
      B, unknown (=6xff), 00 (4x), C, 00(4x), Counter, Rq1, Rq2
00000030:  02 00 54 00 01 26 00 ff 01 26 00 4b 82 7e
      Rq3-Rq13, Chksum1, Chksum2, Sync

GNU license
-----------
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/


/* compile: gcc -lbluetooth -lm -o sb_bt sb_bt.c */


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

/* Our private functions */
char *strrstr(char *s1, char *s2);
int read_bt(unsigned char *buf, int buf_size);
unsigned char *check_header(unsigned char *buf, int len);
unsigned int get_header_cmd(unsigned char *buf, int len);
int create_header(int cmd, unsigned char *buf, int size);
int write_bt(unsigned char *buf, int msg_size);
int dump_hex(char *logstr, unsigned char *buf, int length, int force);
char *get_device_name(char *name, int name_size);
int send_packet(unsigned char *buf, int len);
int read_packet();
int pack_smanet2_data(unsigned char *buf, int size, unsigned char *src, unsigned int num);
int handle_init_1(void);
int handle_get_signal_strength(void);
int handle_total_wh(void);
int handle_net_voltage(void);
int handle_net_amp(void);
int handle_net_freq(void);
int handle_pv_volt(void);
int handle_pv_amp(void);
int handle_logon(void);
int handle_set_time(void);
char *retry_send_receive(int bytes_send, char *log_str);
int build_data_packet(unsigned char *buf, int size, unsigned char c1, unsigned char c2,
                      unsigned char a, unsigned char b, unsigned char c);
int add_fcs_checksum(unsigned char *buf, int size);


/* Global variables */
char *help = "\
  Usage: %s [OPTION]...\n\
  Read information from SunnyBoy inverter via BlueTooth\n\
  Optionally set the internal clock (not necessary for us, but for SMA Sunny Explorer\n\
  \n\
  Mandatory arguments:\n\
    -a ADDRESS        : Bluetooth address of the inverter\n\
    -p PASSWORD       : User level password of the inverter (default: 0000)\n\
  \n\
  Optional arguments\n\
    -f FILENAME       : Output filename lead-in (date and csv extension is added, default: /tmp/pv-2- )\n\
    -t SETTIME        : Set the time, 1: Once a day, 2: every request\n\
    -v                : verbose. if off, the application is silent for cron \n\
    -d LEVEL          : activate debug, 1: status info, 2: additional hexdumps, 3: additional translations\n\
    -h                : This help info\n\
";

/* Structures for reading and creating  package headers */
/* Note: this structure must be byte-aligned, we use pragma to stop the browser from aligning with extra empty bytes */
#pragma pack (push)       /* Push current alignment to compiler stack */
#pragma pack (1)          /* Force byte padding (instead of word or long padding */
typedef struct {
  unsigned char  sync;
  unsigned short len;
  unsigned char  chksum;
  bdaddr_t       src_addr;
  bdaddr_t       dst_addr;
  unsigned short cmd;
} packet_hdr;
#pragma pack (pop)        /* Restore original alignment from compiler stack */

/* Local storage for (commandline) parameters */
struct {
  char bt_address[20];
  char password[12];
  char out_file[80];
  int  set_time;
  int  debug;
  int  verbose;
} config = { "00:80:25:A4:B6:C2", "0000\0\0\0\0\0\0\0\0", "/tmp/pv-2-", 0, 0, 0 };

/* Local storage Bluetooth information and buffers */
struct {
    int           sock;                  /* Socket with SunnyBoy */
    struct        sockaddr_rc src_addr;  /* the local Bluetooth Addres in binary format  */
    struct        sockaddr_rc dst_addr;  /* the remote Bluetooth Addres in binary format */
    char          netid;                 /* The netid, part of the SMA messages */
    int           signal;                /* Signal strength, max = 255 */
    unsigned int  fcs_checksum;          /* Final checksum for messages */
    unsigned char packet_send_counter;   /* Keeps track of the amount of data packages sent */
    unsigned char snd_buf[1024];
    unsigned char rcv_buf[1024];
/* TEMPORARY */
unsigned char rawrcv_buf[1024];
unsigned int rawrcv_buf_size;
} comms = { 0, {0}, {0}, 1, 0, 0xffff, 0, {0}, {0} };

/* Local storage for Sunnyboy output */
struct {
  unsigned long   Wh;
  unsigned long   W;
  unsigned long   netVolt;
  unsigned long   netAmpere;
  unsigned long   netFreq;
  time_t          datetime;
  unsigned long   pvVolt;
  unsigned long   pvAmpere;
} results = { 0L, 0L, 0L};

/* FCS checksum table */
unsigned int fcstab[256] = {
   0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
   0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
   0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
   0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
   0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
   0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
   0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
   0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
   0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
   0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
   0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
   0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
   0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
   0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
   0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
   0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
   0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
   0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
   0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
   0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
   0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
   0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
   0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
   0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
   0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
   0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
   0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
   0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
   0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
   0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
   0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
   0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

/* Definitions for building packages */
#define HDLC_SYNC           0x7e    /* Sync character, denotes start of message and surrounds data */
#define HDLC_ESC            0x7d    /* Escape character, indicates modification of next byte */
#define DATA_CHK            0xa0    /* It seems that this byte at position 32 indicates valid data */

/* Packet header offsets */
#define PKT_OFF_LEN1        1
#define PKT_OFF_LEN2        2
#define PKT_OFF_CMD         16
#define PKT_OFF_DATASTART   18
/* Packet command types */
#define CMD_DATA            0x0001  /* Data */
#define CMD_INITIALISE      0x0002  /* Initialise */
#define CMD_BT_SIGNAL_REQ   0x0003  /* Request Bluetooth signal */
#define CMD_BT_SIGNAL_RSP   0x0004  /* Response Bluetooth signal */
#define CMD_0005            0x0005
#define CMD_IDATA           0x0008  /* Incomplete data (continued in next package) */
#define CMD_000A            0x000A
#define CMD_000C            0x000C

/* Data indexes */
#define IDX_NETID            4
#define IDX_LOGONFAIL       24
#define IDX_DATA_CHK        14  /* It seems this always contains xa0 with a valid data package */
#define IDX_BT_SIGNAL        4
#define IDX_DATETIME        45
#define IDX_VALUE           49

/* Message contents */
unsigned char fourzeros[]           = { 0, 0, 0, 0 };
unsigned char long_one[]            = { 0x01, 0x00, 0x00, 0x00 };
unsigned char sixff[]               = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

unsigned char smanet2dataheader[]   = { 0xff, 0x03, 0x60, 0x65 };
unsigned char smanet2init1[]        = { 0x00, 0x04, 0x70, 0x00 };
unsigned char smanet2getBT[]        = { 0x05, 0x00 };
unsigned char smanet2logon[]        = { 0x80, 0x0c, 0x04, 0xfd, 0xff, 0x07, 0x00, 0x00, 0x00, 0x84, 0x03, 0x00, 0x00 };
unsigned char smanet2totalWh[]      = { 0x80, 0x00, 0x02, 0x00, 0x54, 0x00, 0x01, 0x26, 0x00, 0xff, 0x01, 0x26, 0x00 };
unsigned char smanet2curWatt[]      = { 0x80, 0x00, 0x02, 0x00, 0x51, 0x00, 0x3f, 0x26, 0x00, 0xff, 0x3f, 0x26, 0x00, 0x0e };
unsigned char smanet2netVolt[]      = { 0x80, 0x00, 0x02, 0x00, 0x51, 0x00, 0x48, 0x46, 0x00, 0xff, 0x48, 0x46, 0x00, 0x0e };
unsigned char smanet2netAmp[]       = { 0x80, 0x00, 0x02, 0x00, 0x51, 0x00, 0x50, 0x46, 0x00, 0xff, 0x50, 0x46, 0x00, 0x0e };
unsigned char smanet2netFreq[]      = { 0x80, 0x00, 0x02, 0x00, 0x51, 0x00, 0x57, 0x46, 0x00, 0xff, 0x57, 0x46, 0x00, 0x0e };
unsigned char smanet2pvVolt[]       = { 0x80, 0x00, 0x02, 0x80, 0x63, 0x00, 0x1F, 0x45, 0x00, 0xff, 0x1f, 0x45, 0x00 };
unsigned char smanet2pvAmpere[]     = { 0x80, 0x00, 0x02, 0x80, 0x63, 0x00, 0x21, 0x45, 0x00, 0xff, 0x21, 0x45, 0x00 };
unsigned char smanet2set_time[]     = { 0x80, 0x0a, 0x02, 0x00, 0xf0, 0x00, 0x6d, 0x23, 0x00, 0x00, 0x6d, 0x23, 0x00, 0x00, 0x6d, 0x23, 0x00 };
unsigned char smanet2set_time2[]    = { 0x30,0xfe,0x7e,0x00 };



/*******************************************
Function main - Our main function: interpret commandline arguments, and keep the global flow
  argc : Amount of commandline arguments
  argv : Actual commandline arguments as an array of strings
returns: 0 if succesfull
*******************************************/
int main(int argc, char **argv) {
    int status, i, new_file=0;
    char name[248] = { 0 };
    char *serial = NULL;
    char filename[256];
    time_t curtime;
    struct tm *lt;
    struct stat fileStat;
    FILE *file;

    /* read the commandline arguments */
    for (i = 1; i < argc; i++) {
      if(!strcmp(argv[i],"-a")) {
        i++;
        if (i<argc) {
          strcpy(config.bt_address,argv[i]);
        }
      }
      else if(!strcmp(argv[i],"-p")) {
        i++;
        if (i<argc) {
          strcpy(config.password,argv[i]);
        }
      }
      else if(!strcmp(argv[i],"-f")) {
        i++;
        if (i<argc) {
          strcpy(config.out_file,argv[i]);
        }
      }
      else if(!strcmp(argv[i],"-t")) {
        config.set_time = 1;
        if (i+1 < argc){           /* Note: this tests for the next argument (<= instead of <) */
          if(isdigit(argv[i+1][0])) {
            i++;
            config.set_time = atoi(argv[i]);
          }
        }
      }
      else if(!strcmp(argv[i],"-v")) {
        config.verbose = 1;
      }
      else if(!strcmp(argv[i],"-d")) {
        config.debug = 1;
        if (i+1 < argc){           /* Note: this tests for the next argument (<= instead of <) */
          if(isdigit(argv[i+1][0])) {
            i++;
            config.debug = atoi(argv[i]);
          }
        }
      }
      else if(!strcmp(argv[i],"-h")) {
        printf(help,argv[0]);
        return 0;
      }
    }

    /* Check if this is a new day, by checking if the file with day-values exists */
    /* Create the filename by adding the date to the base-name */
    curtime = time(NULL);
    lt = localtime (&curtime);
    sprintf(filename, "%s%04d-%02d-%02d.csv", config.out_file, 1900+lt->tm_year, 1+lt->tm_mon, lt->tm_mday);
    if(stat(filename,&fileStat) < 0)
        new_file = 1;

    /* set the connection parameters (who to connect to) */
    comms.dst_addr.rc_family = AF_BLUETOOTH;
    comms.dst_addr.rc_channel = (uint8_t) 1;
    str2ba(config.bt_address, &comms.dst_addr.rc_bdaddr );

    /* Get remote device name (and thus serial number) */
    serial = get_device_name(name, sizeof(name));

    /* allocate a sock */
    comms.sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);

    /* connect to server */
    if(comms.sock > 0)
      status = connect(comms.sock, (struct sockaddr *)&comms.dst_addr, sizeof(comms.dst_addr));
    if(comms.sock > 0 && !status) {
        if(config.verbose)
          printf("Connected to SunnyBeam with name: %s (Serial: %s)\n", name, serial);
        if(handle_init_1())
            return 1;
        if(handle_get_signal_strength())
            return 1;
        if(handle_logon())
            return 1;
        /* Set the time, once a day for internal logging (not necessary for us) */
        if( (config.set_time == 2 && handle_set_time()) || (config.set_time == 1 && new_file && handle_set_time()) )
            return 1;
        if(handle_total_wh())
            return 1;
        if(handle_cur_w())
            return 1;
        if(handle_net_voltage())
            return 1;
        if(handle_net_amp())
            return 1;
        if(handle_net_freq())
            return 1;
        if(handle_pv_volt())
            return 1;
        if(handle_pv_amp())
            return 1;
        file = fopen(filename,"a+");
        if(new_file) {
          fprintf(file,";Connected to SunnyBeam with name %s\n", name);
          fprintf(file,";Serial: %s, Bluetooth signal strength: %d \%\n", serial, comms.signal);
          fprintf(file,"DateTime;Total kWh;Current kW;Max kW today;Total SunHours;PV Volt;PV Ampere;Net freq;Net Volt;Sol Temp;Error\n");
        }
        curtime = time(NULL);
        lt = localtime (&curtime);
        fprintf(file, "%02d-%02d-%04d %02d:%02d:%02d;",lt->tm_mday, 1+lt->tm_mon, 1900+lt->tm_year, lt->tm_hour, lt->tm_min, lt->tm_sec);
        fprintf(file, "%.3f;%.3f;",(float)results.Wh/1000, (float)results.W/1000);
        fprintf(file, ";;%.2f;%.3f;", (float)results.pvVolt/100,(float)results.pvAmpere/1000);
        fprintf(file, "%.2f;%.2f;;", (float)results.netFreq/100,(float)results.netVolt/100);
        fprintf(file, "\n");
        fclose(file); /*done!*/ 
  }
  else {
      if (config.verbose)
        printf("connection to SunnyBoy failed\n");
        return 1;
    }

    /* close connection */
    close(comms.sock);
    return 0;
}


/*******************************************
Function handle_init_1 - send the first initialisation string
Globals: comms structure
returns: 0 if succesfull
*******************************************/
int handle_init_1(void) {
    unsigned char *p = comms.snd_buf;
    int len, bytes_read, cmd, size=sizeof(comms.snd_buf);
    unsigned char *payload;

    /* Start by reading from BlueTooth */
    bytes_read = read_bt(comms.rcv_buf, sizeof(comms.rcv_buf));
    payload = check_header(comms.rcv_buf, bytes_read);
    if(payload) {
      comms.netid = payload[IDX_NETID];          
    }
    else {
        if (config.verbose)
            printf("\nSend init 1: received invalid messages header\n");
        return(1);
    }
    if(config.debug >= 2)
        printf("\nSend init 1\n");
    len = create_header(CMD_INITIALISE, p, size);
    p += len; size -= len;
    len = pack_smanet2_data(p, size, smanet2init1, sizeof(smanet2init1));
    p += len; size -= len;
    len = pack_smanet2_data(p, size, &comms.netid, 1);
    p += len; size -= len;
    len = pack_smanet2_data(p, size, fourzeros, sizeof(fourzeros));
    p += len; size -= len;
    len = pack_smanet2_data(p, size, long_one, sizeof(long_one));
    p += len; size -= len;
    if(send_packet(comms.snd_buf, p - comms.snd_buf)) {
        /* Wait for the correct answer */
        while(bytes_read = read_bt(comms.rcv_buf, sizeof(comms.rcv_buf))) {
            cmd = get_header_cmd(comms.rcv_buf, bytes_read);
            if(cmd == CMD_0005)
                break;
        }
        if (cmd != CMD_0005) {
            printf("No valid response from handle_init_1\n");
            return 1;
        }
    }
    else {
        if (config.verbose)
          printf("Could not send data of handle_init_1\n");
        return 1;
    }
    return 0;
}

/*******************************************
Function handle_get_signal_strength - send the first initialisation string
Globals: comms structure
returns: 0 if succesfull
*******************************************/
int handle_get_signal_strength(void) {
    unsigned char *p = comms.snd_buf;
    int len, bytes_read, cmd, size=sizeof(comms.snd_buf);
    unsigned char *payload;

    /* Start by reading from BlueTooth */
    if(config.debug >= 2)
        printf("\nSend Get Bluetooth signal strength\n");
    len = create_header(CMD_BT_SIGNAL_REQ, p, size);
    p += len; size -= len;
    len = pack_smanet2_data(p, size, smanet2getBT, sizeof(smanet2getBT));
    p += len; size -= len;
    if(send_packet(comms.snd_buf, p - comms.snd_buf)) {
        /* Wait for the correct answer */
        while(bytes_read = read_bt(comms.rcv_buf, sizeof(comms.rcv_buf))) {
            cmd = get_header_cmd(comms.rcv_buf, bytes_read);
            if(cmd == CMD_BT_SIGNAL_RSP)
                break;
        }
        if (cmd != CMD_BT_SIGNAL_RSP) {
            printf("No valid response from handle_get_signal_strength\n");
            return 1;
        }
    }
    else {
        if (config.verbose)
          printf("Could not send data of handle_get_signal_strength\n");
        return 1;
    }
    comms.signal = (int)(payload[IDX_BT_SIGNAL]/2.55);          
    if(config.verbose)
      printf("Bluetooth signal strength: %d \%\n", comms.signal);
    return 0;
}

/*******************************************
Function handle_logon - Logon at the SunnyBoy
uses globals: comms
returns: pointer directly after the copied bytes
*******************************************/
int handle_logon(void) {
    unsigned char *p = comms.snd_buf;
    int           i, len, bytes_read, cmd, logon_failed, size=sizeof(comms.snd_buf);
    char          code;
    unsigned char *payload;
    time_t        cur_time;

    if(config.debug >= 2)
        printf("\nSend Logon\n");
    len = create_header(CMD_DATA, p, size);
    p += len; size -= len;
    len = build_data_packet(p, size, 0x0e, 0xa0, 0, 0x01, 0x01);
    p += len; size -= len;
    len = pack_smanet2_data(p, size, smanet2logon, sizeof(smanet2logon));
    p += len; size -= len;
    cur_time = time(NULL);
    /* Add it three times to the buffer */
    len = pack_smanet2_data(p, size, (unsigned char *)&cur_time, sizeof(cur_time));
    p += len; size -= len;
    len = pack_smanet2_data(p, size, fourzeros, sizeof(fourzeros));
    p += len; size -= len;
    /* Encode the password */
    for (i = 0; i < sizeof(config.password); i++) {
      code = (config.password[i] + 0x88) % 0xff;
      len = pack_smanet2_data(p, size, &code, 1);
      p += len; size -= len;
    }
    len = add_fcs_checksum(p, size);
    p += len; size -= len;
    if(send_packet(comms.snd_buf, p - comms.snd_buf)) {
        /* Wait for the correct answer */
        while(bytes_read = read_bt(comms.rcv_buf, sizeof(comms.rcv_buf))) {
            payload = check_header(comms.rcv_buf, bytes_read);
            cmd = get_header_cmd(comms.rcv_buf, bytes_read);
            if(cmd == CMD_DATA)
                break;
        }
        if (cmd != CMD_DATA) {
            printf("No valid response from handle_logon\n");
            return 1;
        }
    }
    else {
        if (config.verbose)
            printf("Could not send data of handle_logon\n");
        return 1;
    }
    /* Check if logon succeeded */
    logon_failed = payload[IDX_LOGONFAIL];          
    if(logon_failed) {
        if (config.verbose)
            printf("Logon failed, check password\n");
        return 1;
    }
    if (config.verbose)
        printf("Logon succeeded\n");
    return 0;
}

/*******************************************
Function handle_set_time - Set the time of the converter (needed for it's internal processing)
uses globals: comms
returns: pointer directly after the copied bytes

NOTE: This function works, but needs a special unknown code we cannot ask from the inverter.
It is not necessary for the functionality of this software, hence we don'nt use this
*******************************************/
int handle_set_time(void) {
    unsigned char *p = comms.snd_buf;
    int           i, len, bytes_read, cmd, logon_failed, size=sizeof(comms.snd_buf);
    unsigned char *payload;
    time_t        cur_time;
    struct tm     *tm_time;

    if(config.debug >= 2)
        printf("\nSend SetTime\n");
    len = create_header(CMD_DATA, p, size);
    p += len; size -= len;
    len = build_data_packet(p, size, 0x10, 0xa0, 0, 0, 0);
    p += len; size -= len;
    len = pack_smanet2_data(p, size, smanet2set_time, sizeof(smanet2set_time));
    p += len; size -= len;
    /* Determine the epoch time in reverse hexadecimal format */
    cur_time = time(NULL);
    /* Add it three times to the buffer */
    len = pack_smanet2_data(p, size, (unsigned char *)&cur_time, sizeof(cur_time));
    p += len; size -= len;
    len = pack_smanet2_data(p, size, (unsigned char *)&cur_time, sizeof(cur_time));
    p += len; size -= len;
    len = pack_smanet2_data(p, size, (unsigned char *)&cur_time, sizeof(cur_time));
    p += len; size -= len;
    /* Add the timezone in seconds */
    tm_time = localtime(&cur_time);
    len = pack_smanet2_data(p, size, (unsigned char *)&tm_time->tm_gmtoff, 4);
    p += len; size -= len;
    len = pack_smanet2_data(p, size, smanet2set_time2, sizeof(smanet2set_time2));
    p += len; size -= len;
    len = pack_smanet2_data(p, size, long_one, sizeof(long_one));
    p += len; size -= len;
    len = add_fcs_checksum(p, size);
    p += len; size -= len;
    if(send_packet(comms.snd_buf, p - comms.snd_buf)) {
#if 0
        /* NOTE: It seems there is no answer required */
        /* Wait for the correct answer */
        while(bytes_read = read_bt(comms.rcv_buf, sizeof(comms.rcv_buf))) {
            payload = check_header(comms.rcv_buf, bytes_read);
            cmd = get_header_cmd(comms.rcv_buf, bytes_read);
            if(cmd == CMD_DATA)
                break;
        }
        if (cmd != CMD_DATA) {
            printf("No valid response from handle_set_time\n");
            return 1;
        }
#endif
    }
    else {
        if (config.verbose)
            printf("Could not send data of handle_set_time\n");
        return 1;
    }
    if (config.verbose)
        printf("Set Inverter time to: %04d-%02d-%02d %02d:%02d:%02d (%d)\n",1900+tm_time->tm_year, tm_time->tm_mon,
               tm_time->tm_mday, tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec, cur_time);
    return 0;
}

/*******************************************
Function handle_total_wh - Get the total Wh so far
uses globals: comms
returns: pointer directly after the copied bytes
*******************************************/
int  handle_total_wh(void) {
    unsigned char *p = comms.snd_buf;
    int           len, size=sizeof(comms.snd_buf);
    unsigned char *payload;
    struct tm     *tm_time;

    if(config.debug >= 2)
        printf("\nSend Total Wh request\n");
    len = create_header(CMD_DATA, p, size);
    p += len; size -= len;
    len = build_data_packet(p, size, 0x09, 0xa0, 0, 0, 0 );
    p += len; size -= len;
    len = pack_smanet2_data(p, size, smanet2totalWh, sizeof(smanet2totalWh));
    p += len; size -= len;
    len = add_fcs_checksum(p, size);
    p += len; size -= len;
    payload = retry_send_receive(p-comms.snd_buf, "handle_total_wh");
    if(!payload)
      return -1;
    /* get the WattHour from this message */
    memcpy(&results.datetime, &payload[IDX_DATETIME], 4);
    memcpy(&results.Wh, &payload[IDX_VALUE], 3);
// TEMPORARY!!! Debug info
if(results.Wh < 0 || results.Wh > 1000000) {  /* More than 1000 kWh is not realistic, currently */
  printf(" Foute waarde voor Wh: %d\n",results.Wh);
  tm_time = localtime(&results.datetime);
  printf("gelezen datetime: %04d-%02d-%02d %02d:%02d:%02d (%x)\n",1900+tm_time->tm_year, tm_time->tm_mon,
  tm_time->tm_mday, tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec, results.datetime);
  dump_hex("Sent package", comms.snd_buf, p - comms.snd_buf, 1);
  dump_hex("Received package", comms.rawrcv_buf, comms.rawrcv_buf_size, 1);
  return -1;
}
    if(config.debug) {
      printf("Total Wh: %lu ( %x )\n",results.Wh, results.Wh);
      tm_time = localtime(&results.datetime);
      printf("datetime: %04d-%02d-%02d %02d:%02d:%02d (%x)\n",1900+tm_time->tm_year, tm_time->tm_mon,
               tm_time->tm_mday, tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec, results.datetime);
    } else if (config.verbose)
      printf("Total kWh: %.3f\n",(float)results.Wh/1000);
    return 0;
}

/*******************************************
Function handle_cur_w - Get the current Watts
uses globals: comms
returns: pointer directly after the copied bytes
*******************************************/
int  handle_cur_w(void) {
    unsigned char *p = comms.snd_buf;
    int           len, size=sizeof(comms.snd_buf);
    unsigned char *payload;
    struct tm     *tm_time;

    if(config.debug >= 2)
        printf("\nSend Current Watt request\n");
    len = create_header(CMD_DATA, p, size);
    p += len; size -= len;
    len = build_data_packet(p, size, 0x09, 0xa1, 0, 0, 0 );
    p += len; size -= len;
    len = pack_smanet2_data(p, size, smanet2curWatt, sizeof(smanet2curWatt));
    p += len; size -= len;
    len = add_fcs_checksum(p, size);
    p += len; size -= len;
    payload = retry_send_receive(p-comms.snd_buf, "handle_cur_w");
    if(!payload)
      return -1;
    /* get the Watt from this message */
    memcpy(&results.datetime, &payload[IDX_DATETIME], 4);
    memcpy(&results.W, &payload[IDX_VALUE], 3);
// TEMPORARY!!! Debug info
if(results.W < 0 || results.W > 10000) {  /* More than 10 kW is not realistic currently */
  printf(" Foute waarde voor W: %d\n",results.Wh);
  tm_time = localtime(&results.datetime);
  printf("gelezen datetime: %04d-%02d-%02d %02d:%02d:%02d (%x)\n",1900+tm_time->tm_year, tm_time->tm_mon,
  tm_time->tm_mday, tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec, results.datetime);
  dump_hex("Sent package", comms.snd_buf, p - comms.snd_buf, 1);
  dump_hex("Received package", comms.rawrcv_buf, comms.rawrcv_buf_size, 1);
  return -1;
}
    if(config.debug) {
      printf("Current Watt: %lu ( %x )\n",results.W, results.W);
      tm_time = localtime(&results.datetime);
      printf("datetime: %04d-%02d-%02d %02d:%02d:%02d (%x)\n",1900+tm_time->tm_year, tm_time->tm_mon,
               tm_time->tm_mday, tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec, results.datetime);
    } else if (config.verbose)
      printf("Current kW: %.3f\n",(float)results.W/1000);
    return 0;
}

/*******************************************
Function handle_net_voltage - Get the Net Voltage
uses globals: comms
returns: pointer directly after the copied bytes
*******************************************/
int  handle_net_voltage(void) {
    unsigned char *p = comms.snd_buf;
    int           len, size=sizeof(comms.snd_buf);
    unsigned char *payload;
    struct tm     *tm_time;

    if(config.debug >= 2)
        printf("\nSend Net Voltage request\n");
    len = create_header(CMD_DATA, p, size);
    p += len; size -= len;
    len = build_data_packet(p, size, 0x09, 0xa1, 0, 0, 0 );
    p += len; size -= len;
    len = pack_smanet2_data(p, size, smanet2netVolt, sizeof(smanet2netVolt));
    p += len; size -= len;
    len = add_fcs_checksum(p, size);
    p += len; size -= len;
    payload = retry_send_receive(p-comms.snd_buf, "handle_net_voltage");
    if(!payload)
      return -1;
    /* get the Volt from this message */
    memcpy(&results.datetime, &payload[IDX_DATETIME], 4);
    memcpy(&results.netVolt, &payload[IDX_VALUE], 3);
    if(config.debug) {
      printf("Net Volt: %.2f ( %x )\n",(float)results.netVolt/100, results.netVolt);
      tm_time = localtime(&results.datetime);
      printf("datetime: %04d-%02d-%02d %02d:%02d:%02d (%x)\n",1900+tm_time->tm_year, tm_time->tm_mon,
               tm_time->tm_mday, tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec, results.datetime);
    } else if (config.verbose)
      printf("Current Net Volt: %.2f\n",(float)results.netVolt/100);
    return 0;
}

/*******************************************
Function handle_net_amp - Get the Net Ampere
uses globals: comms
returns: pointer directly after the copied bytes
*******************************************/
int  handle_net_amp(void) {
    unsigned char *p = comms.snd_buf;
    int           len, size=sizeof(comms.snd_buf);
    unsigned char *payload;
    struct tm     *tm_time;

    if(config.debug >= 2)
        printf("\nSend Net Ampere request\n");
    len = create_header(CMD_DATA, p, size);
    p += len; size -= len;
    len = build_data_packet(p, size, 0x09, 0xa1, 0, 0, 0 );
    p += len; size -= len;
    len = pack_smanet2_data(p, size, smanet2netAmp, sizeof(smanet2netAmp));
    p += len; size -= len;
    len = add_fcs_checksum(p, size);
    p += len; size -= len;
    payload = retry_send_receive(p-comms.snd_buf, "handle_net_amp");
    if(!payload)
      return -1;
    /* get the Ampere from this message */
    memcpy(&results.datetime, &payload[IDX_DATETIME], 4);
    memcpy(&results.netAmpere, &payload[IDX_VALUE], 3);
    if(config.debug) {
      printf("Net milli-Ampere: %lu ( %x )\n",results.netAmpere, results.netAmpere);
      tm_time = localtime(&results.datetime);
      printf("datetime: %04d-%02d-%02d %02d:%02d:%02d (%x)\n",1900+tm_time->tm_year, tm_time->tm_mon,
               tm_time->tm_mday, tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec, results.datetime);
    } else if (config.verbose)
      printf("Net Ampere: %.3f\n",(float)results.netAmpere/1000);
    return 0;
}

/*******************************************
Function handle_net_freq - Get the Net Freq
uses globals: comms
returns: pointer directly after the copied bytes
*******************************************/
int  handle_net_freq(void) {
    unsigned char *p = comms.snd_buf;
    int           len, size=sizeof(comms.snd_buf);
    unsigned char *payload;
    struct tm     *tm_time;

    if(config.debug >= 2)
        printf("\nSend Net Freq request\n");
    len = create_header(CMD_DATA, p, size);
    p += len; size -= len;
    len = build_data_packet(p, size, 0x09, 0xa0, 0, 0, 0 );
    p += len; size -= len;
    len = pack_smanet2_data(p, size, smanet2netFreq, sizeof(smanet2netFreq));
    p += len; size -= len;
    len = add_fcs_checksum(p, size);
    p += len; size -= len;
    payload = retry_send_receive(p-comms.snd_buf, "handle_net_freq");
    if(!payload)
      return -1;
    /* get the Freq from this message */
    memcpy(&results.datetime, &payload[IDX_DATETIME], 4);
    memcpy(&results.netFreq, &payload[IDX_VALUE], 3);
    if(config.debug) {
      printf("Net Freq: %.2f ( %x )\n",(float)results.netFreq/100, results.netFreq);
      tm_time = localtime(&results.datetime);
      printf("datetime: %04d-%02d-%02d %02d:%02d:%02d (%x)\n",1900+tm_time->tm_year, tm_time->tm_mon,
               tm_time->tm_mday, tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec, results.datetime);
    } else if (config.verbose)
      printf("Net Freq: %.2f\n",(float)results.netFreq/100);
    return 0;
}

/*******************************************
Function handle_pv_volt - Get the PV system volt
uses globals: comms
returns: pointer directly after the copied bytes
*******************************************/
int  handle_pv_volt(void) {
    unsigned char *p = comms.snd_buf;
    int           len, size=sizeof(comms.snd_buf);
    unsigned char *payload;
    struct tm     *tm_time;

    if(config.debug >= 2)
        printf("\nSend PV Volt request\n");
    len = create_header(CMD_DATA, p, size);
    p += len; size -= len;
    len = build_data_packet(p, size, 0x09, 0xe0, 0, 0, 0 );
    p += len; size -= len;
    len = pack_smanet2_data(p, size, smanet2pvVolt, sizeof(smanet2pvVolt));
    p += len; size -= len;
    len = add_fcs_checksum(p, size);
    p += len; size -= len;
    payload = retry_send_receive(p-comms.snd_buf, "handle_pv_volt");
    if(!payload)
      return -1;
    /* get the Volt from this message */
    memcpy(&results.datetime, &payload[IDX_DATETIME], 4);
    memcpy(&results.pvVolt, &payload[IDX_VALUE], 3);
    if(config.debug) {
      printf("PV Volt: %.2f ( %x )\n",(float)results.pvVolt/100, results.pvVolt);
      tm_time = localtime(&results.datetime);
      printf("datetime: %04d-%02d-%02d %02d:%02d:%02d (%x)\n",1900+tm_time->tm_year, tm_time->tm_mon,
               tm_time->tm_mday, tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec, results.datetime);
    } else if (config.verbose)
      printf("PV Volt: %.2f\n",(float)results.pvVolt/100);
    return 0;
}

/*******************************************
Function handle_pv_amp - Get the PV Ampere
uses globals: comms
returns: pointer directly after the copied bytes
*******************************************/
int  handle_pv_amp(void) {
    unsigned char *p = comms.snd_buf;
    int           len, size=sizeof(comms.snd_buf);
    unsigned char *payload;
    struct tm     *tm_time;

    if(config.debug >= 2)
        printf("\nSend PV Ampere request\n");
    len = create_header(CMD_DATA, p, size);
    p += len; size -= len;
    len = build_data_packet(p, size, 0x09, 0xe0, 0, 0, 0 );
    p += len; size -= len;
    len = pack_smanet2_data(p, size, smanet2pvAmpere, sizeof(smanet2pvAmpere));
    p += len; size -= len;
    len = add_fcs_checksum(p, size);
    p += len; size -= len;
    payload = retry_send_receive(p-comms.snd_buf, "handle_pv_amp");
    if(!payload)
      return -1;
    /* get the Ampere from this message */
    memcpy(&results.datetime, &payload[IDX_DATETIME], 4);
    memcpy(&results.pvAmpere, &payload[IDX_VALUE], 3);
    if(config.debug) {
      printf("PV milli-Ampere: %lu ( %x )\n",results.pvAmpere, results.pvAmpere);
      tm_time = localtime(&results.datetime);
      printf("datetime: %04d-%02d-%02d %02d:%02d:%02d (%x)\n",1900+tm_time->tm_year, tm_time->tm_mon,
               tm_time->tm_mday, tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec, results.datetime);
    } else if (config.verbose)
      printf("PV Ampere: %.2f\n",(float)results.pvAmpere/100);
    return 0;
}

/*******************************************
Function retry_send_receive - send data-request and receive respons, retry as necessary
  bytes_send : amount of data to send (buffer in comms.snd_buf)
  log_str : string to use for logging errors
uses globals: comms
returns: pointer directly after the copied bytes
*******************************************/
char *retry_send_receive(int bytes_send, char *log_str) {
    int           bytes_read, cmd, data_chk, fcs_retry=4;
    unsigned char *payload;

    while(fcs_retry--) {
        if(send_packet(comms.snd_buf, bytes_send)) {
            /* Wait for the correct answer */
            bytes_read = read_packet();
            if(bytes_read > 0)  /* Data error, checksum or missing sync, force a retry */
            payload = check_header(comms.rcv_buf, bytes_read);
            cmd = get_header_cmd(comms.rcv_buf, bytes_read);
            data_chk = payload[IDX_DATA_CHK];
            if(cmd == CMD_DATA) {
                if(data_chk==DATA_CHK)
                    break;
                else
// TEMPORARY!!! Debug info
printf("Invalid data_chk(%02x), retrying\n", data_chk);
            }
        }
        else {
            printf("Could not send data of %s\n", log_str);
        }
        sleep(3); /* Wait 3 seconds before trying again */
    }
    if (cmd != CMD_DATA || data_chk != DATA_CHK) {
        printf("No valid response from %s\n", log_str);
        return NULL;
    }
    return payload;
}

/*******************************************
Function build_data_packet - Pack a smanet 2 message, translating bytes as necessary
  buf   : destination buffer
  size  : size of the buffer.
  c1    : 
  c2    : 
  pc    : 
  a     :
  b     :
  c     :
returns: Amount of bytes added to buffer
*******************************************/
int build_data_packet(unsigned char *buf, int size, unsigned char c1, unsigned char c2,
                      unsigned char a, unsigned char b, unsigned char c) {
    unsigned char *p = buf;
    int len;

    *p++ = HDLC_SYNC; /* exclude from checksum */
    size--;
    len = pack_smanet2_data(p, size, smanet2dataheader, sizeof(smanet2dataheader));
    p += len; size -= len;
    len = pack_smanet2_data(p, size, &c1, 1);
    p += len; size -= len;
    len = pack_smanet2_data(p, size, &c2, 1);
    p += len; size -= len;
    len = pack_smanet2_data(p, size, sixff, sizeof(sixff));
    p += len; size -= len;
    len = pack_smanet2_data(p, size, &a, 1);
    p += len; size -= len;
    len = pack_smanet2_data(p, size, &b, 1);
    p += len; size -= len;
    /* Some software uses a "unknown secret inverter code", but six ff bytes works too */
    len = pack_smanet2_data(p, size, sixff, sizeof(sixff));
    p += len; size -= len;
    len = pack_smanet2_data(p, size, fourzeros, 1);    /* only need one 0x0, but must be in checksum */
    p += len; size -= len;
    len = pack_smanet2_data(p, size, &c, 1);
    p += len; size -= len;
    len = pack_smanet2_data(p, size, fourzeros, sizeof(fourzeros));
    p += len; size -= len;
    len = pack_smanet2_data(p, size, &comms.packet_send_counter, 1);
    p += len; size -= len;
    /* Check the packet counter */
    if (comms.packet_send_counter++ > 75)
        comms.packet_send_counter = 1;
    return p - buf;
}


/*******************************************
Function add_fcs_checksum - Add an fcs checksum
  buf   : destination buffer
  size  : size of the buffer.
returns: Amount of bytes added to buffer
*******************************************/
int add_fcs_checksum(unsigned char *buf, int size) {
    unsigned char *p = buf;
    if(size > 3) {
      comms.fcs_checksum = comms.fcs_checksum ^ 0xffff;
      *p++ = comms.fcs_checksum & 0x00ff;
      *p++ = (comms.fcs_checksum >> 8) & 0x00ff;
      *p++ = HDLC_SYNC;
    }
    return p - buf;
}

/*******************************************
Function pack_smanet2_data - Pack a smanet 2 message, translating bytes as necessary
  buf   : destination buffer
  size  : size of the buffer.
  src   : source buffer
  len   : length of source buffer
returns: Amount of bytes added to destination buffer
*******************************************/
int pack_smanet2_data(unsigned char *buf, int size, unsigned char *src, unsigned int num) {
    unsigned char *p = buf;

    while (num-- && size--) {
        comms.fcs_checksum = (comms.fcs_checksum >> 8) ^ (fcstab[(comms.fcs_checksum ^ *src) & 0xff]);
        if (*src == HDLC_ESC || *src == HDLC_SYNC || *src == 0x11 || *src == 0x12 || *src == 0x13) {
            *p++ = HDLC_ESC;
            *p++ = *src++ ^ 0x20;
        } else
            *p++ = *src++;
    }
    return p-buf;
}

/*******************************************
Function read_packet - Read a packet from BlueTooth, translating escape characters and checksum
returns: Amount of bytes read, or -1 if an error occurs
*******************************************/
int read_packet() {
    int bytes_read, bytes_in_packet, i, sync_found=0;
    unsigned int fcs_checksum, msg_checksum;
    unsigned char *from, *src, *dest; /* Buffer pointers for translating data */
    packet_hdr *hdr;

    bytes_read = read_bt(comms.rcv_buf, sizeof(comms.rcv_buf));
/* TEMPORARY */
memcpy(comms.rawrcv_buf, comms.rcv_buf, sizeof(comms.rawrcv_buf));
comms.rawrcv_buf_size = bytes_read;
    bytes_in_packet = bytes_read;
    hdr = (packet_hdr *)comms.rcv_buf;
    /* If we received a data package (CMD 01), do some checking */
    if(hdr->cmd == CMD_DATA) {
        if(comms.rcv_buf[bytes_read-1] != HDLC_SYNC) {
            printf("Invalid data message, missing 0x7e at end\n");
            return -1;
        }
        /* Find out where translation and checksumming should start */
        from = comms.rcv_buf + PKT_OFF_DATASTART;
        while((*from != HDLC_SYNC) && (from < comms.rcv_buf+bytes_read ))
          from++;
        if(from < comms.rcv_buf+bytes_read) {
            /* Skip the SYNC character itself */
            from++;
            /* Translate all escaped characters */
            src = from;
            dest = from;
            while(src < comms.rcv_buf+bytes_read) {
                if( *src == HDLC_ESC ) {    /*Found escape character. Need to convert*/
                    src++;                  /* Skip the escape character */
                    *dest++ = *src++^0x20;  /* and Xor the following character with 0x020 */
                    bytes_in_packet--;
                }
                else
                  *dest++ = *src++;
            }
            /* Calculate the checksum */
            fcs_checksum = 0xffff;
            src = from;
            while(src < comms.rcv_buf+bytes_in_packet-3) {
                fcs_checksum = (fcs_checksum >> 8) ^ (fcstab[(fcs_checksum ^ *src++) & 0xff]);
            }
        }
        if( config.debug >= 3 )
          dump_hex("Translated package", comms.rcv_buf, bytes_in_packet, 0);
        msg_checksum = (comms.rcv_buf[bytes_in_packet-2]<<8) + comms.rcv_buf[bytes_in_packet-3];
        fcs_checksum = fcs_checksum ^ 0xffff;
        if(msg_checksum != fcs_checksum) {
            printf("Checksum failed: calculated %04x instead of %04x\n", fcs_checksum, msg_checksum);
            return -1;
        }
    }
    return bytes_in_packet;
}

/*******************************************
Function send_packet - Send a smanet_packet, adding length and checksum
  buf   : buffer
  len   : length of buffer
*******************************************/
int send_packet(unsigned char *buf, int len) {
    packet_hdr *hdr;

    /* Fill in the length */
    hdr = (packet_hdr *)buf;
    hdr->len = len;
    hdr->chksum = hdr->sync ^ buf[PKT_OFF_LEN1] ^ buf[PKT_OFF_LEN2];
    return write_bt(buf, len);
}

/*******************************************
Function check_header - Perform some basic checking on the header, to see if it is valid
  buf   : buffer to be dumped in headecimal format
  len   : length of data in this buffer
returns: pointer to payload if header ok, NULL if header false
*******************************************/
unsigned char *check_header(unsigned char *buf, int len) {
    packet_hdr *hdr;
    int chksum;
    char addr[19] = { 0 };

    hdr = (packet_hdr *)buf;
    if(hdr->sync != HDLC_SYNC) {
        if (config.verbose) {
            printf("WARNING: Start Of Message is %02x instead of %02x\n", hdr->sync, HDLC_SYNC);
            printf("pkt  checksum: 0x%x, calc checksum: 0x%x\n", hdr->chksum, chksum);
        }
        return NULL; 
    }
    chksum = hdr->sync ^ buf[PKT_OFF_LEN1] ^ buf[PKT_OFF_LEN2];
    if (hdr->chksum != chksum) {
        if (config.verbose) {
            printf("WARNING: checksum mismatch\n");
            printf("pkt  checksum: 0x%x, calc checksum: 0x%x\n", hdr->chksum, chksum);
        }
        return NULL; 
    }
    return buf + PKT_OFF_DATASTART;
}

/*******************************************
Function get_header_cmd - Read the header, and give back te command
  buf   : buffer to be dumped in headecimal format
  len   : length of data in this buffer
returns: pointer to payload if header ok, NULL if header false
*******************************************/
unsigned int get_header_cmd(unsigned char *buf, int len) {
    packet_hdr *hdr;

    if(check_header(buf, len)) {
      hdr = (packet_hdr *)buf;
      return(hdr->cmd);
    }
    return 0; /* Failure: return an invalid command */
}


/*******************************************
Function create_header - fill the given buffer with the header, and return a pointer to the payload
  cmd       : Command for this package
  buf       : buffer to be processed
  size      : size of the buffer
returns: pointer to start of payload
*******************************************/
int create_header(int cmd, unsigned char *buf, int size) {
    packet_hdr * hdr;
 
    comms.fcs_checksum = 0xffff;    /* Initialise a fresh checksum */
    hdr = (packet_hdr *) buf;
    hdr->sync    = HDLC_SYNC;
    hdr->len    = 0;        /* Filled in later */
    hdr->chksum = 0;        /* Filled in later */
    hdr->cmd    = cmd;
    memcpy(&hdr->src_addr, &comms.src_addr.rc_bdaddr, sizeof(bdaddr_t));
    memcpy(&hdr->dst_addr, &comms.dst_addr.rc_bdaddr, sizeof(bdaddr_t));
    return PKT_OFF_DATASTART;
}


/*******************************************
Function read_bt - Read a buffer from BlueTooth
  buf       : buffer to be dumped in headecimal format
  buf_size  : size of this buffer
returns: Amount of bytes sent
*******************************************/
int read_bt(unsigned char *buf, int buf_size) {
    int bytes_read;
    bytes_read = read(comms.sock, buf, buf_size);
    dump_hex("reading", buf, bytes_read, 0);
    return bytes_read;
}

/*******************************************
Function write_bt - Write a message to bluetooth
  buf       : buffer to be dumped in headecimal format
  length    : length of the message
*******************************************/
int write_bt(unsigned char *buf, int length) {
  int written;
  written = write(comms.sock, buf, length);
  dump_hex("writing", buf, length, 0);
  return written;
}

/*******************************************
Function dump_hex - show a buffer in hexadecimal format, if the debug level is 2 or more
  logstr    : Description of the buffer being dumped
  buf       : buffer to be dumped in headecimal format
  length    : length of the message
  force     : force dumping, even if debug level is insufficient
*******************************************/
int dump_hex(char *logstr, unsigned char *buf, int length, int force) {
    int i;
    if( (force || config.debug >= 2) && length > 0 ) {
        printf( "\n%s: len=%d data=\n", logstr, length);
        for( i=0; i<length; i++ ) {
          if( i%16== 0 ) printf( "%s  %08x: ", (i>0 ? "\n" : ""), i);
          /* Make sure it is not reported as a negative value (starting with ffffff */
          printf( " %02x", buf[i]);
        }
        printf( "\n" );
    }
    return 0;
}

/*******************************************
Function get_device_name : get the devicaname and serial number of the SunnyBeam
  btaddr    : bluetooth address of the SunnyBeam
  name      : buffer for the name
  name_size : size of this buffer
returns: a pointer to the serial number (part of the device name)
affects: global src_addr will be filled with our local bt address
*******************************************/
char *get_device_name(char *name, int name_size) {
    int dev_id, sock;
    struct hci_dev_info di;
    char *serial;


    dev_id = hci_get_route(NULL);

    /* Get the local address */
    if ( hci_devinfo(dev_id, &di) >= 0 ) {
        comms.src_addr.rc_family = AF_BLUETOOTH;
        comms.src_addr.rc_channel = (uint8_t) 1;
        memcpy(&comms.src_addr.rc_bdaddr, &di.bdaddr, sizeof(bdaddr_t));
    }
    sock = hci_open_dev( dev_id );
    if (dev_id < 0 || sock < 0) {
        strcpy(name, "[unknown]");
        perror("could not open sock");
        return NULL;
    }
    memset(name, 0, name_size);
    if(hci_read_remote_name(sock, &comms.dst_addr.rc_bdaddr, name_size, name, 0) < 0) {
        strcpy(name, "[unknown]");
        return NULL;
    }
    else {
      /* retrieve the serial number from the name */
      serial = strrstr(name, "SN");
      if(serial)
        serial += 2;  /* Skip the SN letters */
      if(serial && !*serial)
        serial = NULL;
    }
    close( sock );
    return serial;
}

/*******************************************
Function strrstr : Find the last occurance of s1 in s2
  s1: String to find
  s2: String to be searched
*******************************************/
char *strrstr(char *s1, char *s2) {
    char *sc1, *sc2, *psc1, *ps1;
    if (*s2 == '\0')
        return((char *)s1);
    ps1 = s1 + strlen(s1);
    while(ps1 != s1) {
        --ps1;
        for (psc1 = ps1, sc2 = s2; ; )
            if (*(psc1++) != *(sc2++))
                break;
            else if (*sc2 == '\0')
                return ((char *)ps1);
    }
    return ((char *)NULL);
}

