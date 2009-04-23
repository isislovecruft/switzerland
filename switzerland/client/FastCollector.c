#ifdef WIN32
# define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
#include <signal.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef WIN32
# include <unistd.h>
# include <sys/mman.h>
# include <stdint.h>
# include <sys/wait.h>
#else
# define open _open
# define close _close
# define write _write
# define strdup _strdup
# include <fcntl.h>
# include <tchar.h>

typedef UCHAR  uint8_t;
typedef USHORT uint16_t;
typedef DWORD uint32_t;
#endif

char errbuf[PCAP_ERRBUF_SIZE];

#define PLAYBACK_SLEEP 1000

#define MAX_PACKET_SIZE 1600
//#define PACKETS 25000
long PACKETS = 25000;
#define ENTRY_SIZE sizeof(PacketEntry)
#define BUFFER_SIZE (PACKETS * ENTRY_SIZE)

#define WIN32_CAPTURE_BUFFER (1024 * 1024 * 10)

typedef struct packet_entry {
  uint8_t valid;
  uint8_t padding;
  uint16_t packet_length;
  uint32_t padding2;
  double timestamp;
  char data[MAX_PACKET_SIZE];
} PacketEntry;


static void write_packet(const unsigned char *packet, unsigned short int len, double timestamp);
static void *open_buffer();
static void check_for_drops(pcap_t *pc);
static void catch_control_c();
static void handle_control_c(int);

static char *iface_or_file = NULL; // interface or file name we're capturing from
static int live = 1; // capturing from device (live)?  assume so by default
static int delete_file = 0;

#ifndef WIN32
static char filename[] = "/tmp/tmpXXXXXX";
#else
# define FILENAME_SIZE 512
static TCHAR filename[FILENAME_SIZE];
#endif
static void *mem;
static unsigned int count = 0;
static pcap_t *pc_global = NULL;
static int f_des;

static PacketEntry blank = { 0x00,0x00,0,0,0,{0x00}};

#ifdef WIN32
static void *win32_mmap(const TCHAR *filename)
{
   HANDLE f = CreateFile(filename, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
   HANDLE m;
   void *p;
   if (!f) return NULL;
   m = CreateFileMapping(f, NULL, PAGE_READWRITE, 0, 0, NULL);
   if (!m) { CloseHandle(f); return NULL; }
   p = MapViewOfFile(m, FILE_MAP_READ|FILE_MAP_WRITE, 0, 0, 0);
   if (!p) { CloseHandle(m); CloseHandle(f); return NULL; }
   return p;
}

static int mkstemp(TCHAR *tmpl)
{
  static TCHAR tmppath[FILENAME_SIZE];
  DWORD dwBufSize = FILENAME_SIZE, dwrv;
  unsigned int urv;
  int ret=-1;
  HANDLE htmp;

  dwrv = GetTempPath(dwBufSize, tmppath);
  if (dwrv > dwBufSize || (dwrv == 0)) {
    fprintf(stderr, "error opening tmpfile\n");
    exit(1);
  }

  urv = GetTempFileName(tmppath, TEXT("fc"), 0, tmpl);
  if (urv == 0) {
    fprintf(stderr, "error opening tmpfile\n");
    exit(1);
  }

  htmp = CreateFile((LPTSTR) filename,
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    NULL,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL);
  if (htmp == INVALID_HANDLE_VALUE) {
      fprintf(stderr, "CreateFile failed (%d)\n", GetLastError());
      exit(1);
  }

  return _open_osfhandle((intptr_t)htmp, O_RDWR|O_BINARY);
}

static void usleep(int us)
{
  if (us > 500)
    Sleep((us+500)/1000);
  else if (us > 0)
    Sleep(1);
  else
    Sleep(0);
}
#endif

static void *open_buffer()
// Create a tempfile and mmap() it into "mem"
{
  int n;
  f_des = mkstemp(filename);
  if (f_des == -1) {
    fprintf(stderr, "Error opening tempfile: %s\n", strerror(errno));
    exit(1);
  }
  for (n = 0; n < PACKETS; n++) {
    if (write(f_des, &blank, ENTRY_SIZE) != ENTRY_SIZE) {
      fprintf(stderr, "Error setting up tempfile: %s\n", strerror(errno));
      exit(1);
    }
  }
#ifndef WIN32
  mem = mmap(NULL, BUFFER_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, f_des, 0);
  if (mem == MAP_FAILED) {
    fprintf(stderr, "mmap failed: %s\n", strerror(errno));
     exit(1);
  }
  printf("Tempfile: %s\n", filename);
#else
  close(f_des);
  if (!(mem = win32_mmap(filename))) {
    fprintf(stderr, "mmap failed: %s\n", strerror(errno));
    exit(1);
  }
  _tprintf(TEXT("Tempfile: %s\n"), filename);
#endif
  fflush(stdout);
  return mem;
}

static unsigned int pos = 0;
static void write_packet(const unsigned char *packet, unsigned short int len, double timestamp)
// Check that we haven't overflowed the mmap()ed buffer, then write
// the next packet into it
{
  PacketEntry *entry = (PacketEntry *) ((uint8_t*)mem + pos);
  if (entry->valid != 0x00) {
    // Oh no, the field we want to write in has a packet in it
    fprintf(stderr, "ERROR: FAILED TO KEEP BUFFER FROM OVERFLOWING\n");
    fprintf(stderr, "(After capturing %d packets)\n", count);
     exit(1);
  }
  if (len > MAX_PACKET_SIZE) {
    fprintf(stderr, "ERROR: Cannot handle a packet of size %d\n", len);
    fprintf(stderr, "(Check for Large Segment Offloading on gigabit Ethernet cards,\n");
    fprintf(stderr, "and avoid loopback devices)\n");
    exit(1);
  }
  entry->packet_length = len;
  entry->timestamp = timestamp;
  memcpy(entry->data, packet, len);
  entry->valid = 0xff;
  pos = (pos + sizeof(PacketEntry)) % BUFFER_SIZE;
}

static pcap_t *start_capture(char *dev_or_file)
// Here we configure libpcap to do its thing..
{
    pcap_t *pc;
    struct bpf_program filter;
    struct stat st;

    if (live) { // device
      if (dev_or_file == NULL)
        dev_or_file = pcap_lookupdev(errbuf); // look for device if not given
      if (dev_or_file == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        exit(2);
      }

      pc = pcap_open_live(dev_or_file, MAX_PACKET_SIZE, 0, 1000, errbuf);  
      if (pc == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev_or_file, errbuf);
        exit(2);
      }
#ifdef WIN32
      if (pcap_setbuff(pc, WIN32_CAPTURE_BUFFER) == -1) {
        printf("Error setting Win32 capture buffer:\n%s\n", pcap_geterr(pc));
      }
#endif
    } else { // file
      if (dev_or_file == NULL || stat(dev_or_file, &st) != 0) {
        fprintf(stderr, "Can't open capture file %s\n", dev_or_file ? dev_or_file : "(none)");
        exit(2);
      }

      pc = pcap_open_offline(dev_or_file, errbuf);  
      if (pc == NULL) {
        fprintf(stderr, "Couldn't open capture file: %s\n", errbuf);
        exit(2);
      }
    }

    assert(pc && "pc shouldn't be null here");
    
    // Open in chaste mode
    if (pcap_compile(pc, &filter, "ip", 0, -1) == -1){
      fprintf(stderr, "Filter compile failed:\n%s\n", pcap_geterr(pc));
      exit(1);
    }
    if (pcap_setfilter(pc, &filter) == -1) {
      fprintf(stderr, "Set filter failed:\n%s\n", pcap_geterr(pc));
      exit(1);
    }

    printf("Initialized sniff on %s \n",dev_or_file);
    return pc;
}


static void handle_packet(u_char *user_data, const struct pcap_pkthdr *header, const u_char *data){
  double ts;
  ts =  header->ts.tv_sec + header->ts.tv_usec * (1.0 / 1000000.0);
  write_packet(data,(unsigned short int) header->len,ts);
  if (!live) usleep(PLAYBACK_SLEEP);
  count ++;
}

#define CHECK_FREQ 30

static void main_loop(pcap_t *pc) {
  int ret = 13;
  unsigned int last_count = 0;
  while (1) {
    last_count = count;
    ret = pcap_loop(pc, CHECK_FREQ, &handle_packet, NULL);
    if (!live && count == last_count) // all done?
      handle_control_c(0);
    if (ret == -1) {
      fprintf(stderr, "Dispatch error:\n%s\n", pcap_geterr(pc));
      exit(1);
    }
    check_for_drops(pc);
  }
}

static void check_for_drops(pcap_t *pc)
{
  static struct pcap_stat stats;
  if (!live) return; // stats only available for live captures
  if (pcap_stats(pc, &stats) == -1) {
    fprintf(stderr, "Statistics unobtainable:\n%s\n", pcap_geterr(pc));
    exit(1);
  }
  if (stats.ps_drop != 0) {
    fprintf(stderr, "ERROR: OPERATING SYSTEM DROPPED %d PACKETS (after capturing %d)\n", \
            stats.ps_drop, count);
    exit(1);
  }

}

static void handle_control_c(int signum) {
  check_for_drops(pc_global);
  printf("No packets were lost during capture.\n");
  exit(0);
}

static void catch_control_c() {
  signal(SIGINT, handle_control_c);
  signal(SIGTERM, handle_control_c);
}

static void get_args(int argc, char **argv) {
  if (argc == 0) return;
  for (++argv, --argc; argc; ++argv, --argc) {
    char *arg = *argv;
    if (arg[0] == '-') {
      switch (arg[1]) {
        case 'i': live = 1; break;
        case 'f': live = 0; break;
        case 'b': 
          if (sscanf(arg+2, "%ld", &PACKETS) != 1) {
            fprintf(stderr, "use -bPACKETS, eg -b100000\n");
            exit(1);
          }
          break;
        case 'd': delete_file = 1; break;
        default:
          fprintf(stderr, "invalid/unrecognized argument: -%c\n", *arg);
          exit(1);
          break;
      }
    } else {
      iface_or_file = strdup(*argv);
    }
  }
}

void cleanup() {
  if (delete_file && 0 != unlink(filename)) {
    perror(filename);
  }
}

int main(int argc,char *argv[])
{
  assert(sizeof(PacketEntry) == 1616 &&
      "Your compiler didn't pack struct packet_entry like we foolishly expected, bailing");
  get_args(argc, argv);
  open_buffer();
  atexit(cleanup);
  pc_global = start_capture(iface_or_file);
  printf("pcap_datalink: %d\n", pcap_datalink(pc_global));
  //fprintf(stderr,"buffer size %ld\n", PACKETS);
  fflush(stdout);
  catch_control_c();
  main_loop(pc_global);
  return 0;
}

