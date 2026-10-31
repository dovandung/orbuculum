/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * Post mortem monitor for parallel trace
 * ======================================
 *
 */

#include <stdarg.h>
#include <inttypes.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>

#include "git_version_info.h"
#include "generics.h"
#include "nw.h"
#include "traceDecoder.h"
#include "oflow.h"
#include "loadelf.h"
#include "sio.h"
#include "stream.h"

#define REMOTE_SERVER       "localhost"

enum Prot { PROT_OFLOW, PROT_ETM, PROT_UNKNOWN };
const char *protString[] = {"OFLOW", "ETM", NULL};

#define SCRATCH_STRING_LEN  (65535)     /* Max length for a string under construction */
//#define DUMP_BLOCK
#define DEFAULT_PM_BUFLEN_K (32)        /* Default size of the Postmortem buffer */
#define DEFAULT_WINDOW_K    (256)       /* Default amount of the buffer decoded at a time */
#define MAX_PM_BUFLEN_K     (2097151)   /* Largest buffer whose length in bytes fits an int */
#define WINDOWS_KEPT_EACH_SIDE (2)      /* Decoded windows kept before and after the cursor's one */
#define ISYNC_SEARCH_BYTES  (65536)     /* How far after an A-sync to look for the first I-sync */
#define MAX_TAGS            (10)        /* How many tags we will allow */

/* Hold-at-function (-x): live flow tracking */
#define DIS_CACHE_SIZE      (1 << 16)   /* Disassembly cache for building the display (addr >> 1) */
#define OPTEXT_MIN_ALLOC    (4096)      /* Display lines array starts at this and doubles */
#define HOLD_ICACHE_SIZE    (1 << 16)   /* Instruction info cache entries (direct mapped on addr >> 1) */
#define HOLD_MAX_RANGES     (32)        /* Max code ranges -x watches (same-name functions, inlined copies) */
#define HOLD_TAIL_BYTES     (4)         /* Trace bytes kept after the trigger, so the entry is shown */
                                        /* (one ETM atom byte covers up to ~16 instructions)         */

#define INTERVAL_TIME_MS    (1000)      /* Intervaltime between acculumator resets */
#define HANG_TIME_MS        (200)       /* Time without a packet after which we dump the buffer */
#define TICK_TIME_MS        (100)       /* Time intervals for screen updates and keypress check */

/* Record for options, either defaults or from command line */
struct Options
{
    /* Source information */
    char *file;                         /* File host connection */
    bool fileTerminate;                 /* Terminate when file read isn't successful */
    char *deleteMaterial;               /* Material to delete off front end of filenames */
    bool demangle;                      /* Indicator that C++ should be demangled */

    char *elffile;                      /* File to use for symbols etc. */
    char *odoptions;                    /* Options to pass directly to objdump */

    int buflen;                         /* Length of post-mortem buffer, in bytes */
    int window;                         /* Amount of the buffer decoded at a time, in bytes */
    int tag;                            /* which OFLOW stream are we decoding? */
    int port;                           /* Source information */
    char *server;
    enum Prot commProt;
    bool mono;                          /* Supress colour in output */
    enum TRACEprotocol traceProt;       /* Encoding protocol to use */
    bool noAltAddr;                     /* Flag to *not* use alternate addressing */
    char *openFileCL;                   /* Command line for opening refernced file */

    bool withDebugText;                 /* Include debug text (hidden in) output...screws line numbering a bit */
    char *holdAt;                       /* Function name (or 0x address) to hold at, or NULL */
} _options =
{
    .port      = OFCLIENT_SERVER_PORT,
    .server    = REMOTE_SERVER,
    .demangle  = true,
    .traceProt = TRACE_PROT_ETM35,
    .tag       = 2,
    .buflen    = DEFAULT_PM_BUFLEN_K * 1024,
    .window    = DEFAULT_WINDOW_K * 1024
};

/* A block of received data */
struct dataBlock
{
    ssize_t fillLevel;
    uint8_t buffer[TRANSFER_SIZE];
};

/* Materials required to be maintained across callbacks for output construction */
struct opConstruct
{
    uint32_t currentFileindex;           /* The filename we're currently in */
    struct symbolFunctionStore *currentFunctionptr;       /* The function we're currently in */
    uint32_t currentLine;                /* The line we're currently in */
    uint32_t workingAddr;                /* The address we're currently in */
};

/* Maximum depth of call stack, defined Section 5.3 or ARM IHI0064H.a ID120820 */
#define MAX_CALL_STACK (15)

struct RunTime
{
    struct TRACEDecoder i;
    struct OFLOW c;
    const char *progName;               /* Name by which this program was called */

    struct symbol *s;                   /* Symbols read from elf */
    bool     ending;                    /* Flag indicating app is terminating */
    bool     singleShot;                /* Flag indicating take a single buffer then stop */
    uint64_t newTotalBytes;             /* Number of bytes of real data transferred in total */
    uint64_t oldTotalBytes;             /* Old number of bytes of real data transferred in total */
    uint64_t oldTotalIntervalBytes;     /* Number of bytes transferred in previous interval */
    uint64_t oldTotalHangBytes;         /* Number of bytes transferred in previous hang interval */

    uint8_t *pmBuffer;                  /* The post-mortem buffer */
    int wp;                             /* Index pointers for ring buffer */
    int rp;
    /* The buffer is decoded in windows (-W), each starting at an A-sync. wBound[0..wNum-1] are */
    /* the window starts (offsets from rp, ascending), wBound[wNum] the end of the buffer. Only */
    /* windows wFirst..wLast are decoded; wLines[k] is the number of lines of window k.         */
    int64_t *wBound;
    int32_t *wLines;
    int wAlloc;
    int wNum;
    int wFirst;
    int wLast;

    struct sioline *opText;             /* Text of the output buffer */
    int32_t lineNum;                    /* Current line number in output buffer */
    int32_t numLines;                   /* Number of lines in the output buffer */
    int32_t opTextAlloc;                /* Number of lines allocated in opText */

    /* Disassembly cache: disassembling with capstone for every traced instruction is slow */
    uint32_t dcAddr[DIS_CACHE_SIZE];    /* Address, or NO_ADDRESS if empty */
    char    *dcText[DIS_CACHE_SIZE];    /* Disassembly text (owned by the cache), NULL if none */
    uint32_t dcNew[DIS_CACHE_SIZE];     /* Branch destination */
    uint8_t  dcIc[DIS_CACHE_SIZE];      /* Instruction class */
    struct symbol *dcSyms;              /* Symbols the cache was filled from */

    int32_t diveline;                   /* Line number we're currently diving into */
    char *divefile;                     /* Filename we're currently diving into */
    bool diving;                        /* Flag indicating we're diving into a file at the moment */

    struct sioline *fileopText;         /* The text lines of the file we're diving into */
    int32_t filenumLines;               /* ...and how many lines of it there are */

    bool held;                          /* If we are actively collecting data */

    struct SIOInstance *sio;            /* Our screen IO instance for managed I/O */

    struct dataBlock rawBlock;          /* Datablock received from distribution */

    struct opConstruct op;              /* The mechanical elements for creating the output buffer */

    struct Options *options;            /* Our runtime configuration */

    bool traceRunning;                  /* Set if we are currently receiving trace */
    uint32_t context;                   /* Context we are currently working under */
    symbolMemaddr callStack[MAX_CALL_STACK]; /* Stack of calls */
    unsigned int stackDepth;            /* Maximum stack depth */
    bool stackDelPending;               /* Possibility to remove an entry from the stack, if address not given */

    /* Hold-at-function (-x): a second decoder follows the program flow live, while the trace is captured */
    struct TRACEDecoder ti;             /* Live decoder */
    struct symbol *holdSyms;            /* Symbol set the hold range was resolved against */
    int holdNumRanges;                  /* Address ranges that trigger the hold (inclusive). There can */
    uint32_t holdLowR[HOLD_MAX_RANGES]; /* be several functions of one name, e.g. a weak default      */
    uint32_t holdHighR[HOLD_MAX_RANGES];/* handler in the startup file and the real one.              */
    const char *holdName;               /* Name of what we hold at, for the screen */
    uint32_t holdAddr;                  /* Live tracked address, or NO_ADDRESS if not known */
    bool holdTriggered;                 /* Range was reached: capture the tail, then hold */
    int holdTail;                       /* Bytes still to capture after the trigger */
    uint32_t hcAddr[HOLD_ICACHE_SIZE];  /* Instruction info cache: address (or NO_ADDRESS if empty) */
    uint32_t hcNew[HOLD_ICACHE_SIZE];   /* ...branch destination */
    uint8_t  hcIc[HOLD_ICACHE_SIZE];    /* ...instruction class */
    bool     hcFound[HOLD_ICACHE_SIZE]; /* ...false if there is no instruction at that address */
    uint64_t hsBytes;                   /* Live tracker statistics, shown while armed */
    uint64_t hsCallbacks;
    uint64_t hsAddrs;
    uint64_t hsInstr;
    uint64_t hsLost;
} _r;

/* For opening the editor (Shift-Right-Arrow) the following command lines work for a few editors;
 *
 * emacs; -c "emacs +%l %f"
 * codium; -c "codium  -g %f:%l"
 * eclipse; -c "eclipse %f:%l"
 */

// ====================================================================================================
// ====================================================================================================
// ====================================================================================================
// Private routines
// ====================================================================================================
// ====================================================================================================
// ====================================================================================================
static void _doExit( void ); /* Forward definition needed */
// ====================================================================================================
static void _intHandler( int sig )

/* Catch CTRL-C so things can be cleaned up properly via atexit functions */
{
    /* CTRL-C exit is not an error... */
    exit( 0 );
}
// ====================================================================================================
static void _printHelp( const char *const progName )

{
    genericsFPrintf( stderr, "Usage: %s [options]" EOL, progName );
    genericsFPrintf( stderr, "    -A, --alt-addr-enc: Do not use alternate address encoding" EOL );
    genericsFPrintf( stderr, "    -b, --buffer-len:   <Length> Length of post-mortem buffer, in KBytes (Default %d KBytes)" EOL, DEFAULT_PM_BUFLEN_K );
    genericsFPrintf( stderr, "    -C, --editor-cmd:   <command> Command line for external editor (%%f = filename, %%l = line)" EOL );
    genericsFPrintf( stderr, "    -D, --no-demangle:  Switch off C++ symbol demangling" EOL );
    genericsFPrintf( stderr, "    -d, --del-prefix:   <String> Material to delete off the front of filenames" EOL );
    genericsFPrintf( stderr, "    -e, --elf-file:     <ElfFile> to use for symbols and source" EOL );
    genericsFPrintf( stderr, "    -E, --eof:          When reading from file, terminate at end of file" EOL );
    genericsFPrintf( stderr, "    -f, --input-file:   <filename>: Take input from specified file" EOL );
    genericsFPrintf( stderr, "    -h, --help:         This help" EOL );
    genericsFPrintf( stderr, "    -M, --no-colour:    Supress colour in output" EOL );
    genericsFPrintf( stderr, "    -O, --objdump-opts: <options> Options to pass directly to objdump" EOL );
    genericsFPrintf( stderr, "    -p, --protocol:     Protocol to communicate. Defaults to OFLOW if -s is not set, otherwise ETM" EOL );
    genericsFPrintf( stderr, "    -P, --trace-proto:  { " );

    for ( int i = TRACE_PROT_LIST_START; i < TRACE_PROT_NUM; i++ )
    {
        genericsFPrintf( stderr, "%s ", TRACEDecodeGetProtocolName( i ) );
    }

    genericsFPrintf( stderr, "} trace protocol to use, default is %s" EOL, TRACEDecodeGetProtocolName( TRACE_PROT_LIST_START ) );
    genericsFPrintf( stderr, "    -s, --server:       <Server>:<Port> to use" EOL );
    genericsFPrintf( stderr, "    -t, --tag:          <stream>: Which OFLOW tag to use (normally 2)" EOL );
    genericsFPrintf( stderr, "    -v, --verbose:      <level> Verbose mode 0(errors)..3(debug)" EOL );
    genericsFPrintf( stderr, "    -x, --hold-at:      <function | 0xaddress> Hold as soon as the trace reaches this function" EOL );
    genericsFPrintf( stderr, "                        (or address). Release with H to wait for the next time." EOL );
    genericsFPrintf( stderr, "    -W, --window:       <Length> Decode this much of the buffer at a time, in KBytes (Default %d KBytes)." EOL, DEFAULT_WINDOW_K );
    genericsFPrintf( stderr, "                        Up, PgUp or Home at the top of the display decodes the next part back." EOL );
    genericsFPrintf( stderr, "    -V, --version:      Print version and exit" EOL );
    genericsFPrintf( stderr, EOL "(Legacy protocol will connect one port higher than that set in -s)" EOL );
    genericsFPrintf( stderr,     "(This will automatically select the second output stream from orbuculum.)" EOL );
    genericsFPrintf( stderr, EOL "Environment Variables;" EOL );
    genericsFPrintf( stderr, "  OBJDUMP: to use non-standard objdump binary" EOL );
}
// ====================================================================================================
void _printVersion( void )

{
    genericsFPrintf( stderr, "orbmortem version " GIT_DESCRIBE );
}
// ====================================================================================================
static struct option _longOptions[] =
{
    {"alt-addr-enc", no_argument, NULL, 'A'},
    {"buffer-len", required_argument, NULL, 'b'},
    {"editor-cmd", required_argument, NULL, 'C'},
    {"no-demangle", required_argument, NULL, 'D'},
    {"del-prefix", required_argument, NULL, 'd'},
    {"elf-file", required_argument, NULL, 'e'},
    {"eof", no_argument, NULL, 'E'},
    {"input-file", required_argument, NULL, 'f'},
    {"help", no_argument, NULL, 'h'},
    {"no-colour", no_argument, NULL, 'M'},
    {"no-color", no_argument, NULL, 'M'},
    {"objdump-opts", required_argument, NULL, 'O'},
    {"trace-proto", required_argument, NULL, 'P'},
    {"protocol", required_argument, NULL, 'p'},
    {"server", required_argument, NULL, 's'},
    {"tag", required_argument, NULL, 't'},
    {"verbose", required_argument, NULL, 'v'},
    {"version", no_argument, NULL, 'V'},
    {"hold-at", required_argument, NULL, 'x'},
    {"window", required_argument, NULL, 'W'},
    {NULL, no_argument, NULL, 0}
};
// ====================================================================================================
static bool _processOptions( int argc, char *argv[], struct RunTime *r )

{
    int c, optionIndex = 0;
    bool protExplicit = false;
    bool serverExplicit = false;

    while ( ( c = getopt_long ( argc, argv, "Ab:C:Dd:Ee:f:hVMO:p:P:s:t:v:wW:x:", _longOptions, &optionIndex ) ) != -1 )
        switch ( c )
        {
            // ------------------------------------
            case 'A':
                r->options->noAltAddr = true;
                break;

            // ------------------------------------
            case 'b':
            {
                long k = strtol( optarg, NULL, 0 );

                if ( ( k < 1 ) || ( k > MAX_PM_BUFLEN_K ) )
                {
                    genericsReport( V_ERROR, "Buffer length must be 1 to %d KBytes" EOL, MAX_PM_BUFLEN_K );
                    return false;
                }

                r->options->buflen = ( int )k * 1024;
            }
            break;

            // ------------------------------------
            case 'W':
            {
                long k = strtol( optarg, NULL, 0 );

                if ( ( k < 1 ) || ( k > MAX_PM_BUFLEN_K ) )
                {
                    genericsReport( V_ERROR, "Window must be 1 to %d KBytes" EOL, MAX_PM_BUFLEN_K );
                    return false;
                }

                r->options->window = ( int )k * 1024;
            }
            break;

            // ------------------------------------
            case 'C':
                r->options->openFileCL = optarg;
                break;

            // ------------------------------------
            case 'D':
                r->options->demangle = false;
                break;

            // ------------------------------------
            case 'd':
                r->options->deleteMaterial = optarg;
                break;

            // ------------------------------------
            case 'E':
                r->options->fileTerminate = true;
                break;

            // ------------------------------------

            case 'e':
                r->options->elffile = optarg;
                break;

            // ------------------------------------

            case 'f':
                r->options->file = optarg;
                break;

            // ------------------------------------

            case 'h':
                _printHelp( r->progName );
                return false;

            // ------------------------------------
            case 'V':
                _printVersion();
                return false;

            // ------------------------------------

            case 'M':
                r->options->mono = true;
                break;

            // ------------------------------------
            case 'O':
                r->options->odoptions = optarg;
                break;

            // ------------------------------------
            case 'P':

                /* Index through protocol strings looking for match or end of list */
                for ( r->options->traceProt = TRACE_PROT_LIST_START;
                        ( ( r->options->traceProt != TRACE_PROT_NUM ) && strcasecmp( optarg, TRACEDecodeGetProtocolName( r->options->traceProt ) ) );
                        r->options->traceProt++ )
                {}

                break;

            // ------------------------------------

            case 'p':
                r->options->commProt = PROT_UNKNOWN;
                protExplicit = true;

                for ( int i = 0; protString[i]; i++ )
                {
                    if ( !strcmp( protString[i], optarg ) )
                    {
                        r->options->commProt = i;
                        break;
                    }
                }

                if ( r->options->commProt == PROT_UNKNOWN )
                {
                    genericsReport( V_ERROR, "Unrecognised protocol type" EOL );
                    return false;
                }

                break;

            // ------------------------------------

            case 's':
                serverExplicit = true;
                r->options->server = optarg;

                // See if we have an optional port number too
                char *a = optarg;

                while ( ( *a ) && ( *a != ':' ) )
                {
                    a++;
                }

                if ( *a == ':' )
                {
                    *a = 0;
                    r->options->port = atoi( ++a );
                }

                if ( !r->options->port )
                {
                    r->options->port = NWCLIENT_SERVER_PORT;
                }

                break;

            // ------------------------------------

            case 't':
                r->options->tag = atoi( optarg );
                break;

            // ------------------------------------

            case 'v':
                if ( !isdigit( *optarg ) )
                {
                    genericsReport( V_ERROR, "-v requires a numeric argument." EOL );
                    return false;
                }

                genericsSetReportLevel( atoi( optarg ) );
                break;

            // ------------------------------------

            case 'w':
                r->options->withDebugText = true;
                break;

            // ------------------------------------

            case 'x':
                r->options->holdAt = optarg;
                break;

            // ------------------------------------

            case '?':
                if ( optopt == 'b' )
                {
                    genericsReport( V_ERROR, "Option '%c' requires an argument." EOL, optopt );
                }
                else if ( !isprint ( optopt ) )
                {
                    genericsReport( V_ERROR, "Unknown option character `\\x%x'." EOL, optopt );
                }

                return false;

            // ------------------------------------
            default:
                genericsReport( V_ERROR, "Unrecognised option '%c'" EOL, c );
                return false;
                // ------------------------------------
        }

    /* If we set an explicit server and port and didn't set a protocol chances are we want ETM, not OFLOW */
    if ( serverExplicit && !protExplicit && r->options->port != OFCLIENT_SERVER_PORT )
    {
        r->options->commProt = PROT_ETM;
        genericsReport( V_INFO, "(Auto-set ETM3.5 for TCP::%s:%d, override by setting protocol explicitly)" EOL, r->options->server, r->options->port );
    }

    /* ... and dump the config if we're being verbose */
    genericsReport( V_INFO, "orbmortem version " GIT_DESCRIBE EOL );

    if ( r->options->withDebugText )
    {
        genericsReport( V_INFO, "Incoporate debug text in output buffer" EOL );
    }

    if ( r->options->file )
    {
        genericsReport( V_INFO, "Input File       : %s", r->options->file );
    }
    else
    {
        genericsReport( V_INFO, "Server           : %s:%d" EOL, r->options->server, r->options->port );
    }

    genericsReport( V_INFO, "Elf File         : %s" EOL, r->options->elffile );

    if ( r->options->traceProt >= TRACE_PROT_NONE )
    {
        genericsExit( V_ERROR, "Unrecognised decode protocol" EOL );
    }
    else
    {
        genericsReport( V_INFO, "Protocol         : %s" EOL, TRACEDecodeGetProtocolName( r->options->traceProt ) );
    }

    if ( ( r->options->traceProt == TRACE_PROT_MTB ) && ( !r->options->file ) )
    {
        genericsExit( V_ERROR, "MTB only makes sense when input is from a file" EOL );
    }

    if ( !r->options->elffile )
    {
        genericsExit( V_ERROR, "Elf File not specified" EOL );
    }

    if ( !r->options->buflen )
    {
        genericsExit( -1, "Illegal value for Post Mortem Buffer length" EOL );
    }

    switch ( r->options->commProt )
    {
        case PROT_OFLOW:
            genericsReport( V_INFO, "Decoding OFLOW with ETM in stream %d" EOL, r->options->tag );
            break;

        case PROT_ETM:
            genericsReport( V_INFO, "Decoding ETM directly in legacy flow" EOL );
            return false;

        default:
            genericsReport( V_INFO, "Decoding unknown" EOL );
            break;
    }

    return true;
}
// ====================================================================================================
// Hold-at-function (-x) support
// ====================================================================================================
static void _holdReset( struct RunTime *r )

/* (Re)arm: forget where the CPU is and wait for the next sync and address from the trace */

{
    r->holdAddr = NO_ADDRESS;
    r->holdTriggered = false;
    r->holdTail = 0;
    TRACEDecoderForceSync( &r->ti, false );
}
// ====================================================================================================
static bool _holdResolve( struct RunTime *r )

/* Find the address range for the -x argument in the current symbol set, and empty the cache */

{
    const char *a = r->options->holdAt;

    for ( int i = 0; i < HOLD_ICACHE_SIZE; i++ )
    {
        r->hcAddr[i] = NO_ADDRESS;
    }

    r->holdSyms = r->s;

    if ( ( a[0] == '0' ) && ( ( a[1] == 'x' ) || ( a[1] == 'X' ) ) )
    {
        r->holdLowR[0] = r->holdHighR[0] = strtoul( a, NULL, 16 ) & ~1UL;
        r->holdNumRanges = 1;
        r->holdName = a;
        return true;
    }

    struct symbolFunctionStore *f;
    r->holdNumRanges = 0;

    /* Exact name first; if nothing matches, ignore upper/lower case (e.g. systick_handler) */
    for ( int pass = 0; ( pass < 2 ) && ( !r->holdNumRanges ); pass++ )
    {
    for ( unsigned int i = 0; ( f = symbolFunctionIndex( r->s, i ) ) && ( r->holdNumRanges < HOLD_MAX_RANGES ); i++ )
    {
        /* Skip declarations (e.g. from a header, in another file's debug info) and inline */
        /* templates: they have no code of their own.                                     */
        if ( ( f->funcname ) && ( !f->isinline ) && ( pass ? !strcasecmp( f->funcname, a ) : !strcmp( f->funcname, a ) ) &&
                ( f->lowaddr ) && ( f->highaddr >= f->lowaddr ) &&
                ( symbolCodeAt( r->s, f->lowaddr & ~1UL, NULL ) ) )
        {
            /* Keep all of them: we can't tell which one the linker used */
            r->holdLowR[r->holdNumRanges]  = f->lowaddr & ~1UL;
            r->holdHighR[r->holdNumRanges] = f->highaddr;
            r->holdNumRanges++;
            r->holdName = f->funcname;
            genericsReport( V_INFO, "Hold at %s (0x%08x..0x%08x)" EOL, a, ( uint32_t )( f->lowaddr & ~1UL ), ( uint32_t )f->highaddr );
        }
    }

    /* ...and every place the function was inlined into another one */
    struct symbolInlineStore *in;

    for ( unsigned int i = 0; ( in = symbolInlineIndex( r->s, i ) ) && ( r->holdNumRanges < HOLD_MAX_RANGES ); i++ )
    {
        if ( ( in->funcname ) && ( pass ? !strcasecmp( in->funcname, a ) : !strcmp( in->funcname, a ) ) )
        {
            r->holdLowR[r->holdNumRanges]  = in->lowaddr & ~1UL;
            r->holdHighR[r->holdNumRanges] = in->highaddr;
            r->holdNumRanges++;
            r->holdName = in->funcname;
            genericsReport( V_INFO, "Hold at %s, inlined (0x%08x..0x%08x)" EOL, a, ( uint32_t )( in->lowaddr & ~1UL ), ( uint32_t )in->highaddr );
        }
    }
    }

    return ( r->holdNumRanges > 0 );
}
// ====================================================================================================
static bool _holdLookup( struct RunTime *r, uint32_t addr, enum instructionClass *ic, symbolMemaddr *newaddr )

/* Instruction class and branch destination at addr, cached (disassembling is slow). False if no instruction there. */

{
    uint32_t ci = ( addr >> 1 ) & ( HOLD_ICACHE_SIZE - 1 );

    if ( r->hcAddr[ci] != addr )
    {
        enum instructionClass c = LE_IC_NONE;
        symbolMemaddr n = NO_ADDRESS;
        r->hcFound[ci] = ( NULL != symbolDisassembleLine( r->s, &c, addr, &n ) );
        r->hcIc[ci]    = ( uint8_t )c;
        r->hcNew[ci]   = ( uint32_t )n;
        r->hcAddr[ci]  = addr;
    }

    *ic = ( enum instructionClass )r->hcIc[ci];
    *newaddr = r->hcNew[ci];
    return r->hcFound[ci];
}
// ====================================================================================================
static inline bool _holdHit( struct RunTime *r, uint32_t addr )

{
    if ( addr == ( uint32_t )NO_ADDRESS )
    {
        return false;
    }

    for ( int n = 0; n < r->holdNumRanges; n++ )
    {
        if ( ( addr < r->holdLowR[n] ) || ( addr > r->holdHighR[n] ) )
        {
            continue;
        }

        r->holdTriggered = true;
        r->holdTail = HOLD_TAIL_BYTES;
        genericsReport( V_INFO, "Reached %s at 0x%08x" EOL, r->holdName, addr );
        return true;
    }

    return false;
}
// ====================================================================================================
static void _holdCB( void *d )

/* Live decode callback: follow the program flow (the same way _traceCB does for ETM3.5, but */
/* without building any output) and trigger when the hold range is reached.                  */

{
    struct RunTime *r = ( struct RunTime * )d;
    struct TRACECPUState *cpu = TRACECPUState( &r->ti );
    uint32_t incAddr = 0;
    uint32_t disposition = 0;
    enum instructionClass ic;
    symbolMemaddr newaddr;

    if ( ( r->holdTriggered ) || ( !r->s ) )
    {
        return;
    }

    r->hsCallbacks++;

    if ( r->s != r->holdSyms )
    {
        /* Symbols were reloaded (the ELF changed) */
        if ( !_holdResolve( r ) )
        {
            return;
        }
    }

    if ( TRACEStateChanged( &r->ti, EV_CH_ADDRESS ) )
    {
        r->holdAddr = cpu->addr & ~1UL;
        r->hsAddrs++;

        if ( _holdHit( r, r->holdAddr ) )
        {
            return;
        }
    }

    if ( TRACEStateChanged( &r->ti, EV_CH_ENATOMS ) )
    {
        incAddr = cpu->eatoms + cpu->natoms;
        disposition = cpu->disposition;
    }

    while ( ( incAddr ) && ( r->holdAddr != ( uint32_t )NO_ADDRESS ) )
    {
        if ( !_holdLookup( r, r->holdAddr, &ic, &newaddr ) )
        {
            /* Not in the image: position unknown until the next address */
            r->holdAddr = NO_ADDRESS;
            r->hsLost++;
            break;
        }

        r->hsInstr++;
        bool executed = ( disposition & 1 );
        uint32_t len = ( ic & LE_IC_4BYTE ) ? 4 : 2;
        disposition >>= 1;
        incAddr--;

        if ( ( ic & LE_IC_CALL ) || ( ic & LE_IC_JUMP ) )
        {
            if ( !executed )
            {
                r->holdAddr += len;
            }
            else if ( ( ic & LE_IC_IMMEDIATE ) || ( ( ic & LE_IC_CALL ) && ( newaddr != NO_ADDRESS ) ) )
            {
                r->holdAddr = newaddr;
            }
            else
            {
                /* Indirect branch: the trace sends the destination address next */
                r->holdAddr = NO_ADDRESS;
                break;
            }
        }
        else
        {
            r->holdAddr += len;
        }

        if ( _holdHit( r, r->holdAddr ) )
        {
            return;
        }
    }
}
// ====================================================================================================
static inline bool _holdFeed( struct RunTime *r, uint8_t c )

/* Pass one received byte to the live decoder. Returns true when capture should stop (hold). */

{
    if ( !r->options->holdAt )
    {
        return false;
    }

    if ( r->holdTriggered )
    {
        return ( --r->holdTail <= 0 );
    }

    TRACEDecoderPump( &r->ti, &c, 1, _holdCB, r );
    return false;
}
// ====================================================================================================
static void _processBlock( struct RunTime *r )

/* Generic block processor for received data */

{
    uint8_t *c = r->rawBlock.buffer;
    uint32_t y = r->rawBlock.fillLevel;

    genericsReport( V_DEBUG, "RXED Packet of %d bytes" EOL, y );

    if ( y )
    {
#ifdef DUMP_BLOCK
        fprintf( stderr, EOL );

        while ( y-- )
        {
            fprintf( stderr, "%02X ", *c++ );

            if ( !( y % 16 ) )
            {
                fprintf( stderr, EOL );
            }
        }

        c = r->rawBlock.buffer;
        y = r->rawBlock.fillLevel;
#endif

        r->newTotalBytes += y;

        while ( y-- )
        {
            if ( ( r->options->holdAt ) && ( r->holdTriggered ) && ( r->holdTail <= 0 ) )
            {
                return;
            }

            _holdFeed( r, *c );
            r->pmBuffer[r->wp] = *c++;
            uint32_t nwp = ( r->wp + 1 ) % r->options->buflen;

            if ( nwp == r->rp )
            {
                if ( r->singleShot )
                {
                    r->held = true;
                    return;
                }
                else
                {
                    r->rp = ( r->rp + 1 ) % r->options->buflen;
                }
            }

            r->wp = nwp;
        }
    }
}

// ====================================================================================================
static bool _rxAdd( struct RunTime *r, uint8_t c )

{
    r->newTotalBytes ++;

    r->pmBuffer[r->wp] = c;
    int nwp = r->wp + 1;

    if ( nwp == r->options->buflen )
    {
        nwp = 0;
    }

    if ( nwp == r->rp )
    {
        if ( r->singleShot )
        {
            r->held = true;
            return true;
        }
        else
        {
            if ( ++r->rp == r->options->buflen )
            {
                r->rp = 0;
            }
        }
    }

    r->wp = nwp;
    return false;
}

// ====================================================================================================

static void _OFLOWpacketRxed ( struct OFLOWFrame *p, void *param )

{
    struct RunTime *r = ( struct RunTime * )param;

    if ( !p->good )
    {
        genericsReport( V_INFO, "Bad packet received" EOL );
    }
    else
    {
        if ( p->tag == r->options->tag )
        {
            if ( r->options->holdAt )
            {
                /* Byte by byte, so the history stops exactly HOLD_TAIL_BYTES after the trigger point */
                /* (a packet can hold thousands of bytes, i.e. many thousands of instructions).     */
                for ( int i = 0; i < p->len; i++ )
                {
                    if ( r->holdTriggered )
                    {
                        if ( r->holdTail <= 0 )
                        {
                            /* Hold point reached and its tail captured: keep the buffer as it is */
                            return;
                        }

                        r->holdTail--;
                    }
                    else
                    {
                        /* Follow the program flow (may trigger the hold) */
                        r->hsBytes++;
                        TRACEDecoderPump( &r->ti, &p->d[i], 1, _holdCB, r );
                    }

                    if ( _rxAdd( r, p->d[i] ) )
                    {
                        return;
                    }
                }

                return;
            }

            for ( int i = 0; i < p->len; i++ )
            {
                if ( _rxAdd( r, p->d[i] ) )
                {
                    return;
                }
            }
        }
    }
}

// ====================================================================================================
static void _flushBuffer( struct RunTime *r )

/* Empty the output buffer, and de-allocate its memory */

{
    /* Tell the UI there's nothing more to show */
    SIOsetOutputBuffer( r->sio, 0, 0, NULL, false );

    /* Remove all of the recorded lines */
    while ( r->numLines-- )
    {
        if ( !r->opText[r->numLines].isRef )
        {
            free( r->opText[r->numLines].buffer );
        }
    }

    /* and the opText buffer */
    free( r->opText );
    r->opText = NULL;
    r->opTextAlloc = 0;
    r->numLines = 0;
    r->wNum = 0;

    /* ...and the file/line references */
    r->op.currentLine = NO_LINE;
    r->op.currentFileindex = NO_FILE;
    r->op.currentFunctionptr = NULL;
    r->op.workingAddr = NO_DESTADDRESS;
}
// ====================================================================================================
static void _opTextGrow( struct RunTime *r )

/* Make room for one more display line. The array doubles when full (growing it one line at */
/* a time copied the whole array for every line, which is very slow for long histories).    */

{
    if ( r->numLines >= r->opTextAlloc )
    {
        int32_t n = r->opTextAlloc ? r->opTextAlloc * 2 : OPTEXT_MIN_ALLOC;
        struct sioline *t = ( struct sioline * )realloc( r->opText, sizeof( struct sioline ) * n );

        if ( !t )
        {
            genericsExit( -1, "Out of memory for display lines, use a smaller -b" EOL );
        }

        r->opText = t;
        r->opTextAlloc = n;
    }
}
// ====================================================================================================
static const char *_disassemble( struct RunTime *r, enum instructionClass *ic, uint32_t addr, symbolMemaddr *newaddr )

/* symbolDisassembleLine with a cache. The returned text belongs to the cache. */

{
    if ( r->dcSyms != r->s )
    {
        /* New symbol set: empty the cache */
        for ( int i = 0; i < DIS_CACHE_SIZE; i++ )
        {
            free( r->dcText[i] );
            r->dcText[i] = NULL;
            r->dcAddr[i] = NO_ADDRESS;
        }

        r->dcSyms = r->s;
    }

    uint32_t ci = ( addr >> 1 ) & ( DIS_CACHE_SIZE - 1 );

    if ( r->dcAddr[ci] != addr )
    {
        enum instructionClass c = LE_IC_NONE;
        symbolMemaddr n = NO_ADDRESS;
        char *a = symbolDisassembleLine( r->s, &c, addr, &n );
        free( r->dcText[ci] );
        r->dcText[ci] = a ? strdup( a ) : NULL;
        r->dcIc[ci]   = ( uint8_t )c;
        r->dcNew[ci]  = ( uint32_t )n;
        r->dcAddr[ci] = addr;
    }

    *ic = ( enum instructionClass )r->dcIc[ci];

    if ( newaddr )
    {
        *newaddr = r->dcNew[ci];
    }

    return r->dcText[ci];
}
// ====================================================================================================
// Strdup leak is deliberately ignored. That is the central purpose of this code. It's cleaned
// upin __flushBuffer above.
#pragma GCC diagnostic push
#if !defined(__clang__)
    #pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
#endif

static void _appendToOPBuffer( struct RunTime *r, void *dat, int32_t lineno, enum LineType lt, const char *fmt, ... )

/* Add line to output buffer, in a printf stylee */

{
    char construct[SCRATCH_STRING_LEN];
    va_list va;
    char *p;

    va_start( va, fmt );
    vsnprintf( construct, SCRATCH_STRING_LEN, fmt, va );
    va_end( va );

    /* Make sure we didn't accidentially admit a CR or LF */
    for ( p = construct; ( ( *p ) && ( *p != '\n' ) && ( *p != '\r' ) ); p++ );

    *p = 0;

    _opTextGrow( r );
    r->opText[r->numLines].buffer = strdup( construct );
    r->opText[r->numLines].lt     = lt;
    r->opText[r->numLines].line   = lineno;
    r->opText[r->numLines].isRef  = false;
    r->opText[r->numLines].dat    = dat;
    r->numLines++;
}
#pragma GCC diagnostic pop

// ====================================================================================================
static void _appendRefToOPBuffer( struct RunTime *r, void *dat, int32_t lineno, enum LineType lt, const char *ref )

/* Add line to output buffer, as a reference (which don't be free'd later) */

{
    _opTextGrow( r );

    /* This line removes the 'const', but we know to not mess with this line */
    r->opText[r->numLines].buffer = ( char * )ref;
    r->opText[r->numLines].lt     = lt;
    r->opText[r->numLines].line   = lineno;
    r->opText[r->numLines].isRef  = true;
    r->opText[r->numLines].dat    = dat;
    r->numLines++;
}
// ====================================================================================================
static void _traceReport( enum verbLevel l, const char *fmt, ... )

/* Debug reporting stream */

{
    if ( _r.options->withDebugText )
    {
        static char op[SCRATCH_STRING_LEN];

        va_list va;
        va_start( va, fmt );
        vsnprintf( op, SCRATCH_STRING_LEN, fmt, va );
        va_end( va );
        _appendToOPBuffer( &_r, NULL, _r.op.currentLine, LT_DEBUG, op );
    }
}
// ====================================================================================================
static void _addRetToStack( struct RunTime *r, symbolMemaddr p )

{
    if ( r->stackDepth == MAX_CALL_STACK - 1 )
    {
        /* Stack is full, so make room for a new entry */
        memmove( &r->callStack[0], &r->callStack[1], sizeof( symbolMemaddr ) * ( MAX_CALL_STACK - 1 ) );
    }

    r->callStack[r->stackDepth] = p;
    _traceReport( V_DEBUG, "Pushed %08x to return stack", r->callStack[r->stackDepth] );

    if ( r->stackDepth < MAX_CALL_STACK - 1 )
    {
        /* We aren't at max depth, so go ahead and remove this entry */
        r->stackDepth++;
    }
}
// ====================================================================================================
static void _reportNonflowEvents( struct RunTime *r )

{
    struct TRACECPUState *cpu = TRACECPUState( &r->i );

    if ( TRACEStateChanged( &r->i, EV_CH_TRACESTART ) )
    {
        if ( !r->traceRunning )
        {
            _appendRefToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "========== TRACE START EVENT ==========" );
            r->traceRunning = true;
        }
    }

    if ( TRACEStateChanged( &r->i, EV_CH_VMID ) )
    {
        _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "*** VMID Set to %d", cpu->vmid );
    }

    if ( TRACEStateChanged( &r->i, EV_CH_EX_EXIT ) )
    {
        _appendRefToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "========== Exception Exit ==========" );
    }

    if ( TRACEStateChanged( &r->i, EV_CH_TSTAMP ) )
    {
        if ( cpu->ts )
        {
            if ( cpu->ts != COUNT_UNKNOWN )
            {
                _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "*** Timestamp %ld", cpu->ts );
            }
            else
            {
                _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "*** Timestamp unknown" );
            }
        }
    }

    if ( TRACEStateChanged( &r->i, EV_CH_TRIGGER ) )
    {
        _appendRefToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "*** Trigger" );
    }

    if ( TRACEStateChanged( &r->i, EV_CH_CLOCKSPEED ) )
    {
        _appendRefToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "*** Change Clockspeed" );
    }

    if ( TRACEStateChanged( &r->i, EV_CH_ISLSIP ) )
    {
        _appendRefToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "*** ISLSIP Triggered" );
    }

    if ( TRACEStateChanged( &r->i, EV_CH_CYCLECOUNT ) )
    {
        _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "(Cycle Count %d)", cpu->cycleCount );
    }

    if ( TRACEStateChanged( &r->i, EV_CH_VMID ) )
    {
        _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "(VMID is now %d)", cpu->vmid );
    }

    if ( TRACEStateChanged( &r->i, EV_CH_CONTEXTID ) )
    {
        if ( r->context != cpu->contextID )
        {
            _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "(Context ID is now %d)", cpu->contextID );
            r->context = cpu->contextID;
        }
    }

    if ( TRACEStateChanged( &r->i, EV_CH_SECURE ) )
    {
        _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "(Non-Secure State is now %s)", cpu->nonSecure ? "True" : "False" );
    }

    if ( TRACEStateChanged( &r->i, EV_CH_ALTISA ) )
    {
        _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "(Using AltISA  is now %s)", cpu->altISA ? "True" : "False" );
    }

    if ( TRACEStateChanged( &r->i, EV_CH_HYP ) )
    {
        _appendToOPBuffer( r, NULL, r->op.currentLine,  LT_EVENT, "(Using Hypervisor is now %s)", cpu->hyp ? "True" : "False" );
    }

    if ( TRACEStateChanged( &r->i, EV_CH_JAZELLE ) )
    {
        _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "(Using Jazelle is now %s)", cpu->jazelle ? "True" : "False" );
    }

    if ( TRACEStateChanged( &r->i, EV_CH_THUMB ) )
    {
        _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "(Using Thumb is now %s)", cpu->thumb ? "True" : "False" );
    }
}

// ====================================================================================================
static void _traceCB( void *d )

/* Callback function for when valid TRACE decode is detected */

{
    struct RunTime *r = ( struct RunTime * )d;
    struct TRACECPUState *cpu = TRACECPUState( &r->i );
    uint32_t incAddr = 0;
    uint32_t disposition;
    uint32_t targetAddr = 0; /* Just to avoid unitialised variable warning */
    bool linearRun = false;
    enum instructionClass ic;
    symbolMemaddr newaddr;

    /* 1: Report anything that doesn't affect the flow */
    /* =============================================== */
    _reportNonflowEvents( r );

    /* 2: Deal with exception entry */
    /* ============================ */
    if ( TRACEStateChanged( &r->i, EV_CH_EX_ENTRY ) )
    {
        switch ( r->options->traceProt )
        {
            case TRACE_PROT_ETM35:
                _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "========== Exception Entry%s (%d (%s) at 0x%08x) ==========",
                                   TRACEStateChanged( &r->i, EV_CH_CANCELLED ) ? ", Last Instruction Cancelled" : "", cpu->exception, TRACEExceptionName( cpu->exception ), cpu->addr );
                break;

            case TRACE_PROT_MTB:
                _appendRefToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "========== Exception Entry ==========" );
                break;


            case TRACE_PROT_ETM4:

                /* For the ETM4 case we get a new address with the exception indication. This address is the preferred _return_ address, */
                /* there will be a further address packet, which is the jump destination, along shortly. Note that _this_ address        */
                /* change indication will be consumed here, and won't hit the test below (which is correct behaviour.                    */
                if ( !TRACEStateChanged( &r->i, EV_CH_ADDRESS ) )
                {
                    _traceReport( V_DEBUG, "Exception occured without return address specification" );
                }
                else
                {
                    _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "========== Exception Entry (%d (%s) at 0x%08x return to %08x ) ==========",
                                       cpu->exception, TRACEExceptionName( cpu->exception ), r->op.workingAddr, cpu->addr );
                    _addRetToStack( r, cpu->addr );
                }

                break;

            default:
                _traceReport( V_DEBUG, "Unrecognised trace protocol in exception handler" );
                break;
        }
    }


    /* 3: Collect flow affecting changes introduced by this event */
    /* ========================================================== */
    if ( TRACEStateChanged( &r->i, EV_CH_ADDRESS ) )
    {
        /* Make debug report if calculated and reported addresses differ. This is most useful for testing when exhaustive  */
        /* address reporting is switched on. It will give 'false positives' for uncalculable instructions (e.g. bx lr) but */
        /* it's a decent safety net to be sure the jump decoder is working correctly.                                      */

        if ( r->options->traceProt != TRACE_PROT_MTB )
        {
            _traceReport( V_DEBUG, "%sCommanded CPU Address change (Was:0x%08x Commanded:0x%08x)" EOL,
                          ( r->op.workingAddr == cpu->addr ) ? "" : "***INCONSISTENT*** ", r->op.workingAddr, cpu->addr );
        }

        /* Return Stack: If we had a stack deletion pending because of a candidate match, it wasn't, so abort */
        if ( r->stackDelPending )
        {
            _traceReport( V_DEBUG, "Stack delete aborted" );
        }

        r->stackDelPending = false;
        /* Whatever the state was, this is an explicit setting of an address, so we need to respect it */
        r->op.workingAddr = cpu->addr;
    }
    else
    {
        /* Return Stack: If we had a stack deletion pending because of a candidate match, the match was good, so commit */
        if ( ( r->stackDelPending == true ) && ( r->stackDepth ) )
        {
            r->stackDepth--;
            _traceReport( V_DEBUG, "Stack delete comitted" );
        }

        r->stackDelPending = false;
    }

    if ( TRACEStateChanged( &r->i, EV_CH_LINEAR ) )
    {
        /* MTB-Specific mechanism: Execute instructions from the marked starting location to the indicated finishing one */
        /* Disposition is all 1's because every instruction is executed.                                                 */
        r->op.workingAddr = cpu->addr;
        targetAddr        = cpu->toAddr;
        linearRun         = true;
        disposition       = 0xffffffff;
        _traceReport( V_DEBUG, "Linear run 0x%08x to 0x%08x" EOL, cpu->addr, cpu->toAddr );
    }

    if ( TRACEStateChanged( &r->i, EV_CH_ENATOMS ) )
    {
        /* Atoms represent instruction steps...some of which will have been executed, some stepped over. The number of steps is the   */
        /* total of the eatoms (executed) and natoms (not executed) and the disposition bitfield shows if each individual instruction */
        /* was executed or not. For ETM3 each 'run' of instructions is a single instruction with the disposition bit telling you if   */
        /* it was executed or not. For ETM4 each 'run' of instructions is from the current address to the next possible change of     */
        /* program flow (and which point the disposition bit tells you if that jump was taken or not).                                */
        incAddr = cpu->eatoms + cpu->natoms;
        disposition = cpu->disposition;
    }

    /* 4: Execute the flow instructions */
    /* ================================ */
    while ( ( incAddr && !linearRun ) || ( ( r->op.workingAddr <= targetAddr ) && linearRun ) )
    {
        /* Firstly, lets get the source code line...*/
        struct symbolLineStore *l = symbolLineAt( r->s, r->op.workingAddr );

        if ( l )
        {
            /* If we have changed file or function put a header line in */
            if ( l->function )
            {
                /* There is a valid function tag recognised here. If it's a change highlight it in the output. */
                if ( ( l->function->filename != r->op.currentFileindex ) || ( l->function != r->op.currentFunctionptr ) )
                {
                    _appendToOPBuffer( r, l, r->op.currentLine, LT_FILE, "%s::%s", symbolGetFilename( r->s, l->function->filename ), l->function->funcname );
                    r->op.currentFileindex     = l->function->filename;
                    r->op.currentFunctionptr   = l->function;
                    r->op.currentLine = NO_LINE;
                }
            }
            else
            {
                /* We didn't find a valid function, but we might have some information to work with.... */
                if ( ( NO_FILE != r->op.currentFileindex ) || ( NULL != r->op.currentFunctionptr ) )
                {
                    _appendToOPBuffer( r, l, r->op.currentLine, LT_FILE, "Unknown function" );
                    r->op.currentFileindex     = NO_FILE;
                    r->op.currentFunctionptr   = NULL;
                    r->op.currentLine = NO_LINE;
                }
            }
        }

        /* If we have changed line then output the new one */
        if ( l && ( ( l->startline != r->op.currentLine ) ) )
        {
            const char *v = symbolSource( r->s, l->filename, l->startline - 1 );
            r->op.currentLine = l->startline;
            _appendRefToOPBuffer( r, l, r->op.currentLine, LT_SOURCE, v );
        }

        /* Now output the matching assembly, and location updates */
        const char *a = _disassemble( r, &ic, r->op.workingAddr, &newaddr );

        if ( a )
        {
            /* Calculate if this instruction was executed. This is slightly hairy depending on which protocol we're using;         */
            /*   * ETM3.5: Instructions are executed based on disposition bit (LSB in disposition word)                            */
            /*   * ETM4  : ETM4 everything up to a branch is executed...decision about that branch is based on disposition bit     */
            /*   * MTB   : Everything except jumps are executed, jumps are executed only if they are the last instruction in a run */
            bool insExecuted = (
                                           /* ETM3.5 case - dependent on disposition */
                                           ( ( !linearRun )  && ( r->i.protocol == TRACE_PROT_ETM35 ) && ( disposition & 1 ) ) ||

                                           /* ETM4 case - either not a branch or disposition is 1 */
                                           ( ( !linearRun ) && ( r->i.protocol == TRACE_PROT_ETM4 ) && ( ( !( ic & LE_IC_JUMP ) ) || ( disposition & 1 ) ) ) ||

                                           /* MTB case - a linear run to last address */
                                           ( ( linearRun ) && ( r->i.protocol == TRACE_PROT_MTB ) &&
                                             ( ( ( r->op.workingAddr != targetAddr ) && ( ! ( ic & LE_IC_JUMP ) ) )  ||
                                               ( r->op.workingAddr == targetAddr )
                                             ) ) );
            /* The text lives in the disassembly cache, so it can be referenced instead of copied */
            _appendRefToOPBuffer( r, l, r->op.currentLine, insExecuted ? LT_ASSEMBLY : LT_NASSEMBLY, a );


            /* Move addressing along */
            if ( ( r->i.protocol != TRACE_PROT_ETM4 ) || ( ic & LE_IC_JUMP ) )
            {
                if ( r->i.protocol == TRACE_PROT_ETM4 )
                {
                    _traceReport( V_DEBUG, "Consumed, %sexecuted (%d left)", insExecuted ? "" : "not ", incAddr - 1 );
                }

                disposition >>= 1;
                incAddr--;
            }

            if ( ic & LE_IC_CALL )
            {
                if ( insExecuted )
                {
                    /* Push the instruction after this if it's a subroutine or ISR */
                    _traceReport( V_DEBUG, "Call to %08x", newaddr );
                    _addRetToStack( r, r->op.workingAddr + ( ( ic & LE_IC_4BYTE ) ? 4 : 2 ) );
                }

                r->op.workingAddr = insExecuted ? newaddr : r->op.workingAddr + ( ( ic & LE_IC_4BYTE ) ? 4 : 2 );
            }
            else if ( ic & LE_IC_JUMP )
            {
                _traceReport( V_DEBUG, "%sTAKEN JUMP", insExecuted ? "" : "NOT " );

                if ( insExecuted )
                {
                    /* Update working address according to if jump was taken */
                    if ( ic & LE_IC_IMMEDIATE )
                    {
                        _traceReport( V_DEBUG, "Immediate address %8x", newaddr );
                        /* We have a good address, so update with it */
                        r->op.workingAddr = newaddr;
                    }
                    else
                    {
                        /* We didn't get the address, so need to park the call stack address if we've got one. Either we won't      */
                        /* get an address (in which case this one was correct), or we wont (in which case, don't unstack this one). */
                        if ( r->stackDepth )
                        {
                            r->op.workingAddr = r->callStack[r->stackDepth - 1];
                            _traceReport( V_DEBUG, "Return with stacked candidate to %08x", r->op.workingAddr );
                        }
                        else
                        {
                            _traceReport( V_DEBUG, "Return with no stacked candidate" );
                        }

                        r->stackDelPending = true;
                    }
                }
                else
                {
                    /* The branch wasn't taken, so just move along */
                    r->op.workingAddr += ( ic & LE_IC_4BYTE ) ? 4 : 2;
                }
            }
            else
            {
                /* Just a regular instruction, so just move along */
                r->op.workingAddr += ( ic & LE_IC_4BYTE ) ? 4 : 2;
            }
        }
        else
        {
            _appendToOPBuffer( r, l, r->op.currentLine, LT_ASSEMBLY, "%8x:\tASSEMBLY NOT FOUND" EOL, r->op.workingAddr );
            r->op.workingAddr += 2;
            disposition >>= 1;
            incAddr--;
        }
    }
}

// ====================================================================================================
static int64_t _pmLen( struct RunTime *r )

/* Number of bytes in the post-mortem ring buffer */

{
    return ( ( int64_t )r->wp + r->options->buflen - r->rp ) % r->options->buflen;
}
// ====================================================================================================
static uint8_t _pmByte( struct RunTime *r, int64_t off )

/* Byte at offset off from the oldest byte in the ring buffer */

{
    return r->pmBuffer[( r->rp + off ) % r->options->buflen];
}
// ====================================================================================================
static int64_t _syncAtOrBefore( struct RunTime *r, int64_t limit )

/* Offset of the latest A-sync (a run of at least 5 zero bytes then 0x80, both for ETM3.5 and ETM4) */
/* that starts at or before limit, or -1 if there is none. Decoding can start there.               */

{
    int64_t len = _pmLen( r );
    int64_t p = ( limit + 5 < len - 1 ) ? limit + 5 : len - 1;

    for ( ; p >= 5; p-- )
    {
        if ( ( _pmByte( r, p ) != 0x80 ) || _pmByte( r, p - 1 ) || _pmByte( r, p - 2 ) ||
                _pmByte( r, p - 3 ) || _pmByte( r, p - 4 ) || _pmByte( r, p - 5 ) )
        {
            continue;
        }

        /* Start of the zero run */
        int64_t q = p - 5;

        while ( ( q > 0 ) && ( !_pmByte( r, q - 1 ) ) )
        {
            q--;
        }

        if ( q <= limit )
        {
            return q;
        }
    }

    return -1;
}
// ====================================================================================================
static void _decodeRange( struct RunTime *r, int64_t from, int64_t to )

/* Decode buffer offsets [from, to) into the output buffer. A range starts at an A-sync (or at */
/* the start of the buffer), so the decoder and the flow state start afresh.                   */

{
    TRACEDecoderForceSync( &r->i, false );
    r->op.currentLine = NO_LINE;
    r->op.currentFileindex = NO_FILE;
    r->op.currentFunctionptr = NULL;
    r->op.workingAddr = NO_DESTADDRESS;
    r->stackDepth = 0;
    r->stackDelPending = false;

    int64_t i = ( r->rp + from ) % r->options->buflen;
    int64_t n = to - from;

    /* Two parts when the range wraps round the end of the ring buffer */
    while ( n > 0 )
    {
        int64_t part = ( n < r->options->buflen - i ) ? n : r->options->buflen - i;
        TRACEDecoderPump( &r->i, &r->pmBuffer[i], ( int )part, _traceCB, r );
        n -= part;
        i = 0;
    }
}
// ====================================================================================================
static void _quietReport( enum verbLevel l, const char *fmt, ... )

/* Report sink for the I-sync search decoder: its messages are not wanted */

{
    ( void )l;
    ( void )fmt;
}
// ====================================================================================================
static void _isyncCB( void *d )

/* The I-sync search decoder reported something: the first report after an A-sync is the I-sync */

{
    *( bool * )d = true;
}
// ====================================================================================================
static int64_t _isyncEnd( struct RunTime *r, int64_t from )

/* Offset just after the first I-sync following the A-sync at from (or from, if there is none   */
/* within ISYNC_SEARCH_BYTES). A decoder starting at an A-sync can place instructions only from */
/* that I-sync on, and on Cortex-M the I-sync can come a good number of bytes after the A-sync. */

{
    static struct TRACEDecoder sd;
    static bool sdInit = false;

    if ( !sdInit )
    {
        TRACEDecoderInit( &sd, r->options->traceProt, !( r->options->noAltAddr ), _quietReport );
        sdInit = true;
    }

    TRACEDecoderForceSync( &sd, false );

    int64_t len = _pmLen( r );
    bool got = false;

    for ( int64_t o = from; ( o < len ) && ( o < from + ISYNC_SEARCH_BYTES ); o++ )
    {
        uint8_t c = _pmByte( r, o );
        TRACEDecoderPump( &sd, &c, 1, _isyncCB, &got );

        if ( got )
        {
            return o + 1;
        }
    }

    return from;
}
// ====================================================================================================
static int64_t _windowEnd( struct RunTime *r, int k )

/* Where decoding window k stops: the end of the buffer for the last window, otherwise just after */
/* the first I-sync of window k + 1. Window k + 1 starts at its A-sync, but its decoder has no    */
/* address until that I-sync, so the instructions in between are decoded here, by window k.      */

{
    if ( k >= r->wNum - 1 )
    {
        return r->wBound[r->wNum];
    }

    return _isyncEnd( r, r->wBound[k + 1] );
}
// ====================================================================================================
static struct sioline *_decodeWindow( struct RunTime *r, int k, int32_t *n )

/* Decode window k into a line array of its own; *n is set to its number of lines */

{
    struct sioline *keep = r->opText;
    int32_t keepLines = r->numLines;
    int32_t keepAlloc = r->opTextAlloc;

    r->opText = NULL;
    r->numLines = 0;
    r->opTextAlloc = 0;
    _decodeRange( r, r->wBound[k], _windowEnd( r, k ) );

    struct sioline *got = r->opText;
    *n = r->numLines;

    r->opText = keep;
    r->numLines = keepLines;
    r->opTextAlloc = keepAlloc;
    return got;
}
// ====================================================================================================
static void _insertLines( struct RunTime *r, int32_t at, struct sioline *l, int32_t n )

/* Put n lines (from _decodeWindow, freed here) into the output buffer before line at */

{
    if ( r->numLines + n > r->opTextAlloc )
    {
        struct sioline *t = ( struct sioline * )realloc( r->opText, sizeof( struct sioline ) * ( ( size_t )r->numLines + n ) );

        if ( !t )
        {
            genericsExit( -1, "Out of memory for display lines, use a smaller -W" EOL );
        }

        r->opText = t;
        r->opTextAlloc = r->numLines + n;
    }

    memmove( &r->opText[at + n], &r->opText[at], sizeof( struct sioline ) * ( r->numLines - at ) );

    if ( n )
    {
        memcpy( &r->opText[at], l, sizeof( struct sioline ) * n );
    }

    r->numLines += n;
    free( l );
}
// ====================================================================================================
static void _removeLines( struct RunTime *r, int32_t at, int32_t n )

/* Remove n lines from the output buffer, starting at line at */

{
    for ( int32_t i = at; i < at + n; i++ )
    {
        if ( !r->opText[i].isRef )
        {
            free( r->opText[i].buffer );
        }
    }

    memmove( &r->opText[at], &r->opText[at + n], sizeof( struct sioline ) * ( r->numLines - at - n ) );
    r->numLines -= n;
}
// ====================================================================================================
static void _windowsSet( struct RunTime *r, int64_t start, int64_t len )

/* One window, [start, len), decoded and holding all lines of the output buffer */

{
    if ( !r->wBound )
    {
        r->wAlloc = 16;
        r->wBound = ( int64_t * )malloc( sizeof( int64_t ) * ( r->wAlloc + 1 ) );
        r->wLines = ( int32_t * )malloc( sizeof( int32_t ) * r->wAlloc );

        if ( ( !r->wBound ) || ( !r->wLines ) )
        {
            genericsExit( -1, "Out of memory" EOL );
        }
    }

    r->wBound[0] = start;
    r->wBound[1] = len;
    r->wNum = 1;
    r->wFirst = r->wLast = 0;
    r->wLines[0] = r->numLines;
}
// ====================================================================================================
static bool _dumpBuffer( struct RunTime *r )

/* Dump the received data buffer into the text buffer: only the last window of it (-W), so */
/* the display lines (many per buffer byte) stay within memory. _windowStep adds more.     */

{
    _flushBuffer( r );

    if ( !symbolSetValid( r->s ) )
    {
        symbolDelete( r->s );

        if ( !( r->s = symbolAcquire( r->options->elffile, true, true ) ) )
        {
            genericsReport( V_ERROR, "Elf file or symbols in it not found" EOL );
            return false;
        }

        genericsReport( V_DEBUG, "Loaded %s" EOL, r->options->elffile );
    }

    int64_t len = _pmLen( r );
    int64_t start = 0;

    /* MTB has no sync points to start decoding at, so it is always decoded whole */
    if ( ( r->options->traceProt != TRACE_PROT_MTB ) && ( len > r->options->window ) )
    {
        start = _syncAtOrBefore( r, len - r->options->window );

        if ( start < 0 )
        {
            start = 0;
        }
    }

    _decodeRange( r, start, len );
    _windowsSet( r, start, len );

    /* Submit this constructed buffer for display */
    SIOsetOutputBuffer( r->sio, r->numLines, r->numLines - 1, &r->opText, false );

    if ( start )
    {
        static char winMsg[120];
        snprintf( winMsg, sizeof( winMsg ), "Decoded the last %" PRId64 " of %" PRId64 " KB (Up/PgUp/Home at the top for more)",
                  ( len - start ) / 1024, len / 1024 );
        SIOalert( r->sio, winMsg );
    }

    return true;
}
// ====================================================================================================
static void _windowStep( struct RunTime *r, bool earlier )

/* The cursor is at the top (earlier) or bottom of the decoded part: decode the window before or */
/* after it, then free the windows more than WINDOWS_KEPT_EACH_SIDE away from the cursor's one.  */

{
    int32_t cur = SIOgetCurrentLineno( r->sio );
    int32_t added = 0;
    int k;

    if ( !r->wNum )
    {
        SIObeep();
        return;
    }

    if ( earlier )
    {
        if ( r->wFirst > 0 )
        {
            /* Decoded before and freed again: its bounds are known */
            k = r->wFirst - 1;
        }
        else
        {
            /* A new window in front of all the known ones */
            int64_t b0 = r->wBound[0];
            int64_t from = ( b0 > r->options->window ) ? _syncAtOrBefore( r, b0 - r->options->window ) : 0;

            if ( from < 0 )
            {
                from = 0;
            }

            if ( from >= b0 )
            {
                SIOalert( r->sio, "Start of the buffer" );
                return;
            }

            if ( r->wNum + 1 > r->wAlloc )
            {
                r->wAlloc *= 2;
                r->wBound = ( int64_t * )realloc( r->wBound, sizeof( int64_t ) * ( r->wAlloc + 1 ) );
                r->wLines = ( int32_t * )realloc( r->wLines, sizeof( int32_t ) * r->wAlloc );

                if ( ( !r->wBound ) || ( !r->wLines ) )
                {
                    genericsExit( -1, "Out of memory" EOL );
                }
            }

            memmove( &r->wBound[1], &r->wBound[0], sizeof( int64_t ) * ( r->wNum + 1 ) );
            memmove( &r->wLines[1], &r->wLines[0], sizeof( int32_t ) * r->wNum );
            r->wBound[0] = from;
            r->wNum++;
            r->wFirst++;
            r->wLast++;
            k = 0;
        }

        int32_t n;
        struct sioline *l = _decodeWindow( r, k, &n );
        _insertLines( r, 0, l, n );
        r->wLines[k] = n;
        r->wFirst = k;
        cur += n;
        added = n;
    }
    else
    {
        if ( r->wLast >= r->wNum - 1 )
        {
            SIOalert( r->sio, "End of the buffer" );
            return;
        }

        int32_t n;
        k = r->wLast + 1;
        struct sioline *l = _decodeWindow( r, k, &n );
        _insertLines( r, r->numLines, l, n );
        r->wLines[k] = n;
        r->wLast = k;
    }

    /* The window the cursor is in */
    int c = r->wFirst;
    int32_t acc = 0;

    while ( ( c < r->wLast ) && ( cur >= acc + r->wLines[c] ) )
    {
        acc += r->wLines[c];
        c++;
    }

    /* Free the windows too far from it */
    int32_t removedFront = 0;

    while ( r->wFirst < c - WINDOWS_KEPT_EACH_SIDE )
    {
        _removeLines( r, 0, r->wLines[r->wFirst] );
        removedFront += r->wLines[r->wFirst];
        r->wFirst++;
    }

    while ( r->wLast > c + WINDOWS_KEPT_EACH_SIDE )
    {
        _removeLines( r, r->numLines - r->wLines[r->wLast], r->wLines[r->wLast] );
        r->wLast--;
    }

    cur -= removedFront;
    SIOsetOutputBuffer( r->sio, r->numLines, cur, &r->opText, false );
    SIOlinesInserted( r->sio, added - removedFront );

    static char stepMsg[120];
    int64_t len = _pmLen( r );
    snprintf( stepMsg, sizeof( stepMsg ), "Showing %" PRId64 "-%" PRId64 " of %" PRId64 " KB (%d window%s)",
              r->wBound[r->wFirst] / 1024, _windowEnd( r, r->wLast ) / 1024, len / 1024,
              r->wLast - r->wFirst + 1, ( r->wLast > r->wFirst ) ? "s" : "" );
    SIOalert( r->sio, stepMsg );
}
// ====================================================================================================
static struct symbolLineStore *_fileAndLine( struct RunTime *r, uint32_t i )

/* Find the source line record for buffer line i: the nearest source or assembly line with a  */
/* line record at or above i, but not past a function header (that would be another function, */
/* e.g. the code an interrupt broke into). Failing that, look below i.                        */

{
    #define _HASREF(n) ( ( ( r->opText[n].lt == LT_SOURCE ) || ( r->opText[n].lt == LT_ASSEMBLY ) || \
                           ( r->opText[n].lt == LT_NASSEMBLY ) ) && ( r->opText[n].dat != NULL ) )

    if ( ( !r->numLines ) || ( i >= ( uint32_t )r->numLines ) )
    {
        return NULL;
    }

    /* Upwards, stopping at the header of the function we're in */
    for ( int32_t n = i; n >= 0; n-- )
    {
        if ( _HASREF( n ) )
        {
            return ( struct symbolLineStore * )r->opText[n].dat;
        }

        if ( r->opText[n].lt == LT_FILE )
        {
            break;
        }
    }

    /* Downwards (e.g. the cursor is on a function header) */
    for ( int32_t n = i; n < r->numLines; n++ )
    {
        if ( _HASREF( n ) )
        {
            return ( struct symbolLineStore * )r->opText[n].dat;
        }
    }

    return NULL;
    #undef _HASREF
}
// ====================================================================================================
static void _mapFileBuffer( struct RunTime *r, int lineno, int filenameIndex )

/* Map filename records into buffer */

{
    /* Get line reference from current buffer */
    assert( r->fileopText == NULL );
    assert( r->filenumLines == 0 );
    unsigned int index = 0;
    const char *c;

    r->filenumLines = 0;

    while ( ( c = symbolSource( r->s, filenameIndex, index++ ) ) )
    {
        r->fileopText = ( struct sioline * )realloc( r->fileopText, ( sizeof( struct sioline ) ) * ( r->filenumLines + 1 ) );

        /* This line removes the 'const', but we know to not mess with this line */
        r->fileopText[r->filenumLines].buffer = ( char * )c;
        r->fileopText[r->filenumLines].dat    = NULL;
        r->fileopText[r->filenumLines].lt     = LT_MU_SOURCE;
        r->fileopText[r->filenumLines].isRef  = true;
        r->fileopText[r->filenumLines].line   = r->filenumLines + 1;
        r->filenumLines++;
    }

    SIOsetOutputBuffer( r->sio, r->filenumLines, lineno - 1, &r->fileopText, true );
    r->diving = true;
}
// ====================================================================================================
static void _doFileDive( struct RunTime *r )

/* Do actions required to get file contents to dive into */

{
    static struct symbolLineStore *l;

    if ( ( r->diving ) || ( !r->numLines ) || ( !r->held ) )
    {
        return;
    }

    /* There should be no file read in at the moment */
    assert( !r->fileopText );
    assert( !r->filenumLines );

    if ( !( l = _fileAndLine( r, SIOgetCurrentLineno( r->sio ) ) ) )
    {
        SIOalert( r->sio, "Couldn't get filename/line" );
        return;
    }

    /* Cache the line in this file in case we need it later */
    r->lineNum = SIOgetCurrentLineno( r->sio );

    _mapFileBuffer( r,  l->startline, l->filename );
}
// ====================================================================================================
static void _doFilesurface( struct RunTime *r )

/* Come back out of a file we're diving into */

{
    if ( !r->diving )
    {
        return;
    }

    /* Buffer is a ref so we don't need to delete it, just remove the index */
    free( r->fileopText );
    r->fileopText = NULL;
    r->filenumLines = 0;
    r->diving = false;

    SIOsetOutputBuffer( r->sio, r->numLines, r->numLines - 1, &r->opText, false );
    SIOsetCurrentLineno( r->sio, r->lineNum );
}
// ====================================================================================================
static void _doSave( struct RunTime *r, bool includeDebug )

/* Save buffer in both raw and processed formats */

{
    FILE *f;
    char fn[SCRATCH_STRING_LEN];
    uint32_t w;
    char *p;

    snprintf( fn, SCRATCH_STRING_LEN, "%s.trace", SIOgetSaveFilename( r->sio ) );
    f = fopen( fn, "wb" );

    if ( !f )
    {
        SIOalert( r->sio, "Save Trace Failed" );
        return;
    }

    w = r->rp;

    while ( w != r->wp )
    {
        fwrite( &r->pmBuffer[w], 1, 1, f );
        w = ( w + 1 ) % r->options->buflen;
    }

    fclose( f );

    snprintf( fn, SCRATCH_STRING_LEN, "%s.report", SIOgetSaveFilename( r->sio ) );
    f = fopen( fn, "wb" );

    if ( !f )
    {
        SIOalert( r->sio, "Save Report Failed" );
        return;
    }

    w = 0;

    while ( w != r->numLines )
    {
        p = r->opText[w].buffer;

        /* Skip blank and debug lines unless specifically told to include them */
        if ( !p || ( ( r->opText[w].lt == LT_DEBUG ) && ( !includeDebug ) ) )
        {
            w++;
            continue;
        }

        if ( ( r->opText[w].lt == LT_SOURCE ) || ( r->opText[w].lt == LT_MU_SOURCE ) )
        {
            /* Need a line number on this */
            fwrite( fn, sprintf( fn, "%5d ", r->opText[w].line ), 1, f );
        }

        if ( r->opText[w].lt == LT_NASSEMBLY )
        {
            /* This is an _unexecuted_ assembly line, need to mark it */
            fwrite( "(**", 3, 1, f );
        }

        /* Search forward for a NL or 0, both are EOL for this purpose */
        while ( ( *p ) && ( *p != '\n' ) && ( *p != '\r' ) )
        {
            p++;
        }

        fwrite( r->opText[w].buffer, p - r->opText[w].buffer, 1, f );

        if ( r->opText[w].lt == LT_NASSEMBLY )
        {
            /* This is an _unexecuted_ assembly line, need to mark it */
            fwrite( " **)", 4, 1, f );
        }

        fwrite( EOL, strlen( EOL ), 1, f );
        w++;
    }

    fclose( f );

    SIOalert( r->sio, "Save Complete" );
}
// ====================================================================================================
static void _doExit( void )

/* Perform any explicit exit functions */

{
    _r.ending = true;
    /* Give them a bit of time, then we're leaving anyway */
    usleep( 200 );
    SIOterminate( _r.sio );
}

// ====================================================================================================
// ====================================================================================================
// ====================================================================================================
// Publicly available routines
// ====================================================================================================
// ====================================================================================================
// ====================================================================================================
int main( int argc, char *argv[] )

{
    int32_t lastTTime, lastTSTime, lastHTime;
    struct Stream *stream;              /* Stream that we are collecting data from */
    struct timeval tv;
    enum SIOEvent s;

    /* Have a basic name and search string set up */
    _r.progName = genericsBasename( argv[0] );

    /* This is set here to avoid huge .data section in startup image */
    _r.options = &_options;

    if ( !_processOptions( argc, argv, &_r ) )
    {
        /* processOptions generates its own error messages */
        genericsExit( -1, "" EOL );
    }

    genericsScreenHandling( !_r.options->mono );

    /* Make sure any cleanup happens at the end */
    atexit( _doExit );

    if ( _r.options->file != NULL )
    {
        if ( NULL == ( stream = streamCreateFile( _r.options->file ) ) )
        {
            genericsExit( V_ERROR, "File not found" EOL );
            _r.ending = true;
        }
    }

    /* Check we've got _some_ symbols to start from */
    _r.s = symbolAcquire( _r.options->elffile, true, true );

    if ( !_r.s )
    {
        genericsReport( V_ERROR, "Elf file or symbols in it not found" EOL );
        return -1;
    }

    genericsReport( V_DEBUG, "Loaded %s" EOL, _r.options->elffile );

    /* This ensures the atexit gets called */
    if ( SIG_ERR == signal( SIGINT, _intHandler ) )
    {
        genericsExit( -1, "Failed to establish Int handler" EOL );
    }

    /* Fill in a time to start from */
    lastHTime = lastTTime = lastTSTime = genericsTimestampmS();


#if !defined( WIN32 )

    /* Don't kill a sub-process when any reader or writer evaporates */
    if ( SIG_ERR == signal( SIGPIPE, SIG_IGN ) )
    {
        genericsExit( -1, "Failed to ignore SIGPIPEs" EOL );
    }

#endif

    /* Create the buffer memory */
    _r.pmBuffer = ( uint8_t * )calloc( 1, _r.options->buflen );

    TRACEDecoderInit( &_r.i, _r.options->traceProt, !( _r.options->noAltAddr ), _traceReport );

    if ( _r.options->holdAt )
    {
        if ( _r.options->traceProt != TRACE_PROT_ETM35 )
        {
            genericsExit( -1, "-x (hold at function) is only supported for ETM3.5 trace" EOL );
        }

        /* The live tracker needs the symbols from the start */
        if ( !( _r.s = symbolAcquire( _r.options->elffile, true, true ) ) )
        {
            genericsExit( -1, "Elf file or symbols in it not found" EOL );
        }

        if ( !_holdResolve( &_r ) )
        {
            genericsExit( -1, "Function %s not found in %s (or use -x 0x<address>)" EOL, _r.options->holdAt, _r.options->elffile );
        }

        TRACEDecoderInit( &_r.ti, _r.options->traceProt, !( _r.options->noAltAddr ), _traceReport );
        _holdReset( &_r );
    }

    OFLOWInit( &_r.c );

    /* Create a screen and interaction handler */
    _r.sio = SIOsetup( _r.progName, _r.options->elffile, ( _r.options->file != NULL ) );

    /* Put a record of the protocol in use on screen */
    SIOtagText( _r.sio, TRACEDecodeGetProtocolName( _r.options->traceProt ) );

    if ( _r.options->holdAt )
    {
        static char armMsg[256];
        int o = snprintf( armMsg, sizeof( armMsg ), "Will hold at %s", _r.holdName );

        for ( int n = 0; ( n < _r.holdNumRanges ) && ( o < ( int )sizeof( armMsg ) - 24 ); n++ )
        {
            o += snprintf( &armMsg[o], sizeof( armMsg ) - o, " (0x%08x-0x%08x)", _r.holdLowR[n], _r.holdHighR[n] );
        }
        SIOalert( _r.sio, armMsg );
    }

    while ( !_r.ending )
    {
        if ( NULL == _r.options->file )
        {
            /* Keep trying to open a network connection at half second intervals */
            while ( 1 )
            {
                stream = streamCreateSocket( _r.options->server, _r.options->port + ( ( PROT_OFLOW != _r.options->commProt ) ? 1 : 0 ) );

                if ( stream )
                {
                    break;
                }

                /* This can happen when the feeder has gone missing... */
                SIOalert( _r.sio, "No connection" );

                if ( SIOHandler( _r.sio, true, 0, _r.options->withDebugText ) == SIO_EV_QUIT )
                {
                    _r.ending = true;
                    break;
                }

                usleep( 1000000 );
            }
        }

        /* ----------------------------------------------------------------------------- */
        /* This is the main active loop...only break out of this when ending or on error */
        /* ----------------------------------------------------------------------------- */
        while ( !_r.ending )
        {
            tv.tv_sec = 0;
            tv.tv_usec  = 10000;

            if ( stream )
            {
                /* We always read the data, even if we're held, to keep the socket alive */
                enum ReceiveResult result = stream->receive( stream, _r.rawBlock.buffer, TRANSFER_SIZE, &tv, ( size_t * )&_r.rawBlock.fillLevel );

                /* Try to re-establish socket if there was an error */
                if ( result == RECEIVE_RESULT_ERROR )
                {
                    break;
                }

                if ( ( ( result == RECEIVE_RESULT_EOF ) || ( _r.rawBlock.fillLevel <= 0 ) ) && _r.options->file )
                {
                    /* Read from file is complete, remove it */
                    stream->close( stream );
                    free( stream );

                    stream = NULL;
                }
            }
            else
            {
                /* No point in checking for keypresses _too_ often! */
                usleep( TICK_TIME_MS * 100 );
            }

            if ( !_r.held )
            {
                /* Pump all of the data through the protocol handler */

                if ( PROT_OFLOW == _r.options->commProt )
                {
                    OFLOWPump( &_r.c, _r.rawBlock.buffer, _r.rawBlock.fillLevel, _OFLOWpacketRxed, &_r );
                }
                else
                {
                    _processBlock( &_r );
                }

                /* Hold-at-function reached (and the instructions after it captured): show it */
                if ( ( _r.options->holdAt ) && ( _r.holdTriggered ) && ( _r.holdTail <= 0 ) )
                {
                    if ( _r.numLines )
                    {
                        _flushBuffer( &_r );
                    }

                    if ( !_dumpBuffer( &_r ) )
                    {
                        _r.ending = true;
                    }
                    else
                    {
                        _r.held = true;
                        SIOheld( _r.sio, _r.held );
                        static char holdMsg[128];
                        snprintf( holdMsg, sizeof( holdMsg ), "Reached %s (H to wait for the next time)", _r.holdName );
                        SIOalert( _r.sio, holdMsg );
                    }
                }
            }

            /* Update the outputs and deal with any keys that made it up this high */
            /* =================================================================== */
            switch ( ( s = SIOHandler( _r.sio, ( genericsTimestampmS() - lastTTime ) > TICK_TIME_MS, _r.oldTotalIntervalBytes, _r.options->withDebugText ) ) )
            {
                case SIO_EV_HOLD:  // ----------------- Request for Hold Start/Stop -------------------------------------
                    if ( !_r.options->file )
                    {
                        _r.held = !_r.held;

                        if ( !_r.held )
                        {
                            _r.wp = _r.rp = 0;

                            if ( _r.options->holdAt )
                            {
                                /* Re-arm: wait for the next time the function is reached */
                                _holdReset( &_r );
                            }

                            if ( _r.diving )
                            {
                                _doFilesurface( &_r );
                            }

                            _flushBuffer( &_r );
                        }

                        /* Flag held status to the UI */
                        SIOheld( _r.sio, _r.held );
                    }

                    break;

                case SIO_EV_PREV:
                case SIO_EV_NEXT: // ----------------- Request for next/prev execution line -----------------------------
                    if ( !_r.diving )
                    {
                        int32_t l = SIOgetCurrentLineno( _r.sio );

                        if ( ( ( s == SIO_EV_PREV ) && ( !l ) ) || ( ( s == SIO_EV_NEXT ) && ( l >= _r.numLines - 1 ) ) )
                        {
                            break;
                        }

                        /* In a regular window, scroll back looking for an earlier assembly instruction */
                        do
                        {
                            l += s == SIO_EV_PREV ? -1 : 1;
                        }
                        while ( l && ( l < _r.numLines - 1 ) && ( ( _r.opText[l].lt != LT_ASSEMBLY ) ) );

                        if ( l )
                        {
                            SIOsetCurrentLineno( _r.sio, l );
                            SIOrequestRefresh( _r.sio );
                        }
                        else
                        {
                            SIObeep();
                        }
                    }
                    else
                    {
                        /* In a diving window, situation is slightly more complicated */
                        int32_t l = _r.lineNum;
                        struct symbolLineStore *oldLine = _fileAndLine( &_r, l );

                        if ( ( ( s == SIO_EV_PREV ) && ( !l ) ) || ( ( s == SIO_EV_NEXT ) && ( l >= _r.numLines - 1 ) ) )
                        {
                            break;
                        }

                        /* Search for different _source_line_ to the one we started from */
                        do
                        {
                            l += s == SIO_EV_PREV ? -1 : 1;
                        }
                        while ( l && ( l < _r.numLines - 1 ) && ( ( _r.opText[l].lt != LT_SOURCE ) ) );

                        struct symbolLineStore *newLine = l ? _fileAndLine( &_r, l ) : NULL;

                        if ( ( newLine ) && ( oldLine ) )
                        {
                            if ( oldLine->filename == newLine->filename )
                            {
                                /* We are still in the same file, so only the line number to change */
                                _r.lineNum = l;
                                SIOsetCurrentLineno( _r.sio, newLine->startline - 1 );
                                SIOrequestRefresh( _r.sio );
                            }
                            else
                            {
                                /* We have changed diving file, surface and enter the new one */
                                _r.lineNum = l;
                                _doFilesurface( &_r );
                                _doFileDive( &_r );
                                SIOrequestRefresh( _r.sio );
                            }
                        }
                        else
                        {
                            SIObeep();
                        }

                    }

                    break;

                case SIO_EV_EARLIER: // --------------- Cursor at the top: decode the trace before it ---------------------
                case SIO_EV_LATER: // ----------------- Cursor at the bottom: decode the trace after it -------------------
                    if ( ( !_r.diving ) && ( _r.numLines ) )
                    {
                        _windowStep( &_r, s == SIO_EV_EARLIER );
                    }

                    break;

                case SIO_EV_SAVE: // ------------------ Request for file save -------------------------------------------
                    if ( !_r.options->file )
                    {
                        _doSave( &_r, false );
                    }

                    break;

                case SIO_EV_DIVE: // -------------------- Request for dive into source file -----------------------------
                    _doFileDive( &_r );
                    break;

                case SIO_EV_FOPEN: // ------------------- Request for file open -----------------------------------------
                    if ( _r.options->openFileCL )
                    {
                        //                        _doFileOpen( &_r, false );
                    }

                    break;

                case SIO_EV_SURFACE: // --------------------- Request for file surface ----------------------------------
                    _doFilesurface( &_r );
                    break;

                case SIO_EV_QUIT: // ------------------------- Request to exit ------------------------------------------
                    _r.ending = true;
                    break;

                default:
                    break;
            }

            /* Deal with possible timeout on sampling, or if this is a read-from-file that is finished */
            if ( ( !_r.numLines )  &&
                    (
                                ( _r.options->file && !stream ) ||
                                ( ( ( genericsTimestampmS() - lastHTime ) > HANG_TIME_MS ) &&
                                  ( _r.newTotalBytes - _r.oldTotalHangBytes == 0 ) &&
                                  ( _r.wp != _r.rp ) )
                    )
               )
            {
                if ( !_dumpBuffer( &_r ) )
                {
                    /* Dumping the buffer failed, so give up */
                    _r.ending = true;
                }
                else
                {
                    _r.held = true;
                    SIOheld( _r.sio, _r.held );
                }
            }

            /* Update the intervals */
            if ( ( genericsTimestampmS() - lastHTime ) > HANG_TIME_MS )
            {
                _r.oldTotalHangBytes = _r.newTotalBytes;
                lastHTime = genericsTimestampmS();
            }

            if ( ( genericsTimestampmS() - lastTTime ) > TICK_TIME_MS )
            {
                lastTTime = genericsTimestampmS();
            }

            if ( ( genericsTimestampmS() - lastTSTime ) > INTERVAL_TIME_MS )
            {
                _r.oldTotalIntervalBytes = _r.newTotalBytes - _r.oldTotalBytes;
                _r.oldTotalBytes = _r.newTotalBytes;

                if ( ( _r.options->holdAt ) && ( !_r.held ) )
                {
                    /* Show what the live tracker is doing while waiting for the hold function */
                    static char hsMsg[200];
                    snprintf( hsMsg, sizeof( hsMsg ), "%s: %" PRIu64 "KB %s cb %" PRIu64 " addr %" PRIu64 " ins %" PRIu64 "K lost %" PRIu64 " at %08x",
                              _r.holdName, _r.hsBytes / 1024, TRACEDecoderIsSynced( &_r.ti ) ? "sync" : "NOSYNC",
                              _r.hsCallbacks, _r.hsAddrs, _r.hsInstr / 1000, _r.hsLost, _r.holdAddr );
                    SIOalert( _r.sio, hsMsg );
                }
                lastTSTime = genericsTimestampmS();
            }
        }

        /* ----------------------------------------------------------------------------- */
        /* End of main loop ... we get here because something forced us out              */
        /* ----------------------------------------------------------------------------- */

        if ( stream )
        {
            stream->close( stream );
            free( stream );

            stream = NULL;
        }

        if ( _r.options->file )
        {
            /* Don't keep re-reading the file if it is a file! */
            _r.held = true;
        }

        if ( _r.options->fileTerminate )
        {
            _r.ending = true;
        }
    }

    symbolDelete( _r.s );
    return OK;
}

// ====================================================================================================
