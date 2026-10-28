/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * Profiling module for Orbuculum
 * ==============================
 *
 */

#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <semaphore.h>
#include <pthread.h>
#include <assert.h>
#include <getopt.h>

#include "git_version_info.h"
#include "uthash.h"
#include "generics.h"
#include "traceDecoder.h"
#include "oflow.h"
#include "symbols.h"
#include "nw.h"
#include "ext_fileformats.h"
#include "stream.h"

#define TICK_TIME_MS        (1)          /* Time intervals for checks */
#define DEFAULT_DURATION_MS (1000)       /* Default time to sample, in mS */
#define HANDLE_MASK         (0xFFFFFF)   /* cachegrind cannot cope with large file handle numbers */

enum Prot { PROT_OFLOW, PROT_ETM, PROT_UNKNOWN };
const char *protString[] = {"OFLOW", "ETM", NULL};

/* How many transfer buffers from the source to allocate */
#define NUM_RAW_BLOCKS (1000)

#ifdef ORBPROFILE_DEBUG
#define DBG_OUT(...) fprintf(stderr,__VA_ARGS__)
#else
#define DBG_OUT(...)
#endif

/* Instructions skipped because the trace position wasn't known (e.g. after an indirect branch) */
static uint64_t _lostInstructions;

struct _subcallAccount
{
    struct subcallSig sig;
    uint64_t inTicks;
};


/* ---------- CONFIGURATION ----------------- */
struct Options                           /* Record for options, either defaults or from command line */
{
    bool demangle;                       /* Demangle C++ names */
    char *file;                          /* File host connection */
    bool fileTerminate;                  /* Terminate when file read isn't successful */

    char *deleteMaterial;                /* Material to strip off front of filenames for target */
    bool truncateDeleteMaterial;         /* Do we want this material totally removing from file references? */

    char *elffile;                       /* Target program config */
    char *odoptions;                     /* Options to pass directly to objdump */

    char *dotfile;                       /* File to output dot information */
    char *profile;                       /* File to output profile information */
    int  sampleDuration;                 /* How long we are going to sample for */
    bool mono;                           /* Supress colour in output */
    bool noaltAddr;                      /* Dont use alternate addressing */
    int  tag;                            /*  Which OFLOW stream are we decoding? */
    enum TRACEprotocol tProtocol;        /* Encoding protocol to use */

    int  port;                           /* Source information for where to connect to */
    char *server;
    enum Prot protocol;                  /* What protocol to communicate (default to OFLOW (== orbuculum)) */


} _options =
{
    .demangle       = true,
    .sampleDuration = DEFAULT_DURATION_MS,
    .port           = OFCLIENT_SERVER_PORT,
    .tProtocol      = TRACE_PROT_ETM35,
    .tag            = 2,
    .server         = "localhost"
};

/* State of routine tracking, maintained across TRACE callbacks to reconstruct program flow */
struct opConstruct
{
    struct execEntryHash *h;             /* The exec entry we were in last (file, function, line, addr etc) */
    struct execEntryHash *oldh;          /* The exec entry we're currently in (file, function, line, addr etc) */
    struct execEntryHash *inth;          /* Fake exec entry for an interrupt source */
    uint32_t workingAddr;                /* The address we're currently in */
    uint32_t nextAddr;                   /* The address we will next be accessing (if known) */
    uint32_t lastfn;                     /* The function of the last instruction carried out */

    uint64_t firsttstamp;                /* First timestamp we recorded (that was valid) */
    uint64_t lasttstamp;                 /* Last timestamp we recorded (that was valid) */

    bool isExceptReturn;                 /* Is this flagged as an exception return? */
    bool isException;                    /* Is this flagged as an exception? */
};

/* A block of received data */
struct dataBlock
{
    ssize_t fillLevel;
    uint8_t buffer[TRANSFER_SIZE];
};

/* ----------- LIVE STATE ----------------- */
struct RunTime
{
    /* Information about the program */
    const char *progName;                       /* Name by which this program was called */

    /* Subsystem data support */
    struct TRACEDecoder i;
    struct SymbolSet *s;                        /* Symbols read from elf */
    struct OFLOW c;

    /* Calls related info */
    struct edge *calls;                         /* Call data table */
    struct subcall *subhead;                    /* Calls onstruct data */
    struct execEntryHash *insthead;             /* Exec table handle for hash */

    /* Subroutine related info...the call stack and its length */
    struct _subcallAccount *substack;           /* Calls stack data */
    uint32_t substacklen;                       /* Calls stack length */

    /* Stats about the run */
    int instCount;                              /* Number of instruction locations */
    uint64_t callsCount;                        /* Call data count */
    uint64_t intervalBytes;                     /* Number of bytes transferred in current interval */

    /* State of the target tracker */
    struct opConstruct op;                      /* The mechanical elements for creating the output buffer */

    /* Subprocess control and interworking */
    pthread_t processThread;                    /* Thread handling received data flow */
    pthread_cond_t dataForClients;              /* Semaphore counting data for clients */
    pthread_mutex_t dataForClients_m;           /* Mutex for counting data for clients */

    /* Ring buffer for samples ... this 'pads' the rate data arrive and how fast they can be processed */
    int wp;                                     /* Read and write pointers into transfer buffers */
    int rp;
    struct dataBlock rawBlock[NUM_RAW_BLOCKS];  /* Transfer buffers from the receiver */

    /* State info */
    volatile bool ending;                       /* Flag indicating app is terminating */
    bool     sampling;                          /* Are we actively sampling at the moment */
    uint32_t starttime;                         /* At what time did we start sampling? */

    /* Turn addresses into files and routines tags */
    uint32_t nameCount;
    struct nameEntryHash *name;

    struct Options *options;                    /* Our runtime configuration */

} _r;

// ====================================================================================================
// ====================================================================================================
// ====================================================================================================
// Internally available routines
// ====================================================================================================
// ====================================================================================================
// ====================================================================================================
static void _callEvent( struct RunTime *r, uint32_t retAddr, uint32_t to )

/* This is a call or a return, manipulate stack tracking appropriately */

{
    struct TRACECPUState *cpu = TRACECPUState( &r->i );
    struct subcall *s;

    /* ...add it to the call stack */
    r->substack = ( struct _subcallAccount * )realloc( r->substack, ( r->substacklen + 1 ) * sizeof( struct _subcallAccount ) );

    /* This is a call */
    r->substack[r->substacklen].sig.src     = retAddr;
    r->substack[r->substacklen].sig.dst     = to;
    r->substack[r->substacklen].inTicks     = cpu->instCount;

    /* Find a record for this source/dest pair */
    HASH_FIND( hh, r->subhead, &r->substack[r->substacklen].sig, sizeof( struct subcallSig ), s );

    if ( !s )
    {
        /* This call entry doesn't exist (i.e. it's the first time this from/to pair have been seen...let's create it */
        s = ( struct subcall * )calloc( 1, sizeof( struct subcall ) );
        MEMCHECKV( s );
        memcpy( &s->sig, &r->substack[r->substacklen].sig, sizeof( struct subcallSig ) );
        HASH_ADD( hh, r->subhead, sig, sizeof( struct subcallSig ), s );
    }

    r->substacklen++;

#ifdef ORBPROFILE_DEBUG
    for ( uint32_t g = 0; g < r->substacklen; g++ )
    {
        putchar( ' ' );
    }
#endif

    DBG_OUT( "INC:%3d %08x -> %08x" EOL, r->substacklen, retAddr, to );
}
// ====================================================================================================
static void _returnEvent( struct RunTime *r, uint32_t to )

/* This is a return, manipulate stack tracking appropriately */

{
    struct TRACECPUState *cpu = TRACECPUState( &r->i );
    struct subcall *s;
    uint32_t orig = r->substacklen;

    /* Cover the startup case that we happen to hit a return before a call */
    if ( !r->substack )
    {
        return;
    }

    /* Check we've got a valid stack entry to match to */
    do
    {
        if ( !r->substacklen )
        {
            DBG_OUT( "OUT OUT OF STACK ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" EOL );
            break;
        }

        /* The -1th entry was the last written, so see if that is back far enough */
        r->substacklen--;

#ifdef ORBPROFILE_DEBUG
        for ( uint32_t g = 0; g < r->substacklen + 1; g++ )
        {
            putchar( ' ' );
        }
#endif

        DBG_OUT( " DEC:%3d %08x " EOL, r->substacklen + 1, r->substack[r->substacklen].sig.src );
        HASH_FIND( hh, r->subhead, &r->substack[r->substacklen].sig, sizeof( struct subcallSig ), s );
        assert( s );

        /* We don't bother deallocating memory here cos it'll be done the next time we make a call */
        s->myCost += cpu->instCount - r->substack[r->substacklen].inTicks;
        s->count++;
    }
    while ( to != r->substack[r->substacklen].sig.src );

    /* Check function we popped back to matches where we think we should be */
    if ( to != r->substack[r->substacklen].sig.src )
    {
        for ( uint32_t ty = 0; ty < orig; ty++ )
        {
            DBG_OUT( "%d:%08X ", ty, r->substack[ty].sig.src );
        }

        DBG_OUT( "(wanted %08x, got %08x)" EOL, to, r->substack[r->substacklen].sig.src );
    }
}
// ====================================================================================================
static bool _hashFindOrCreate( struct RunTime *r, uint32_t addr, struct execEntryHash **h )

/* Find the record for this instruction address, or create it. Returns false if the address */
/* isn't a known instruction (unknown position after an indirect branch, code outside the   */
/* ELF file, or a mis-decode), so the caller can skip it instead of crashing or exiting.    */

{
    struct nameEntry n;

    HASH_FIND_INT( r->insthead, &addr, *h );

    if ( *h )
    {
        return true;
    }

    if ( ( addr & SPECIALS_MASK ) == SPECIALS_MASK )
    {
        /* Placeholder address (e.g. NO_DESTADDRESS after BLX rx): position unknown */
        return false;
    }

    if ( !SymbolLookup( r->s, addr, &n ) )
    {
        genericsReport( V_DEBUG, "No symbol for address %08x" EOL, addr );
        return false;
    }

    if ( ( !n.assy ) || ( n.assyLine == ASSY_NOT_FOUND ) )
    {
        genericsReport( V_DEBUG, "No assembly for address %08x, %s" EOL, addr, SymbolFunction( r->s, n.functionindex ) );
        return false;
    }

    *h = calloc( 1, sizeof( struct execEntryHash ) );
    MEMCHECK( *h, false );

    ( *h )->addr          = addr;
    ( *h )->fileindex     = n.fileindex;
    ( *h )->line          = n.line;
    ( *h )->functionindex = n.functionindex;
    ( *h )->isJump        = n.assy[n.assyLine].isJump;
    ( *h )->isSubCall     = n.assy[n.assyLine].isSubCall;
    ( *h )->isReturn      = n.assy[n.assyLine].isReturn;
    ( *h )->jumpdest      = n.assy[n.assyLine].jumpdest;
    ( *h )->is4Byte       = n.assy[n.assyLine].is4Byte;
    ( *h )->codes         = n.assy[n.assyLine].codes;
    ( *h )->assyText      = n.assy[n.assyLine].lineText;

    HASH_ADD_INT( r->insthead, addr, ( *h ) );
    return true;
}
// ====================================================================================================
static struct execEntryHash *_callEndpoint( struct RunTime *r, uint32_t addr )

/* Find the instruction record for one end of a call. If that address was never recorded as     */
/* executed (e.g. an exception entry/return address), make a stand-alone record for it that is  */
/* not added to the instruction table, so it doesn't show up as executed code.                  */

{
    struct execEntryHash *h;
    struct nameEntry n;

    HASH_FIND_INT( r->insthead, &addr, h );

    if ( h )
    {
        return h;
    }

    h = ( struct execEntryHash * )calloc( 1, sizeof( struct execEntryHash ) );
    MEMCHECK( h, NULL );
    h->addr = addr;

    if ( SymbolLookup( r->s, addr, &n ) )
    {
        h->fileindex     = n.fileindex;
        h->functionindex = n.functionindex;
        h->line          = n.line;
    }
    else
    {
        h->fileindex     = NO_FILE;
        h->functionindex = NO_FUNCTION;
        h->line          = NO_LINE;
    }

    return h;
}
// ====================================================================================================
static void _resolveCalls( struct RunTime *r )

/* The DOT and KCacheGrind writers need the source and destination records of every call */

{
    for ( struct subcall *s = r->subhead; s; s = s->hh.next )
    {
        s->srch = _callEndpoint( r, s->sig.src );
        s->dsth = _callEndpoint( r, s->sig.dst );
    }
}
// ====================================================================================================
static void _handleInstruction( struct RunTime *r, bool actioned )

{
    /* ------------------------------------------------------------------------------------*/
    /* First Stage: Individual address visit accounting.                                   */
    /* Let's find the local hash record for this address, or create it if it doesn't exist */
    /* ------------------------------------------------------------------------------------*/

    r->op.oldh = r->op.h;

    if ( !_hashFindOrCreate( r, r->op.workingAddr, &r->op.h ) )
    {
        /* Position unknown: count it as lost and wait for the next address from the trace. */
        /* The interrupt placeholder record has no jump/call/return flags, so it is inert.  */
        _lostInstructions++;
        r->op.h = r->op.inth;
        return;
    }

    //    if ( r->op.oldh ) DBG_OUT( "%4d,%4d %4d %s%s%c %s", r->op.h->functionindex, ( r->op.h ? r->op.oldh->functionindex : 0 ),  r->op.h->fileindex,
    //                               ( r->op.h->isJump ) ? "J" : " ", ( r->op.h->isSubCall ) ? "S" : r->op.h->isReturn ? "R" : " ", ( actioned ) ? ( r->op.h->is4Byte ? 'X' : 'x' ) : '-',
    //                               r->op.h->assyText );

    /* OK, by hook or by crook we've got an address entry now, so increment the number of executions */
    r->op.h->count++;

    /* If source postion changed then update source code line visitation counts too */
    if ( ( r->op.oldh ) && ( ( r->op.h->line != r->op.oldh->line ) || ( r->op.h->functionindex != r->op.oldh->functionindex ) ) )
    {
        r->op.h->scount++;
    }

    /* If this is a computable destination then action it */
    if ( ( actioned ) && ( ( r->op.h->isJump ) || ( r->op.h->isSubCall ) ) )
    {
        /* Take this call ... note that the jumpdest may not be known at this point */
        r->op.workingAddr = r->op.h->jumpdest;
    }
    else
    {
        /* If it wasn't a jump or subroutine then increment the address */
        r->op.workingAddr += ( r->op.h->is4Byte ) ? 4 : 2;
    }
}

// ====================================================================================================
static void _checkJumps( struct RunTime *r )

{
    if ( r->op.h )
    {

        if ( ( TRACEStateChanged( &r->i, EV_CH_EX_EXIT ) ) || ( r->op.h->isReturn ) )
        {
            _returnEvent( r, r->op.workingAddr );
        }

        if ( r->op.h->isSubCall )
        {
            _callEvent( r, r->op.h->addr + ( ( r->op.h->is4Byte ) ? 4 : 2 ), r->op.workingAddr );
        }
    }
}
// ====================================================================================================
static void _traceCB( void *d )

/* Callback function for when valid TRACE decode is detected */

{
    struct RunTime *r       = ( struct RunTime * )d;
    struct TRACECPUState *cpu = TRACECPUState( &r->i );
    static uint32_t incAddr        = 0;
    static uint32_t disposition    = 0;

    /* This routine gets called when valid data are available */
    /* if these are the first data, then reset counters etc.  */
    if ( !r->sampling )
    {
        r->op.firsttstamp = cpu->instCount;
        genericsReport( V_INFO, "Sampling" EOL );
        /* Fill in a time to start from */
        r->starttime = genericsTimestampmS();

        if ( TRACEStateChanged( &r->i, EV_CH_ADDRESS ) )
        {
            r->op.workingAddr = cpu->addr;
            DBG_OUT( "Got initial address %08x" EOL, r->op.workingAddr );
            r->sampling  = true;
        }

        /* Create false entry for an interrupt source */
        r->op.inth = calloc( 1, sizeof( struct execEntryHash ) );

        MEMCHECKV( r->op.inth );
        r->op.inth->addr          = INTERRUPT;
        r->op.inth->fileindex     = INTERRUPT;
        r->op.inth->line          = NO_LINE;
        r->op.inth->count         = NO_LINE;
        r->op.inth->functionindex = INTERRUPT;
        HASH_ADD_INT( r->insthead, addr, r->op.inth );
    }

    r->op.lasttstamp = cpu->instCount;

    /* Pull changes introduced by this event ============================== */

    if ( TRACEStateChanged( &r->i, EV_CH_ENATOMS ) )
    {
        /* We are going to execute some instructions. Check if the last of the old batch of    */
        /* instructions was cancelled and, if it wasn't and it's still outstanding, action it. */
        if ( TRACEStateChanged( &r->i, EV_CH_CANCELLED ) )
        {
            DBG_OUT( "CANCELLED" EOL );
        }
        else
        {
            if ( incAddr )
            {
                DBG_OUT( "***" EOL );
                _handleInstruction( r, disposition & 1 );

                if ( ( r->op.h->isJump ) || ( r->op.h->isSubCall ) || ( r->op.h->isReturn ) )
                {
                    if ( TRACEStateChanged( &r->i, EV_CH_ADDRESS ) )
                    {
                        DBG_OUT( "New addr %08x" EOL, cpu->addr );
                        r->op.workingAddr = cpu->addr;
                    }

                    _checkJumps( r );
                }
            }
        }

        if ( TRACEStateChanged( &r->i, EV_CH_ADDRESS ) )
        {
            if ( TRACEStateChanged( &r->i, EV_CH_EX_ENTRY ) )
            {
                DBG_OUT( "INTERRUPT!!" EOL );
                _callEvent( r, r->op.workingAddr, cpu->addr );
            }

            r->op.workingAddr = cpu->addr;
            DBG_OUT( "A:%08x" EOL, cpu->addr );
        }

        /* ================================================ */
        /* OK, now collect the next iterations worth of fun */
        /* ================================================ */
        incAddr     = cpu->eatoms + cpu->natoms;
        disposition = cpu->disposition;
        DBG_OUT( "E:%d N:%d" EOL, cpu->eatoms, cpu->natoms );

        /* Action those changes, except the last one */
        while ( incAddr > 1 )
        {
            incAddr--;
            _handleInstruction( r, disposition & 1 );
            _checkJumps( r );
            disposition >>= 1;
        }
    }
}

// ====================================================================================================
static void _printHelp( const char *const progName )

{
    genericsFPrintf( stderr, "Usage: %s [options]" EOL, progName );
    genericsFPrintf( stderr, "    -A, --alt-addr-enc: Switch off alternate address decoding (on by default)" EOL );
    genericsFPrintf( stderr, "    -D, --no-demangle:  Switch off C++ symbol demangling" EOL );
    genericsFPrintf( stderr, "    -d, --del-prefix:   <String> Material to delete off front of filenames" EOL );
    genericsFPrintf( stderr, "    -e, --elf-file:     <ElfFile> to use for symbols" EOL );
    genericsFPrintf( stderr, "    -E, --eof:          When reading from file, terminate at EOF" EOL );
    genericsFPrintf( stderr, "    -f, --input-file:   Take input from specified file" EOL );
    genericsFPrintf( stderr, "    -h, --help:         This help" EOL );
    genericsFPrintf( stderr, "    -I, --interval:     <Interval> Time between samples (in ms)" EOL );
    genericsFPrintf( stderr, "    -M, --no-colour:    Supress colour in output" EOL );
    genericsFPrintf( stderr, "    -O, --objdump-opts: <options> Options to pass directly to objdump" EOL );
    genericsFPrintf( stderr, "    -P, --trace-proto:  {ETM35|MTB} trace protocol to use, default is ETM35" EOL );
    genericsFPrintf( stderr, "    -p, --protocol:     Protocol to communicate. Defaults to OFLOW if -s is not set, otherwise raw ETM" EOL );
    genericsFPrintf( stderr, "    -s, --server:       <Server>:<Port> to use" EOL );
    genericsFPrintf( stderr, "    -t, --tag:          <stream>: Which OFLOW tag to use (normally 2)" EOL );
    genericsFPrintf( stderr, "    -T, --all-truncate: truncate -d material off all references (i.e. make output relative)" EOL );
    genericsFPrintf( stderr, "    -v, --verbose:      <level> Verbose mode 0(errors)..3(debug)" EOL );
    genericsFPrintf( stderr, "    -V, --version:      Print version and exit" EOL );
    genericsFPrintf( stderr, "    -y, --graph-file:   <Filename> dotty filename for structured callgraph output" EOL );
    genericsFPrintf( stderr, "    -z, --cache-file:   <Filename> profile filename for kcachegrind output" EOL );
    genericsFPrintf( stderr, EOL "(Will connect one port higher than that set in -s when Orbflow is not used)" EOL );
}
// ====================================================================================================
void _printVersion( void )

{
    genericsFPrintf( stderr, "orbprofile version " GIT_DESCRIBE );
}
// ====================================================================================================
static struct option _longOptions[] =
{
    {"alt-addr-enc", no_argument, NULL, 'A'},
    {"no-demangle", required_argument, NULL, 'D'},
    {"del-prefix", required_argument, NULL, 'd'},
    {"elf-file", required_argument, NULL, 'e'},
    {"eof", no_argument, NULL, 'E'},
    {"input-file", required_argument, NULL, 'f'},
    {"help", no_argument, NULL, 'h'},
    {"interval", required_argument, NULL, 'I'},
    {"no-colour", no_argument, NULL, 'M'},
    {"no-color", no_argument, NULL, 'M'},
    {"objdump-opts", required_argument, NULL, 'O'},
    {"trace-proto", required_argument, NULL, 'P'},
    {"protocol", required_argument, NULL, 'p'},
    {"server", required_argument, NULL, 's'},
    {"all-truncate", no_argument, NULL, 'T'},
    {"tag", required_argument, NULL, 't'},
    {"verbose", required_argument, NULL, 'v'},
    {"version", no_argument, NULL, 'V'},
    {"graph-file", required_argument, NULL, 'y'},
    {"cache-file", required_argument, NULL, 'z'},
    {NULL, no_argument, NULL, 0}
};
// ====================================================================================================
static bool _processOptions( int argc, char *argv[], struct RunTime *r )

{
    int c, optionIndex = 0;
    bool protExplicit = false;
    bool serverExplicit = false;

    while ( ( c = getopt_long ( argc, argv, "ADd:e:Ef:hVI:MO:P:p:s:t:Tv:y:z:", _longOptions, &optionIndex ) ) != -1 )

        switch ( c )
        {
            // ------------------------------------
            case 'A':
                r->options->noaltAddr = true;
                break;

            // ------------------------------------
            case 'd':
                r->options->deleteMaterial = optarg;
                break;

            // ------------------------------------
            case 'D':
                r->options->demangle = false;
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
                exit( 0 );

            // ------------------------------------

            case 'M':
                r->options->mono = true;
                break;

            // ------------------------------------
            case 'V':
                _printVersion();
                return false;

            // ------------------------------------
            case 'I':
                r->options->sampleDuration = atoi( optarg );
                break;

            // ------------------------------------

            case 'O':
                r->options->odoptions = optarg;
                break;

            // ------------------------------------

            case 'P':

                /* Index through protocol strings looking for match or end of list */
                for ( r->options->tProtocol = TRACE_PROT_LIST_START;
                        ( ( r->options->tProtocol != TRACE_PROT_LIST_END ) && strcasecmp( optarg, TRACEDecodeGetProtocolName( r->options->tProtocol ) ) );
                        r->options->tProtocol++ )
                {}

                break;

            // ------------------------------------

            case 'p':
                r->options->protocol = PROT_UNKNOWN;
                protExplicit = true;

                for ( int i = 0; protString[i]; i++ )
                {
                    if ( !strcmp( protString[i], optarg ) )
                    {
                        r->options->protocol = i;
                        break;
                    }
                }

                if ( r->options->protocol == PROT_UNKNOWN )
                {
                    genericsReport( V_ERROR, "Unrecognised protocol type" EOL );
                    return false;
                }

                break;

            // ------------------------------------
            case 's':
                r->options->server = optarg;
                serverExplicit = true;

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
            case 'T':
                r->options->truncateDeleteMaterial = true;
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
            case 'y':
                r->options->dotfile = optarg;
                break;

            // ------------------------------------
            case 'z':
                r->options->profile = optarg;
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
                genericsReport( V_ERROR, "Unknown option %c" EOL, optopt );
                return false;
                // ------------------------------------
        }

    /* If we set an explicit server and port and didn't set a protocol chances are we want ETM, not OFLOW */
    if ( serverExplicit && !protExplicit )
    {
        r->options->protocol = PROT_ETM;
    }

    if ( !r->options->elffile )
    {
        genericsExit( -2, "Elf File not specified" EOL );
    }

    if ( !r->options->sampleDuration )
    {
        genericsExit( -2, "Illegal sample duration" EOL );
    }

    if ( r->options->tProtocol >= TRACE_PROT_NONE )
    {
        genericsExit( V_ERROR, "Unrecognised decode protocol" EOL );
    }


    genericsReport( V_INFO, "orbprofile version " GIT_DESCRIBE EOL );
    genericsReport( V_INFO, "Server          : %s:%d" EOL, r->options->server, r->options->port );
    genericsReport( V_INFO, "Delete Material : %s" EOL, r->options->deleteMaterial ? r->options->deleteMaterial : "None" );
    genericsReport( V_INFO, "Elf File        : %s (%s Names)" EOL, r->options->elffile, r->options->truncateDeleteMaterial ? "Truncate" : "Don't Truncate" );
    genericsReport( V_INFO, "Objdump options : %s" EOL, r->options->odoptions ? r->options->odoptions : "None" );
    genericsReport( V_INFO, "Protocol        : %s" EOL, TRACEDecodeGetProtocolName( r->options->tProtocol ) );
    genericsReport( V_INFO, "Orbflow Tag     : %d" EOL, r->options->tag );
    genericsReport( V_INFO, "DOT file        : %s" EOL, r->options->dotfile ? r->options->dotfile : "None" );
    genericsReport( V_INFO, "Sample Duration : %d mS" EOL, r->options->sampleDuration );

    switch ( r->options->protocol )
    {
        case PROT_OFLOW:
            genericsReport( V_INFO, "Decoding OFLOW (Orbuculum) with ITM in stream %d" EOL, r->options->tag );
            break;

        case  PROT_ETM:
            genericsReport( V_INFO, "Using raw ETM" EOL );
            break;

        default:
            genericsReport( V_INFO, "Decoding unknown" EOL );
            break;
    }

    return true;
}
// ====================================================================================================
static void _doExit( void )

/* Perform any explicit exit functions */

{
    _r.ending = true;
    /* Give them a bit of time, then we're leaving anyway */
    usleep( 200 );

}
// ====================================================================================================
static void _intHandler( int sig )

/* Catch CTRL-C so things can be cleaned up properly via atexit functions */
{
    /* CTRL-C exit is not an error... */
    _doExit();
}

// ====================================================================================================

static void _OFLOWpacketRxed ( struct OFLOWFrame *p, void *param )

{
    if ( !p->good )
    {
        genericsReport( V_INFO, "Bad packet received" EOL );
    }
    else
    {
        if ( p->tag == _r.options->tag )
        {
            TRACEDecoderPump( &_r.i, p->d, p->len, _traceCB, &_r );
        }
    }
}
// ====================================================================================================
static bool _queueBlock( struct RunTime *r, bool force )

/* Hand the block at wp (already filled in) to the processing thread and start a new, empty one. */
/* One slot is always kept free for the end-of-data block, which is queued with force set.       */
/* Returns false if the buffer is full (decoding has fallen too far behind).                     */

{
    pthread_mutex_lock( &r->dataForClients_m );
    int nwp = ( r->wp + 1 ) % NUM_RAW_BLOCKS;

    if ( ( ( nwp + 1 ) % NUM_RAW_BLOCKS == r->rp ) && ( !force ) )
    {
        pthread_mutex_unlock( &r->dataForClients_m );
        return false;
    }

    r->wp = nwp;
    r->rawBlock[r->wp].fillLevel = 0;
    pthread_cond_signal( &r->dataForClients );
    pthread_mutex_unlock( &r->dataForClients_m );
    return true;
}
// ====================================================================================================
static void *_processBlocks( void *params )

/* Generic block processor for received data. This runs in a task parallel to the receiver and *
 * processes all of the data that arrive.                                                      */

{
    struct RunTime *r = ( struct RunTime * )params;

    while ( true )
    {
        /* Wait (with the mutex held, as pthread_cond_wait requires) until a block is queued */
        pthread_mutex_lock( &r->dataForClients_m );

        while ( r->rp == r->wp )
        {
            pthread_cond_wait( &r->dataForClients, &r->dataForClients_m );
        }

        pthread_mutex_unlock( &r->dataForClients_m );

        struct dataBlock *b = &r->rawBlock[r->rp];
        genericsReport( V_DEBUG, "RXED Packet of %d bytes" EOL, ( int )b->fillLevel );

        /* A zero length block marks the end of the data */
        if ( b->fillLevel <= 0 )
        {
            break;
        }

        if ( PROT_OFLOW == r->options->protocol )
        {
            OFLOWPump( &_r.c, b->buffer, b->fillLevel, _OFLOWpacketRxed, &_r );
        }
        else
        {
            /* Pump all of the data through the protocol handler */
            TRACEDecoderPump( &r->i, b->buffer, b->fillLevel, _traceCB, &_r );
        }

        pthread_mutex_lock( &r->dataForClients_m );
        r->rp = ( r->rp + 1 ) % NUM_RAW_BLOCKS;
        pthread_mutex_unlock( &r->dataForClients_m );
    }

    return NULL;
}
// ====================================================================================================
int main( int argc, char *argv[] )

{
    struct timeval tv;
    struct Stream *stream = NULL;
    enum symbolErr r;

    DBG_OUT( "This utility is in development. Use at your own risk!!" EOL );

    /* Have a basic name and search string set up */
    _r.progName = genericsBasename( argv[0] );
    _r.options = &_options;

    if ( pthread_mutex_init( &_r.dataForClients_m, NULL ) != 0 )
    {
        genericsExit( -1, "Failed to establish mutex for condition variablee" EOL );
    }

    if ( pthread_cond_init( &_r.dataForClients, NULL ) != 0 )
    {
        genericsExit( -1, "Failed to establish condition variablee" EOL );
    }

    if ( !_processOptions( argc, argv, &_r ) )
    {
        /* processOptions generates its own error messages */
        genericsExit( -1, "" EOL );
    }

    genericsScreenHandling( !_r.options->mono );

    /* Make sure any cleanup happens at the end */
    atexit( _doExit );

    /* This ensures the atexit gets called */
    if ( SIG_ERR == signal( SIGINT, _intHandler ) )
    {
        genericsExit( -1, "Failed to establish Int handler" EOL );
    }

#if !defined(WIN32)

    /* Don't kill a sub-process when any reader or writer evaporates */
    if ( SIG_ERR == signal( SIGPIPE, SIG_IGN ) )
    {
        genericsExit( -1, "Failed to ignore SIGPIPEs" EOL );
    }

#endif

    TRACEDecoderInit( &_r.i, _r.options->tProtocol, !_r.options->noaltAddr, genericsReport );
    OFLOWInit( &_r.c );

    bool processThreadStarted = false;

    while ( !_r.ending )
    {
        if ( _r.options->file != NULL )
        {
            stream = streamCreateFile( _r.options->file );
        }
        else
        {
            while ( 1 )
            {
                stream = streamCreateSocket( _r.options->server, _r.options->port );

                if ( stream )
                {
                    break;
                }

                perror( "Could not connect" );
                usleep( 1000000 );
            }
        }


        /* We need symbols constantly while running ... lets get them */
        if ( !SymbolSetValid( &_r.s, _r.options->elffile ) )
        {
            r = SymbolSetCreate( &_r.s, _r.options->elffile, _r.options->deleteMaterial, _r.options->demangle, true, true, _r.options->odoptions );

            switch ( r )
            {
                case SYMBOL_NOELF:
                    genericsExit( -1, "Elf file or symbols in it not found" EOL );
                    break;

                case SYMBOL_NOOBJDUMP:
                    genericsExit( -1, "No objdump found" EOL );
                    break;

                case SYMBOL_UNSPECIFIED:
                    genericsExit( -1, "Unknown error in symbol subsystem" EOL );
                    break;

                default:
                    break;
            }

            genericsReport( V_WARN, "Loaded %s" EOL, _r.options->elffile );
        }

        _r.intervalBytes = 0;

        /* Start the result processing task (once: we may come round here again after a reconnect) */
        if ( !processThreadStarted )
        {
            pthread_create( &_r.processThread, NULL, &_processBlocks, &_r );
            processThreadStarted = true;
        }

        /* ----------------------------------------------------------------------------- */
        /* This is the main active loop...only break out of this when ending or on error */
        /* ----------------------------------------------------------------------------- */

        while ( !_r.ending )
        {
            /* Each time segment is restricted */
            tv.tv_sec = 0;
            tv.tv_usec  = TICK_TIME_MS * 1000;


            /* Data are gathered into large blocks: the decoder is usually slower than the trace */
            /* (every instruction is decoded), so the buffer (NUM_RAW_BLOCKS x TRANSFER_SIZE)     */
            /* holds the capture while decoding catches up.                                     */
            struct dataBlock *rxBlock = &_r.rawBlock[_r.wp];
            size_t got = 0;

            enum ReceiveResult result = stream->receive( stream, rxBlock->buffer + rxBlock->fillLevel,
                                        TRANSFER_SIZE - rxBlock->fillLevel, &tv, &got );

            if ( ( result == RECEIVE_RESULT_EOF ) || ( result == RECEIVE_RESULT_ERROR ) )
            {
                if ( ( result == RECEIVE_RESULT_EOF ) && ( _r.options->file ) )
                {
                    /* End of the input file: nothing more will come */
                    _r.ending = true;
                }

                break;
            }

            /* A timeout (no data for a moment) is not the end of the connection, just carry on */
            if ( got > 0 )
            {
                rxBlock->fillLevel += got;
                _r.intervalBytes += got;
            }

            /* Pass the block on when it's full, or when the data pause (so decoding can start) */
            if ( ( rxBlock->fillLevel >= TRANSFER_SIZE ) || ( ( got == 0 ) && ( rxBlock->fillLevel > 0 ) ) )
            {
                if ( !_queueBlock( &_r, false ) )
                {
                    genericsReport( V_WARN, "Capture buffer full after %u ms: stopping capture and decoding what was received" EOL,
                                    _r.sampling ? genericsTimestampmS() - _r.starttime : 0 );
                    rxBlock->fillLevel = 0;
                    _r.ending = true;
                }
            }

            /* Stop once the sample interval is over */
            if ( ( ( volatile bool ) _r.sampling ) && ( ( genericsTimestampmS() - ( volatile uint32_t )_r.starttime ) > _r.options->sampleDuration ) )
            {
                _r.ending = true;
            }
        }

        stream->close( stream );
        free( stream );
    }

    /* Post an empty block to tell the processing thread it's done, then wait for it */
    if ( processThreadStarted )
    {
        /* Pass on any partly filled block (there's always room for this one plus the end block) */
        if ( _r.rawBlock[_r.wp].fillLevel > 0 )
        {
            _queueBlock( &_r, true );
        }

        genericsReport( V_INFO, "Capture done (%" PRIu64 " bytes), finishing decoding..." EOL, _r.intervalBytes );
        _r.rawBlock[_r.wp].fillLevel = 0;
        _queueBlock( &_r, true );
        pthread_join( _r.processThread, NULL );
    }

    /* Data are collected, now process and report */
    genericsReport( V_INFO, "Received %d raw sample bytes, %ld function changes, %ld distinct addresses" EOL,
                    _r.intervalBytes, HASH_COUNT( _r.subhead ), HASH_COUNT( _r.insthead ) );

    if ( _lostInstructions )
    {
        genericsReport( V_INFO, "%" PRIu64 " instructions skipped where the trace position was not known" EOL, _lostInstructions );
    }

    if ( HASH_COUNT( _r.subhead ) )
    {
        _resolveCalls( &_r );

        if ( ext_ff_outputDot( _r.options->dotfile, _r.subhead, _r.s ) )
        {
            genericsReport( V_INFO, "Output DOT" EOL );
        }
        else
        {
            if ( _r.options->dotfile )
            {
                genericsExit( -1, "Failed to output DOT" EOL );
            }
        }

        if ( ext_ff_outputProfile( _r.options->profile, _r.options->elffile,
                                   _r.options->truncateDeleteMaterial ? _r.options->deleteMaterial : NULL,
                                   true,
                                   _r.op.lasttstamp - _r.op.firsttstamp,
                                   _r.insthead,
                                   _r.subhead,
                                   _r.s ) )
        {
            genericsReport( V_INFO, "Output Profile" EOL );
        }
        else
        {
            if ( _r.options->profile )
            {
                genericsExit( -1, "Failed to output profile" EOL );
            }
        }
    }
    else
    {
        genericsReport( V_WARN, "No calls recorded, so no profile written" EOL );
    }

    return OK;
}

// ====================================================================================================
