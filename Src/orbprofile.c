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

#ifdef WIN32
    #include <windows.h>
#endif

#define TICK_TIME_MS        (1)          /* Time intervals for checks */
#define DEFAULT_DURATION_MS (1000)       /* Default time to sample, in mS */
#define LIVE_MIN_INTERVAL_MS (200)       /* Fastest live update, in mS */
#define TIMELINE_MAX_EVENTS (5000000)    /* Most calls written to a timeline file (about 100 bytes each) */
#define HANDLE_MASK         (0xFFFFFF)   /* cachegrind cannot cope with large file handle numbers */

enum Prot { PROT_OFLOW, PROT_ETM, PROT_UNKNOWN };
const char *protString[] = {"OFLOW", "ETM", NULL};

/* How many transfer buffers from the source to allocate */
#define DEFAULT_BUFFER_MB (1024)         /* Default capture buffer size, can be changed with -b */
#define MIN_RAW_BLOCKS (4)
#define FAULTS_KEPT (8)                   /* Trace faults described in the -X report */
#define HIST_BLOCKS (256)                 /* -X: decoded blocks kept, 64 MiB of trace before the decoder's position */
#define DROP_SAMPLES (180)                /* -X: seconds of rate history kept */
#define SPARE_BLOCKS (8)                  /* Emptied capture buffers kept for reuse, the rest are freed */

/* Direct-mapped cache in front of the instruction hash table (decoding looks up every instruction) */
#define ICACHE_BITS (16)
#define ICACHE_SIZE (1 << ICACHE_BITS)

#ifdef ORBPROFILE_DEBUG
#define DBG_OUT(...) fprintf(stderr,__VA_ARGS__)
#else
#define DBG_OUT(...)
#endif

/* Instructions skipped because the trace position wasn't known (e.g. after an indirect branch) */
static uint64_t _lostInstructions;

/* ETM4: most instructions run between two atoms (branches) before giving up on the position */
#define ETM4_MAX_RUN (0x10000)

struct _subcallAccount
{
    struct subcallSig sig;
    struct subcall *rec;                 /* The record for this source/destination pair */
    uint64_t inTicks;                    /* Instructions executed when the call was made */
    uint64_t inVisits;                   /* Source line visits when the call was made */
    uint64_t inCycles;                   /* Cycles when the call was made */
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
    char *lcovfile;                      /* File to output lcov coverage information */
    int  sampleDuration;                 /* How long we are going to sample for (0 = until stopped) */
    char *timelineFile;                  /* File to output the function timeline (Chrome trace JSON) */
    uint32_t timelineMin;                /* Shortest call to put in the timeline, in instructions (or cycles) */
    int  liveInterval;                   /* Live mode: rewrite the coverage file and report this often, in ms (0 = off) */
    int  bufferMB;                       /* Capture buffer size in MiB */
    char *dropDump;                      /* Stop at the first data loss and write the evidence to <name>.* */
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
    .bufferMB       = DEFAULT_BUFFER_MB,
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
    struct execEntryHash **link;         /* Where the record of the instruction at workingAddr is, or will be, noted */
    uint32_t nextAddr;                   /* The address we will next be accessing (if known) */
    uint32_t lastfn;                     /* The function of the last instruction carried out */

    uint64_t firsttstamp;                /* First timestamp we recorded (that was valid) */
    uint64_t lasttstamp;                 /* Last timestamp we recorded (that was valid) */

    bool isExceptReturn;                 /* Is this flagged as an exception return? */
    bool isException;                    /* Is this flagged as an exception? */

    /* ETM4 only */
    bool etm4Pending;                    /* A taken indirect branch (op.h) is waiting for its destination */
    bool etm4ExPending;                  /* An exception was taken, waiting for the handler address */
    bool etm4ExReturn;                   /* An exception return element was seen */
    uint32_t etm4ExRetAddr;              /* Where the pending exception will return to */
};

/* A block of received data */
struct dataBlock
{
    ssize_t fillLevel;
    bool afterGap;                              /* Trace was discarded just before this block */
    uint8_t buffer[TRANSFER_SIZE];
};

/* ----------- LIVE STATE ----------------- */
struct traceFault                               /* Execution that cannot have happened: see _traceFault */
{
    uint32_t from;
    uint32_t to;
    uint64_t inst;
    uint32_t ms;
};

struct dropSample                               /* State once a second, for the -X report */
{
    uint32_t ms;                                /* Since the capture started */
    uint64_t rxBytes;
    uint64_t decodedBytes;
    uint64_t inst;
    uint64_t lost;
    uint64_t cpuMs;
    uint64_t liveMs;
    uint32_t waitingBlocks;
    uint32_t blockMs;                           /* How long the decoder has been on its current block */
    int core;                                   /* Processor the decoding thread was last seen on */
};

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
    uint32_t substackcap;                       /* Calls stack entries allocated */

    /* Stats about the run */
    int instCount;                              /* Number of instruction locations */
    uint64_t instExecuted;                      /* Instructions executed (the Inst cost) */
    uint64_t lineVisits;                        /* Source line visits (the Visits cost) */
    uint64_t cyclesExecuted;                    /* Cycles of traced instructions (the Cycles cost) */
    uint64_t pendingCycles;                     /* Cycles waiting for the next instruction to complete */
    uint64_t packetCycles;                      /* Cycles reported in cycle count packets */
    uint64_t callsCount;                        /* Call data count */
    uint64_t intervalBytes;                     /* Number of bytes transferred in current interval */
    FILE *timeline;                             /* Timeline output, while open */
    uint64_t timelineEvents;                    /* Calls written to the timeline */
    uint64_t timelineSkipped;                   /* Calls left out (too short, or the file limit was reached) */
    uint32_t rootFn;                            /* Function running with no call open (main, usually), or NO_FUNCTION */
    int timeBase;                               /* Timeline clock: 0 not decided yet, 1 instructions, 2 cycles */
    uint64_t rootStart;                         /* ...and when it started, or when the last one ended */
    uint64_t droppedBytes;                      /* Bytes discarded because decoding could not keep up */

    /* For -X: what is needed to work out afterwards why decoding fell behind */
    struct dataBlock *hist[HIST_BLOCKS];        /* The blocks decoded last, oldest at histHead when full */
    int histHead;
    int histCount;
    uint64_t traceFaults;                       /* Times execution ran from one function straight into the next */
    struct traceFault fault[FAULTS_KEPT];       /* The first of them */
    volatile bool faultStop;                    /* -X: one was found, the receiving thread is to stop and dump */
    uint64_t faultAtDecoded;                    /* Trace given to the decoder before the block with the first one */
    volatile bool abandon;                      /* Stop decoding: throw the waiting blocks away */
    volatile uint64_t decodedBytes;             /* Trace handed to the decoder so far */
    volatile uint64_t decodeCpuMs;              /* Processor time the decoding thread has used */
    volatile uint64_t liveMs;                   /* ...and the time it spent writing live results */
    volatile int decodeCore;                    /* Processor the decoding thread is on */
    int fastCores;                              /* Windows: performance cores the process was put on (0 = not done) */
    int slowCores;                              /* ...and efficiency cores it is kept off */
    volatile uint32_t blockStartMs;             /* When the decoder started on its current block */
    struct dropSample samp[DROP_SAMPLES];       /* One entry a second, most recent at sampHead-1 */
    int sampHead;
    int sampCount;
    uint32_t lastSample;
    uint32_t lastLive;                          /* When the last live update was made */
    uint32_t liveUpdates;                       /* Number of live updates made */

    /* State of the target tracker */
    struct opConstruct op;                      /* The mechanical elements for creating the output buffer */

    /* Subprocess control and interworking */
    pthread_t processThread;                    /* Thread handling received data flow */
    pthread_cond_t dataForClients;              /* Semaphore counting data for clients */
    pthread_mutex_t dataForClients_m;           /* Mutex for counting data for clients */

    /* Ring buffer for samples ... this 'pads' the rate data arrive and how fast they can be processed */
    int wp;                                     /* Read and write pointers into transfer buffers */
    int rp;
    struct dataBlock **rawBlock;                /* Transfer buffers from the receiver: slots for up to -b of them. */
    /* A buffer is only allocated while it holds data waiting to be decoded */
    struct dataBlock *spareBlock[SPARE_BLOCKS]; /* Decoded buffers kept for reuse */
    int numSpare;
    int numBlocks;                              /* Number of transfer buffers */

    /* Instruction lookup cache: addresses and records, indexed by (addr >> 1) */
    uint32_t icacheAddr[ICACHE_SIZE];
    struct execEntryHash *icacheEntry[ICACHE_SIZE];

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
/* TRACEStateChanged, inline: this is asked several times for every trace message */
static inline bool _changed( struct TRACECPUState *cpu, enum TRACEchanges c )

{
    const uint32_t m = 1u << c;
    const bool r = ( cpu->changeRecord & m ) != 0;
    cpu->changeRecord &= ~m;
    return r;
}
// ====================================================================================================
static bool _timelineInCycles( struct RunTime *r )

/* Timeline clock: cycles if the trace is cycle accurate, otherwise instructions executed.   */
/* Cycle accurate trace gives cycles for every instruction from the start, so decide once,   */
/* early on: a stray cycle count from damaged trace must not change the clock half way.      */

{
    if ( !r->timeBase )
    {
        bool cyc = ( r->cyclesExecuted ) && ( r->cyclesExecuted >= r->instExecuted );

        if ( r->instExecuted < 1024 )
        {
            return cyc;
        }

        r->timeBase = cyc ? 2 : 1;
    }

    return r->timeBase == 2;
}
// ====================================================================================================
static uint64_t _timelineNow( struct RunTime *r )

{
    return _timelineInCycles( r ) ? r->cyclesExecuted : r->instExecuted;
}
// ====================================================================================================
static void _jsonString( const char *in, char *out, size_t outLen )

/* Copy text for use inside a JSON string: escape quotes and backslashes, blank control characters */

{
    size_t o = 0;

    for ( ; ( *in ) && ( o + 2 < outLen ); in++ )
    {
        if ( ( *in == '"' ) || ( *in == '\\' ) )
        {
            out[o++] = '\\';
        }

        out[o++] = ( ( unsigned char ) * in < 0x20 ) ? ' ' : *in;
    }

    out[o] = 0;
}
// ====================================================================================================
static void _timelineCall( struct RunTime *r, struct _subcallAccount *a )

/* A call (or exception) has ended: write it to the timeline as one complete event */

{
    struct nameEntry n;
    char name[256];
    const char *f;
    uint64_t start = _timelineInCycles( r ) ? a->inCycles : a->inTicks;
    uint64_t dur   = _timelineNow( r ) - start;

    if ( !r->timeline )
    {
        return;
    }

    if ( ( dur < r->options->timelineMin ) || ( r->timelineEvents >= TIMELINE_MAX_EVENTS ) )
    {
        r->timelineSkipped++;
        return;
    }

    f = SymbolLookup( r->s, a->sig.dst, &n ) ? SymbolFunction( r->s, n.functionindex ) : NULL;

    if ( !f )
    {
        snprintf( name, sizeof( name ), "0x%08x", a->sig.dst );
    }
    else
    {
        _jsonString( f, name, sizeof( name ) );
    }

    fprintf( r->timeline, "%s{\"name\":\"%s\",\"ph\":\"X\",\"ts\":%" PRIu64 ",\"dur\":%" PRIu64 ",\"pid\":1,\"tid\":1}",
             r->timelineEvents ? ",\n" : "", name, start, dur ? dur : 1 );
    r->timelineEvents++;
}
// ====================================================================================================
static bool _isFunction( uint32_t fn )

{
    return ( fn != NO_FUNCTION ) && ( ( fn & SPECIALS_MASK ) != SPECIALS_MASK );
}
// ====================================================================================================
static void _timelineRootClose( struct RunTime *r )

/* The function that was running with no call open (the one the trace started in, normally main) */
/* ends here. Its own call was before the trace, so it gets a bar from where it was first seen.  */

{
    char name[256];
    uint64_t now = _timelineNow( r );

    if ( ( r->timeline ) && ( _isFunction( r->rootFn ) ) )
    {
        if ( now - r->rootStart < r->options->timelineMin )
        {
            r->timelineSkipped++;
        }
        else
        {
            _jsonString( SymbolFunction( r->s, r->rootFn ), name, sizeof( name ) );
            fprintf( r->timeline, "%s{\"name\":\"%s\",\"ph\":\"X\",\"ts\":%" PRIu64 ",\"dur\":%" PRIu64 ",\"pid\":1,\"tid\":1}",
                     r->timelineEvents ? ",\n" : "", name, r->rootStart, ( now > r->rootStart ) ? now - r->rootStart : 1 );
            r->timelineEvents++;
        }
    }

    r->rootFn = NO_FUNCTION;
    r->rootStart = now;
}
// ====================================================================================================
static void _timelineCloseOpenCalls( struct RunTime *r )

/* The call stack is being abandoned (end of capture, or resync): the open calls end here */

{
    for ( uint32_t d = r->substacklen; d; d-- )
    {
        _timelineCall( r, &r->substack[d - 1] );
    }

    if ( ( !_isFunction( r->rootFn ) ) && ( !r->substacklen ) && ( r->op.h ) )
    {
        /* Nothing was called since the last one ended: it is the function we are in */
        r->rootFn = r->op.h->functionindex;
    }

    _timelineRootClose( r );
}
// ====================================================================================================
static void _callEvent( struct RunTime *r, uint32_t retAddr, uint32_t to, struct execEntryHash *from )

/* This is a call or a return, manipulate stack tracking appropriately. from is the calling */
/* instruction if there is one: it remembers the record of the call it made last time.       */

{
    struct subcall *s;

    /* A call never goes to the address it returns to. That is an exception return seen as */
    /* an exception entry, so it isn't a call.                                              */
    if ( retAddr == to )
    {
        return;
    }

    if ( ( r->timeline ) && ( !r->substacklen ) && ( from ) )
    {
        /* A call with none open: the caller is the function at the bottom of the timeline. */
        /* (Not for an exception: when it is taken on a return, the address it interrupts   */
        /* is not known yet and would name the function just left.)                         */
        uint32_t fn = from->functionindex;

        if ( ( _isFunction( fn ) ) && ( fn != r->rootFn ) )
        {
            if ( _isFunction( r->rootFn ) )
            {
                _timelineRootClose( r );
            }

            r->rootFn = fn;
        }
    }

    /* ...add it to the call stack */
    if ( r->substacklen >= r->substackcap )
    {
        r->substackcap = r->substackcap ? r->substackcap * 2 : 64;
        r->substack = ( struct _subcallAccount * )realloc( r->substack, r->substackcap * sizeof( struct _subcallAccount ) );
        MEMCHECKV( r->substack );
    }


    /* This is a call */
    r->substack[r->substacklen].sig.src     = retAddr;
    r->substack[r->substacklen].sig.dst     = to;
    r->substack[r->substacklen].inTicks     = r->instExecuted;
    r->substack[r->substacklen].inVisits    = r->lineVisits;
    r->substack[r->substacklen].inCycles    = r->cyclesExecuted;

    /* Find a record for this source/dest pair */
    if ( ( from ) && ( from->callRec ) && ( from->callDst == to ) )
    {
        s = from->callRec;
    }
    else
    {
        HASH_FIND( hh, r->subhead, &r->substack[r->substacklen].sig, sizeof( struct subcallSig ), s );
    }

    if ( !s )
    {
        /* This call entry doesn't exist (i.e. it's the first time this from/to pair have been seen...let's create it */
        s = ( struct subcall * )calloc( 1, sizeof( struct subcall ) );
        MEMCHECKV( s );
        memcpy( &s->sig, &r->substack[r->substacklen].sig, sizeof( struct subcallSig ) );
        HASH_ADD( hh, r->subhead, sig, sizeof( struct subcallSig ), s );
    }

    if ( from )
    {
        from->callRec = s;
        from->callDst = to;
    }

    r->substack[r->substacklen].rec = s;
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
static uint32_t _returnEvent( struct RunTime *r, uint32_t to, bool mustMatch )

/* This is a return to 'to'. Close the calls down to the one that returns there. If no call */
/* on the stack does (the trace didn't say where this return went, or the call was missed), */
/* close just the innermost one, or none if mustMatch. Returns the address the last closed  */
/* call returns to, or 0 if none was closed.                                                */

{
    struct subcall *s;
    struct _subcallAccount *a;
    uint32_t depth = r->substacklen;
    uint32_t src = 0;

    while ( ( depth ) && ( r->substack[depth - 1].sig.src != to ) )
    {
        depth--;
    }

    if ( !depth )
    {
        if ( ( mustMatch ) || ( !r->substacklen ) )
        {
            struct nameEntry n;

            if ( ( r->timeline ) && ( !mustMatch ) &&
                    /* ...unless it stays in the same function: that is a computed jump (a switch), not a return */
                    !( ( r->op.h ) && ( SymbolLookup( r->s, to, &n ) ) && ( n.functionindex == r->op.h->functionindex ) ) )
            {
                /* A return with no call open: the function at the bottom of the timeline is left */
                if ( ( !_isFunction( r->rootFn ) ) && ( r->op.h ) )
                {
                    r->rootFn = r->op.h->functionindex;
                }

                _timelineRootClose( r );
            }

            DBG_OUT( "NO CALL RETURNS TO %08x" EOL, to );
            return 0;
        }

        depth = r->substacklen;
    }

    while ( r->substacklen >= depth )
    {
        /* We don't bother deallocating memory here cos it'll be done the next time we make a call */
        a = &r->substack[--r->substacklen];

#ifdef ORBPROFILE_DEBUG

        for ( uint32_t g = 0; g < r->substacklen + 1; g++ )
        {
            putchar( ' ' );
        }

#endif

        DBG_OUT( " DEC:%3d %08x (wanted %08x)" EOL, r->substacklen + 1, a->sig.src, to );
        s = a->rec;

        if ( r->timeline )
        {
            _timelineCall( r, a );
        }

        /* Inclusive costs: what was executed and visited while this call was open */
        s->myCost   += r->instExecuted - a->inTicks;
        s->myVisits += r->lineVisits - a->inVisits;
        s->myCycles += r->cyclesExecuted - a->inCycles;
        s->count++;
        src = a->sig.src;
    }

    return src;
}
// ====================================================================================================
static bool _isFunctionEntry( struct RunTime *r, uint32_t addr )

/* Exception handlers are entered at their first instruction, so an address is a function   */
/* entry if the code just before it is not part of the same function. Exception returns go  */
/* back into the middle of the interrupted function.                                        */

{
    struct nameEntry n;
    struct nameEntry p;

    if ( !SymbolLookup( r->s, addr, &n ) )
    {
        return false;
    }

    return ( !SymbolLookup( r->s, addr - 2, &p ) ) || ( p.functionindex != n.functionindex );
}
// ====================================================================================================
static bool _hashFindOrCreate( struct RunTime *r, uint32_t addr, struct execEntryHash **h )

/* Find the record for this instruction address, or create it. Returns false if the address */
/* isn't a known instruction (unknown position after an indirect branch, code outside the   */
/* ELF file, or a mis-decode), so the caller can skip it instead of crashing or exiting.    */

{
    struct nameEntry n;

    /* Fast path: direct-mapped cache (Thumb instructions are at even addresses) */
    uint32_t ci = ( addr >> 1 ) & ( ICACHE_SIZE - 1 );

    if ( ( r->icacheAddr[ci] == addr ) && ( r->icacheEntry[ci] ) )
    {
        *h = r->icacheEntry[ci];
        return true;
    }

    HASH_FIND_INT( r->insthead, &addr, *h );

    if ( *h )
    {
        r->icacheAddr[ci]  = addr;
        r->icacheEntry[ci] = *h;
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
    ( *h )->isCondJump    = n.assy[n.assyLine].isCondJump;
    ( *h )->isP0          = n.assy[n.assyLine].etm4branch;
    ( *h )->p0Sequential  = n.assy[n.assyLine].etm4seq;
    ( *h )->isSubCall     = n.assy[n.assyLine].isSubCall;
    ( *h )->isReturn      = n.assy[n.assyLine].isReturn;
    ( *h )->jumpdest      = n.assy[n.assyLine].jumpdest;
    ( *h )->is4Byte       = n.assy[n.assyLine].is4Byte;
    ( *h )->codes         = n.assy[n.assyLine].codes;
    ( *h )->assyText      = n.assy[n.assyLine].lineText;
    ( *h )->special       = ( *h )->isJump || ( *h )->isCondJump || ( *h )->isSubCall || ( *h )->isReturn;

    HASH_ADD_INT( r->insthead, addr, ( *h ) );
    r->icacheAddr[ci]  = addr;
    r->icacheEntry[ci] = *h;
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
static void _traceFault( struct RunTime *r, const struct execEntryHash *from, const struct execEntryHash *to )

/* The decoder has stepped from the last instruction of one function straight on into another.  */
/* Compiled code does not do that (it returns or branches), so trace was lost or damaged just   */
/* before and the decoder is off the path the program really took. It finds its place again at  */
/* the next address in the trace; the instructions in between are counted in the wrong place.   */

{
    if ( r->traceFaults < FAULTS_KEPT )
    {
        struct traceFault *f = &r->fault[r->traceFaults];
        f->from = from->addr;
        f->to = to->addr;
        f->inst = r->instExecuted;
        f->ms = genericsTimestampmS() - r->starttime;
    }

    if ( ( !r->traceFaults++ ) && ( r->options->dropDump ) )
    {
        r->faultAtDecoded = r->decodedBytes;
        r->faultStop = true;
    }
}
// ====================================================================================================
static void _handleInstruction( struct RunTime *r, bool actioned, uint32_t cycles )

/* Account one instruction (atom), which took 'cycles' (cycle accurate trace, else 0) */

{
    /* ------------------------------------------------------------------------------------*/
    /* First Stage: Individual address visit accounting.                                   */
    /* Let's find the local hash record for this address, or create it if it doesn't exist */
    /* ------------------------------------------------------------------------------------*/

    r->op.oldh = r->op.h;

    /* The instruction before this one usually knows which record comes next */
    if ( ( r->op.link ) && ( *r->op.link ) && ( ( *r->op.link )->addr == r->op.workingAddr ) )
    {
        r->op.h = *r->op.link;
    }
    else if ( !_hashFindOrCreate( r, r->op.workingAddr, &r->op.h ) )
    {
        /* Position unknown: count it as lost and wait for the next address from the trace. */
        /* The interrupt placeholder record has no jump/call/return flags, so it is inert.  */
        _lostInstructions++;
        r->op.h = r->op.inth;
        r->op.link = NULL;
        return;
    }
    else if ( r->op.link )
    {
        *r->op.link = r->op.h;
    }

    //    if ( r->op.oldh ) DBG_OUT( "%4d,%4d %4d %s%s%c %s", r->op.h->functionindex, ( r->op.h ? r->op.oldh->functionindex : 0 ),  r->op.h->fileindex,
    //                               ( r->op.h->isJump ) ? "J" : " ", ( r->op.h->isSubCall ) ? "S" : r->op.h->isReturn ? "R" : " ", ( actioned ) ? ( r->op.h->is4Byte ? 'X' : 'x' ) : '-',
    //                               r->op.h->assyText );

    /* OK, by hook or by crook we've got an address entry now, so increment the number of executions */
    r->op.h->count++;
    r->op.h->cycles += cycles;
    r->instExecuted++;
    r->cyclesExecuted += cycles;

    /* If source postion changed then update source code line visitation counts too */
    if ( ( r->op.oldh ) && ( ( r->op.h->line != r->op.oldh->line ) || ( r->op.h->functionindex != r->op.oldh->functionindex ) ) )
    {
        r->op.h->scount++;
        r->lineVisits++;

        if ( ( r->op.h->functionindex != r->op.oldh->functionindex ) &&
                ( r->op.h->addr == r->op.oldh->addr + ( r->op.oldh->is4Byte ? 4 : 2 ) ) )
        {
            _traceFault( r, r->op.oldh, r->op.h );
        }
    }

    /* For branch coverage: a conditional jump that executed (condition passed) was taken */
    if ( ( actioned ) && ( r->op.h->isCondJump ) )
    {
        r->op.h->taken++;
    }

    /* If this is a computable destination then action it */
    if ( ( actioned ) && ( ( r->op.h->isJump ) || ( r->op.h->isSubCall ) ) )
    {
        /* Take this call ... note that the jumpdest may not be known at this point */
        r->op.workingAddr = r->op.h->jumpdest;
        r->op.link = &r->op.h->jumpH;
    }
    else
    {
        /* If it wasn't a jump or subroutine then increment the address */
        r->op.workingAddr += ( r->op.h->is4Byte ) ? 4 : 2;

        /* A return or other indirect branch goes where the trace says: remember the last place */
        r->op.link = ( ( actioned ) && ( r->op.h->isReturn ) ) ? &r->op.h->jumpH : &r->op.h->seqH;
    }
}

// ====================================================================================================
static uint32_t _checkJumps( struct RunTime *r, bool actioned )

/* Account the call or return made by the instruction just handled, if it executed. Returns */
/* the address the closed call returns to if it was a return, or 0.                         */

{
    uint32_t popped = 0;

    if ( ( r->op.h ) && ( actioned ) )
    {
        if ( r->op.h->isReturn )
        {
            popped = _returnEvent( r, r->op.workingAddr, false );
        }

        if ( r->op.h->isSubCall )
        {
            _callEvent( r, r->op.h->addr + ( ( r->op.h->is4Byte ) ? 4 : 2 ), r->op.workingAddr, r->op.h );
        }
    }

    return popped;
}
// ====================================================================================================
static void _runAtoms( struct RunTime *r, uint32_t n, uint32_t disposition )

/* Account n atoms (ETM3.5: one instruction each) when the trace is not cycle accurate. Most    */
/* instructions are neither a jump, a call nor a return, and for those all there is to do is   */
/* count them and step on: that is done here with the state in local variables. The others,    */
/* and any instruction whose record is not at hand yet, go through the general routines.       */

{
    struct execEntryHash *h = r->op.h;
    struct execEntryHash **link = r->op.link;
    uint32_t addr = r->op.workingAddr;
    uint64_t inst = 0;
    uint64_t visits = 0;

    while ( n )
    {
        struct execEntryHash *nh = link ? *link : NULL;

        if ( ( !nh ) || ( nh->addr != addr ) || ( nh->special ) )
        {
            /* The general way, with the shared state brought up to date for it and read back after */
            r->instExecuted += inst;
            r->lineVisits += visits;
            inst = visits = 0;
            r->op.workingAddr = addr;
            r->op.link = link;
            r->op.h = h;
            _handleInstruction( r, disposition & 1, 0 );
            _checkJumps( r, disposition & 1 );
            h = r->op.h;
            link = r->op.link;
            addr = r->op.workingAddr;
        }
        else
        {
            nh->count++;
            inst++;

            if ( ( h ) && ( ( nh->line != h->line ) || ( nh->functionindex != h->functionindex ) ) )
            {
                nh->scount++;
                visits++;

                if ( ( nh->functionindex != h->functionindex ) && ( nh->addr == h->addr + ( h->is4Byte ? 4 : 2 ) ) )
                {
                    _traceFault( r, h, nh );
                }
            }

            addr += nh->is4Byte ? 4 : 2;
            link = &nh->seqH;
            r->op.oldh = h;
            h = nh;
        }

        disposition >>= 1;
        n--;
    }

    r->instExecuted += inst;
    r->lineVisits += visits;
    r->op.workingAddr = addr;
    r->op.link = link;
    r->op.h = h;
}
// ====================================================================================================
static uint32_t _atomCycles( struct RunTime *r, uint32_t *budget )

/* Cycles of the next atom: the waits before it, plus its own cycle while the P-header has one */

{
    uint32_t c = ( uint32_t )r->pendingCycles;

    if ( *budget )
    {
        c++;
        ( *budget )--;
    }

    r->pendingCycles = 0;
    return c;
}
// ====================================================================================================
static bool _etm4Known( struct RunTime *r, struct execEntryHash **h )

/* ETM4: is the current position known, and if so its record */

{
    /* The instruction before usually knows which record comes next */
    if ( ( r->op.link ) && ( *r->op.link ) && ( ( *r->op.link )->addr == r->op.workingAddr ) )
    {
        *h = *r->op.link;
        return true;
    }

    return ( ( r->op.workingAddr & SPECIALS_MASK ) != SPECIALS_MASK ) && _hashFindOrCreate( r, r->op.workingAddr, h );
}
// ====================================================================================================
static uint32_t _etm4Resolve( struct RunTime *r, uint32_t dest )

/* ETM4: the taken indirect branch in op.h went to dest (NO_DESTADDRESS if the trace didn't say). */
/* Account the call or return it made. Returns the address a closed call returns to, or 0.        */

{
    uint32_t popped = 0;

    r->op.etm4Pending = false;
    r->op.workingAddr = dest;

    if ( ( r->op.h ) && ( r->op.h->isReturn ) )
    {
        /* With no destination this closes the innermost call, and where that returns to is where we are */
        popped = _returnEvent( r, dest, false );

        if ( ( ( dest & SPECIALS_MASK ) == SPECIALS_MASK ) && ( popped ) )
        {
            r->op.workingAddr = popped;
        }
    }
    else if ( ( r->op.h ) && ( r->op.h->isSubCall ) && ( ( dest & SPECIALS_MASK ) != SPECIALS_MASK ) )
    {
        _callEvent( r, r->op.h->addr + ( ( r->op.h->is4Byte ) ? 4 : 2 ), dest, r->op.h );
    }

    return popped;
}
// ====================================================================================================
static void _etm4Atom( struct RunTime *r, bool taken )

/* ETM4: one atom. Every instruction up to the next P0 element (branch, ISB, WFI, WFE) executed, */
/* and the atom says if that one did (for a conditional branch: if it was taken).               */

{
    struct execEntryHash *h;

    if ( r->op.etm4Pending )
    {
        /* The last indirect branch's destination never came (e.g. return stack compression) */
        _etm4Resolve( r, NO_DESTADDRESS );
    }

    for ( uint32_t steps = 0; steps < ETM4_MAX_RUN; steps++ )
    {
        if ( !_etm4Known( r, &h ) )
        {
            /* Position unknown: lost until the next address from the trace */
            _lostInstructions++;
            r->op.workingAddr = NO_DESTADDRESS;
            return;
        }

        if ( !h->isP0 )
        {
            /* Executed, and not a branch (as 'not actioned' it can't move anywhere but on, which */
            /* matters for SVC and UDF, encoded like conditional branches)                         */
            _handleInstruction( r, false, 0 );
            continue;
        }

        /* This atom's instruction. Cycle count packets come with P0 elements, so it gets the cycles */
        uint32_t zero = 0;
        _handleInstruction( r, taken, _atomCycles( r, &zero ) );

        if ( ( taken ) && ( !h->p0Sequential ) )
        {
            if ( ( ( h->isJump ) || ( h->isSubCall ) ) && ( ( h->jumpdest & SPECIALS_MASK ) != SPECIALS_MASK ) )
            {
                /* Direct branch: _handleInstruction moved to its destination */
                _checkJumps( r, true );
            }
            else
            {
                /* Indirect branch: the destination comes in an address packet */
                r->op.workingAddr = NO_DESTADDRESS;
                r->op.etm4Pending = true;
            }
        }

        return;
    }

    /* No branch in a very long run: the position is wrong */
    r->op.workingAddr = NO_DESTADDRESS;
}
// ====================================================================================================
static void _etm4Exception( struct RunTime *r, uint32_t retAddr )

/* ETM4: an exception was taken, with this preferred return address. Everything from the position */
/* up to (not including) the return address executed. The handler address comes next.            */

{
    struct execEntryHash *h;

    if ( r->op.etm4Pending )
    {
        /* The last indirect branch's destination wasn't in the trace. A return's comes from the */
        /* call stack (its code may have run before the exception). Otherwise the exception was  */
        /* taken before the first instruction there, so it is the return address.               */
        _etm4Resolve( r, ( ( r->op.h ) && ( r->op.h->isReturn ) ) ? NO_DESTADDRESS : retAddr );
    }

    if ( ( ( r->op.workingAddr & SPECIALS_MASK ) != SPECIALS_MASK ) && ( retAddr > r->op.workingAddr ) &&
            ( retAddr - r->op.workingAddr < ETM4_MAX_RUN ) )
    {
        while ( ( r->op.workingAddr < retAddr ) && ( _etm4Known( r, &h ) ) && ( !h->isP0 ) )
        {
            _handleInstruction( r, false, 0 );
        }
    }

    r->op.workingAddr   = retAddr;
    r->op.etm4ExPending = true;
    r->op.etm4ExRetAddr = retAddr;
}
// ====================================================================================================
static void _etm4CB( struct RunTime *r, struct TRACECPUState *cpu )

/* ETM4 trace callback. Unlike ETM3.5 an atom is not one instruction but a run of instructions up */
/* to a branch, and addresses come after the branch they belong to, so nothing is deferred.       */

{
    if ( _changed( cpu, EV_CH_EXRETURN ) )
    {
        r->op.etm4ExReturn = true;
    }

    if ( _changed( cpu, EV_CH_ADDRESS ) )
    {
        if ( _changed( cpu, EV_CH_EX_ENTRY ) )
        {
            /* Exception packet: this is the address it returns to */
            DBG_OUT( "EXCEPTION, returns to %08x" EOL, cpu->addr );
            _etm4Exception( r, cpu->addr );
        }
        else if ( r->op.etm4ExPending )
        {
            /* Start of the exception handler: a call from where it returns to */
            DBG_OUT( "HANDLER %08x" EOL, cpu->addr );
            r->op.etm4ExPending = false;
            _callEvent( r, r->op.etm4ExRetAddr, cpu->addr, NULL );
            r->op.workingAddr = cpu->addr;
        }
        else
        {
            uint32_t popped = 0;

            if ( r->op.etm4Pending )
            {
                /* Destination of the last indirect branch */
                popped = _etm4Resolve( r, cpu->addr );
            }

            if ( ( r->op.etm4ExReturn ) && ( !popped ) )
            {
                /* Exception return without a return instruction seen: close the exception's call */
                _returnEvent( r, cpu->addr, true );
            }

            r->op.workingAddr = cpu->addr;
            DBG_OUT( "A:%08x" EOL, cpu->addr );
        }

        r->op.etm4ExReturn = false;
    }

    if ( _changed( cpu, EV_CH_ENATOMS ) )
    {
        uint32_t n = cpu->eatoms + cpu->natoms;
        uint32_t disposition = cpu->disposition;

        DBG_OUT( "E:%d N:%d" EOL, cpu->eatoms, cpu->natoms );

        while ( n-- )
        {
            _etm4Atom( r, disposition & 1 );
            disposition >>= 1;
        }
    }
}
// ====================================================================================================
static void _traceCB( void *d )

/* Callback function for when valid TRACE decode is detected */

{
    struct RunTime *r       = ( struct RunTime * )d;
    struct TRACECPUState *cpu = &r->i.cpu;
    static uint32_t incAddr        = 0;
    static uint32_t disposition    = 0;
    static uint32_t deferredCycles = 0;
    uint32_t cycleBudget           = 0;

    /* This routine gets called when valid data are available */
    /* if these are the first data, then reset counters etc.  */
    if ( !r->sampling )
    {
        r->op.firsttstamp = cpu->instCount;
        genericsReport( V_INFO, "Sampling" EOL );
        /* Fill in a time to start from */
        r->starttime = genericsTimestampmS();

        if ( _changed( cpu, EV_CH_ADDRESS ) )
        {
            r->op.workingAddr = cpu->addr;
            DBG_OUT( "Got initial address %08x" EOL, r->op.workingAddr );
            r->sampling  = true;
        }

        /* Create false entry for an unknown position. It isn't executed code, so it isn't */
        /* added to the instruction table (it would be written to the profile).             */
        if ( !r->op.inth )
        {
            r->op.inth = calloc( 1, sizeof( struct execEntryHash ) );

            MEMCHECKV( r->op.inth );
            r->op.inth->addr          = INTERRUPT;
            r->op.inth->fileindex     = INTERRUPT;
            r->op.inth->line          = NO_LINE;
            r->op.inth->functionindex = INTERRUPT;
        }
    }

    r->op.lasttstamp = cpu->instCount;

    /* Pull changes introduced by this event ============================== */

    /* Cycle count packets (cycle accurate trace) report cycles not covered by P-headers */
    if ( ( _changed( cpu, EV_CH_CYCLECOUNT ) ) && ( r->sampling ) )
    {
        r->pendingCycles += cpu->cycleCount;
        r->packetCycles  += cpu->cycleCount;
    }

    if ( r->options->tProtocol == TRACE_PROT_ETM4 )
    {
        if ( r->sampling )
        {
            _etm4CB( r, cpu );
        }

        return;
    }

    if ( _changed( cpu, EV_CH_ENATOMS ) )
    {
        if ( _changed( cpu, EV_CH_WATOMS ) )
        {
            /* Cycle accurate: watoms cycles for these atoms. Waits beyond one per atom come  */
            /* first (format 3), and belong to the next instruction to complete. If there are */
            /* more atoms than cycles (format 2 and 4), the later atoms took no extra cycle.  */
            uint32_t atoms = cpu->eatoms + cpu->natoms;
            uint32_t lead  = ( cpu->watoms > atoms ) ? cpu->watoms - atoms : 0;

            r->pendingCycles += lead;
            cycleBudget = cpu->watoms - lead;

            if ( !atoms )
            {
                /* Only waits: leave the outstanding instruction and any address for the next atoms */
                return;
            }
        }

        /* Reading a change clears it, so collect what came with these atoms once */
        bool newAddr = _changed( cpu, EV_CH_ADDRESS );
        bool exEntry = _changed( cpu, EV_CH_EX_ENTRY );
        bool exExit  = _changed( cpu, EV_CH_EX_EXIT );
        uint32_t popped = 0;

        /* An exception is taken when the new address is the start of a handler. A branch with */
        /* exception information back into the middle of a function is an exception return.    */
        bool interrupt = newAddr && exEntry && _isFunctionEntry( r, cpu->addr );

        /* We are going to execute some instructions. Check if the last of the old batch of    */
        /* instructions was cancelled and, if it wasn't and it's still outstanding, action it. */
        if ( _changed( cpu, EV_CH_CANCELLED ) )
        {
            /* Its cycles go to the next instruction that completes */
            DBG_OUT( "CANCELLED" EOL );
            r->pendingCycles += deferredCycles;
        }
        else
        {
            if ( incAddr )
            {
                DBG_OUT( "***" EOL );
                _handleInstruction( r, disposition & 1, deferredCycles );

                if ( ( r->op.h->isJump ) || ( r->op.h->isSubCall ) || ( r->op.h->isReturn ) )
                {
                    /* The new address is where this branch went, unless it is an exception handler */
                    if ( ( newAddr ) && ( !interrupt ) )
                    {
                        DBG_OUT( "New addr %08x" EOL, cpu->addr );
                        r->op.workingAddr = cpu->addr;
                        newAddr = false;
                    }

                    popped = _checkJumps( r, disposition & 1 );
                }
            }
        }

        if ( newAddr )
        {
            if ( interrupt )
            {
                /* The exception is a call from where the interrupted code resumes. After a return */
                /* the trace gave no destination for (tail-chaining), that is where it returned to. */
                DBG_OUT( "INTERRUPT!!" EOL );
                _callEvent( r, ( ( ( r->op.workingAddr & SPECIALS_MASK ) == SPECIALS_MASK ) && ( popped ) ) ? popped : r->op.workingAddr, cpu->addr, NULL );
            }
            else if ( ( ( exEntry ) || ( exExit ) ) && ( !popped ) )
            {
                /* Exception return without a return instruction seen: close the interrupt call */
                _returnEvent( r, cpu->addr, true );
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
        if ( ( !cycleBudget ) && ( !r->pendingCycles ) && ( incAddr > 1 ) )
        {
            /* Not cycle accurate (the usual case): the quick way */
            _runAtoms( r, incAddr - 1, disposition );
            disposition >>= ( incAddr - 1 );
            incAddr = 1;
        }

        while ( incAddr > 1 )
        {
            incAddr--;
            _handleInstruction( r, disposition & 1, _atomCycles( r, &cycleBudget ) );
            _checkJumps( r, disposition & 1 );
            disposition >>= 1;
        }

        /* ...whose cycles are kept until it is actioned */
        deferredCycles = incAddr ? _atomCycles( r, &cycleBudget ) : 0;
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
    genericsFPrintf( stderr, "    -b, --buffer-size:  <MiB> Most memory for trace waiting to be decoded (default %d). Decoding" EOL, DEFAULT_BUFFER_MB );
    genericsFPrintf( stderr, "                        can be slower than a fast CPU makes ETM data, so this sets how long a" EOL );
    genericsFPrintf( stderr, "                        capture can be. Memory is only used while there is a backlog" EOL );
    genericsFPrintf( stderr, "    -c, --coverage-file: <Filename> lcov tracefile for line, function and branch coverage" EOL );
    genericsFPrintf( stderr, "    -g, --timeline-file: <Filename> timeline of function calls and exceptions (Chrome trace JSON," EOL );
    genericsFPrintf( stderr, "                        for ui.perfetto.dev or chrome://tracing). Time is in instructions," EOL );
    genericsFPrintf( stderr, "                        or in cycles with cycle accurate trace" EOL );
    genericsFPrintf( stderr, "    -G, --timeline-min: <Count> leave calls shorter than this out of the timeline (default 0)" EOL );
    genericsFPrintf( stderr, "    -I, --interval:     <Interval> Time to capture (in ms, default %d), 0 = until CTRL-C" EOL, DEFAULT_DURATION_MS );
    genericsFPrintf( stderr, "    -l, --live:         <Interval> Live mode: capture until CTRL-C (or for -I), rewriting the coverage" EOL );
    genericsFPrintf( stderr, "                        file and reporting progress every <Interval> ms" EOL );
    genericsFPrintf( stderr, "    -M, --no-colour:    Supress colour in output" EOL );
    genericsFPrintf( stderr, "    -O, --objdump-opts: <options> Options to pass directly to objdump" EOL );
    genericsFPrintf( stderr, "    -P, --trace-proto:  { " );

    for ( int i = TRACE_PROT_LIST_START; i < TRACE_PROT_LIST_END; i++ )
    {
        genericsFPrintf( stderr, "%s ", TRACEDecodeGetProtocolName( i ) );
    }

    genericsFPrintf( stderr, "} trace protocol to use, default is %s" EOL, TRACEDecodeGetProtocolName( TRACE_PROT_LIST_START ) );
    genericsFPrintf( stderr, "    -p, --protocol:     Protocol to communicate. Defaults to OFLOW if -s is not set, otherwise raw ETM" EOL );
    genericsFPrintf( stderr, "    -s, --server:       <Server>:<Port> to use" EOL );
    genericsFPrintf( stderr, "    -t, --tag:          <stream>: Which OFLOW tag to use (normally 2)" EOL );
    genericsFPrintf( stderr, "    -T, --all-truncate: truncate -d material off all references (i.e. make output relative)" EOL );
    genericsFPrintf( stderr, "    -v, --verbose:      <level> Verbose mode 0(errors)..3(debug)" EOL );
    genericsFPrintf( stderr, "    -V, --version:      Print version and exit" EOL );
    genericsFPrintf( stderr, "    -X, --stop-on-drop: <name> Stop when trace has to be discarded because decoding fell behind, or at" EOL );
    genericsFPrintf( stderr, "                        the first trace fault (execution running from one function straight into" EOL );
    genericsFPrintf( stderr, "                        the next), and write <name>.trace (the trace around that point, replay" EOL );
    genericsFPrintf( stderr, "                        with -f) and <name>.txt (what happened, rates, where the decoder was)" EOL );
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
    {"live", required_argument, NULL, 'l'},
    {"timeline-file", required_argument, NULL, 'g'},
    {"timeline-min", required_argument, NULL, 'G'},
    {"buffer-size", required_argument, NULL, 'b'},
    {"stop-on-drop", required_argument, NULL, 'X'},
    {"coverage-file", required_argument, NULL, 'c'},
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
    bool durationSet = false;

    while ( ( c = getopt_long ( argc, argv, "Ab:c:Dd:e:Ef:g:G:hVI:l:MO:P:p:s:t:Tv:X:y:z:", _longOptions, &optionIndex ) ) != -1 )

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
            case 'X':
                r->options->dropDump = optarg;
                break;

            // ------------------------------------
            case 'b':
                r->options->bufferMB = atoi( optarg );

                if ( r->options->bufferMB <= 0 )
                {
                    genericsReport( V_ERROR, "-b requires a positive size in MiB" EOL );
                    return false;
                }

                break;

            case 'I':
                r->options->sampleDuration = atoi( optarg );
                durationSet = true;
                break;

            // ------------------------------------
            case 'g':
                r->options->timelineFile = optarg;
                break;

            // ------------------------------------
            case 'G':
                r->options->timelineMin = strtoul( optarg, NULL, 0 );
                break;

            // ------------------------------------
            case 'l':
                r->options->liveInterval = atoi( optarg );

                if ( r->options->liveInterval < LIVE_MIN_INTERVAL_MS )
                {
                    r->options->liveInterval = LIVE_MIN_INTERVAL_MS;
                }

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
            case 'c':
                r->options->lcovfile = optarg;
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

    /* Live mode runs until stopped unless a time was given */
    if ( ( r->options->liveInterval ) && ( !durationSet ) )
    {
        r->options->sampleDuration = 0;
    }

    if ( r->options->sampleDuration < 0 )
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
    genericsReport( V_INFO, "Coverage file   : %s" EOL, r->options->lcovfile ? r->options->lcovfile : "None" );
    if ( r->options->sampleDuration )
    {
        genericsReport( V_INFO, "Sample Duration : %d mS" EOL, r->options->sampleDuration );
    }
    else
    {
        genericsReport( V_INFO, "Sample Duration : until CTRL-C" EOL );
    }

    if ( r->options->liveInterval )
    {
        genericsReport( V_INFO, "Live updates    : every %d mS" EOL, r->options->liveInterval );
    }
    genericsReport( V_INFO, "Capture buffer  : %d MiB" EOL, r->options->bufferMB );

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
static int _currentCore( void )

{
#ifdef WIN32
    return ( int )GetCurrentProcessorNumber();
#elif defined(__linux__)
    return sched_getcpu();
#else
    return -1;
#endif
}
// ====================================================================================================
#ifdef WIN32
/* As Windows declares it; written out here so that older headers will do */
struct orbCpuSetInfo
{
    DWORD size;
    DWORD type;
    DWORD id;
    WORD group;
    BYTE logicalProcessorIndex;
    BYTE coreIndex;
    BYTE lastLevelCacheIndex;
    BYTE numaNodeIndex;
    BYTE efficiencyClass;
    BYTE flags;
    DWORD reserved;
    DWORD64 allocationTag;
};
#endif

static void _preferFastCores( struct RunTime *r )

/* Decoding is one thread working flat out, and it has to keep up with the trace. On a processor */
/* with performance and efficiency cores (Intel 12th generation on) Windows is free to run it on */
/* an efficiency core, or to treat a console program in the background as low priority work, and */
/* it then decodes at well under half the speed and falls behind. So: ask not to be throttled,   */
/* raise the priority a little, and keep the process on the fastest class of core.               */

{
#ifdef WIN32
    HMODULE k = GetModuleHandleA( "kernel32.dll" );
    BOOL ( WINAPI * getSets )( void *, ULONG, PULONG, HANDLE, ULONG ) = ( void * )GetProcAddress( k, "GetSystemCpuSetInformation" );
    BOOL ( WINAPI * setSets )( HANDLE, const ULONG *, ULONG ) = ( void * )GetProcAddress( k, "SetProcessDefaultCpuSets" );
    BOOL ( WINAPI * setInfo )( HANDLE, int, void *, DWORD ) = ( void * )GetProcAddress( k, "SetProcessInformation" );
    static uint8_t buf[64 * 1024];
    ULONG ids[1024];
    ULONG len = 0, n = 0, slow = 0;
    BYTE best = 0;

    SetPriorityClass( GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS );

    if ( setInfo )
    {
        /* ProcessPowerThrottling (4): version 1, control EXECUTION_SPEED (1), state 0 = never throttle */
        ULONG state[3] = { 1, 1, 0 };
        setInfo( GetCurrentProcess(), 4, state, sizeof( state ) );
    }

    if ( ( !getSets ) || ( !setSets ) || ( !getSets( buf, sizeof( buf ), &len, GetCurrentProcess(), 0 ) ) )
    {
        return;
    }

    for ( int pass = 0; pass < 2; pass++ )
    {
        for ( ULONG o = 0; o + sizeof( struct orbCpuSetInfo ) <= len; )
        {
            struct orbCpuSetInfo *c = ( struct orbCpuSetInfo * )&buf[o];

            if ( c->size < 16 )
            {
                break;
            }

            if ( c->type == 0 )
            {
                if ( !pass )
                {
                    if ( c->efficiencyClass > best )
                    {
                        best = c->efficiencyClass;
                    }
                }
                else if ( c->efficiencyClass != best )
                {
                    slow++;
                }
                else if ( n < sizeof( ids ) / sizeof( ids[0] ) )
                {
                    ids[n++] = c->id;
                }
            }

            o += c->size;
        }
    }

    /* Only worth doing (and only done) when the cores are not all alike */
    if ( ( slow ) && ( n ) && ( setSets( GetCurrentProcess(), ids, n ) ) )
    {
        r->fastCores = ( int )n;
        r->slowCores = ( int )slow;
        genericsReport( V_INFO, "Using the %d performance cores, not the %d efficiency cores" EOL, r->fastCores, r->slowCores );
    }

#else
    ( void )r;
#endif
}
// ====================================================================================================
static uint64_t _threadCpuMs( void )

/* Processor time used by the calling thread */

{
#ifdef WIN32
    FILETIME c, e, k, u;

    if ( !GetThreadTimes( GetCurrentThread(), &c, &e, &k, &u ) )
    {
        return 0;
    }

    return ( ( ( ( uint64_t )k.dwHighDateTime << 32 ) | k.dwLowDateTime ) + ( ( ( uint64_t )u.dwHighDateTime << 32 ) | u.dwLowDateTime ) ) / 10000;
#else
    struct timespec ts;

    if ( clock_gettime( CLOCK_THREAD_CPUTIME_ID, &ts ) )
    {
        return 0;
    }

    return ( uint64_t )ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}
// ====================================================================================================
static uint32_t _waitingBlocks( struct RunTime *r )

{
    return ( uint32_t )( ( r->wp + r->numBlocks - r->rp ) % r->numBlocks );
}
// ====================================================================================================
static void _dropSample( struct RunTime *r )

/* -X: note the state once a second (called from the receiving thread) */

{
    uint32_t now = genericsTimestampmS();
    struct dropSample *d;

    if ( ( !r->options->dropDump ) || ( !r->sampling ) || ( now - r->lastSample < 1000 ) )
    {
        return;
    }

    r->lastSample = now;
    d = &r->samp[r->sampHead];
    r->sampHead = ( r->sampHead + 1 ) % DROP_SAMPLES;

    if ( r->sampCount < DROP_SAMPLES )
    {
        r->sampCount++;
    }

    d->ms = now - r->starttime;
    d->rxBytes = r->intervalBytes;
    d->decodedBytes = r->decodedBytes;
    d->inst = r->instExecuted;
    d->lost = _lostInstructions;
    d->cpuMs = r->decodeCpuMs;
    d->liveMs = r->liveMs;
    d->waitingBlocks = _waitingBlocks( r );
    d->blockMs = ( ( int32_t )( now - r->blockStartMs ) > 0 ) ? now - r->blockStartMs : 0;
    d->core = r->decodeCore;
}
// ====================================================================================================
static const char *_whereIs( struct RunTime *r, uint32_t addr, char *out, size_t len )

{
    struct nameEntry n;

    if ( ( addr & SPECIALS_MASK ) == SPECIALS_MASK )
    {
        snprintf( out, len, "0x%08" PRIx32 " (not an address: position unknown)", addr );
    }
    else if ( SymbolLookup( r->s, addr, &n ) )
    {
        snprintf( out, len, "0x%08" PRIx32 " %s, %s:%u", addr, SymbolFunction( r->s, n.functionindex ), SymbolFilename( r->s, n.fileindex ), ( unsigned )n.line );
    }
    else
    {
        snprintf( out, len, "0x%08" PRIx32 " (not in the ELF file)", addr );
    }

    return out;
}
// ====================================================================================================
static void _dropDump( struct RunTime *r, struct dataBlock *rxBlock, bool fault )

/* -X: decoding fell so far behind that trace has to be discarded. Write what is needed to find */
/* out why: the trace from 64 MiB before the decoder's position to the newest data received,    */
/* and a report. Called from the receiving thread; the decoder is still at work, so its state   */
/* is read as it happens to be.                                                                  */

{
    char name[1024], where[512];
    uint64_t before = 0, waiting = 0;
    uint32_t now = genericsTimestampmS();
    struct TRACEDecoderStats *st = TRACEDecoderGetStats( &r->i );
    FILE *f;

    genericsFPrintf( stderr, EOL "%s: stopping (-X)" EOL, fault ? "Trace fault (execution ran from one function straight into the next)" :
                     "Decoding fell behind and trace would be lost" );

    /* ---- The trace ---- */
    snprintf( name, sizeof( name ), "%s.trace", r->options->dropDump );
    f = fopen( name, "wb" );
    pthread_mutex_lock( &r->dataForClients_m );

    if ( f )
    {
        for ( int i = 0; i < r->histCount; i++ )
        {
            struct dataBlock *b = r->hist[( r->histHead + HIST_BLOCKS - r->histCount + i ) % HIST_BLOCKS];
            before += fwrite( b->buffer, 1, b->fillLevel, f );
        }

        for ( int i = r->rp; i != r->wp; i = ( i + 1 ) % r->numBlocks )
        {
            if ( ( r->rawBlock[i] ) && ( r->rawBlock[i]->fillLevel > 0 ) )
            {
                waiting += fwrite( r->rawBlock[i]->buffer, 1, r->rawBlock[i]->fillLevel, f );
            }
        }

        if ( rxBlock->fillLevel > 0 )
        {
            waiting += fwrite( rxBlock->buffer, 1, rxBlock->fillLevel, f );
        }

        fclose( f );
    }

    pthread_mutex_unlock( &r->dataForClients_m );

    /* ---- The report ---- */
    snprintf( name, sizeof( name ), "%s.txt", r->options->dropDump );
    f = fopen( name, "w" );

    if ( !f )
    {
        genericsReport( V_ERROR, "Could not write %s" EOL, name );
        return;
    }

    fprintf( f, "orbprofile stopped because %s\n", fault ? "of a trace fault" : "decoding fell behind the trace" );
    fprintf( f, "=========================================================\n\n" );
    fprintf( f, "Version           : %s\n", GIT_DESCRIBE );
    fprintf( f, "ELF file          : %s\n", r->options->elffile );
    fprintf( f, "Trace protocol    : %s, link %s, tag %d\n", TRACEDecodeGetProtocolName( r->options->tProtocol ),
             ( PROT_OFLOW == r->options->protocol ) ? "OFLOW" : "raw", r->options->tag );
    fprintf( f, "Capture time      : %.1f s\n", ( now - r->starttime ) / 1000.0 );
    fprintf( f, "Buffer limit (-b) : %d MiB\n\n", r->options->bufferMB );

    fprintf( f, "Received          : %.1f MB\n", r->intervalBytes / 1e6 );
    fprintf( f, "Given to decoder  : %.1f MB\n", r->decodedBytes / 1e6 );
    fprintf( f, "Waiting           : %.1f MB in %u blocks\n", waiting / 1e6, _waitingBlocks( r ) + 1 );
    fprintf( f, "Instructions      : %" PRIu64 " decoded, %" PRIu64 " skipped (position not known)\n", r->instExecuted, _lostInstructions );
    fprintf( f, "Decoder sync      : gained %u times, lost %u times\n", st->syncCount, st->lostSyncCount );
    fprintf( f, "Decoder thread    : %.1f s of processor time, %.1f s of it writing live results\n", r->decodeCpuMs / 1000.0, r->liveMs / 1000.0 );
    fprintf( f, "Current block     : the decoder has been on it for %u ms\n\n", ( ( int32_t )( now - r->blockStartMs ) > 0 ) ? now - r->blockStartMs : 0 );

    if ( r->traceFaults )
    {
        char w2[512];
        fprintf( f, "Trace faults      : %" PRIu64 "\n", r->traceFaults );
        fprintf( f, "   Execution ran from the last instruction of one function straight on into another. Compiled\n" );
        fprintf( f, "   code does not do that, so trace was lost or damaged just before each of these:\n" );

        for ( uint64_t i = 0; ( i < r->traceFaults ) && ( i < FAULTS_KEPT ); i++ )
        {
            fprintf( f, "   %8.3f s  after %" PRIu64 " instructions\n              from %s\n              into %s\n", r->fault[i].ms / 1000.0, r->fault[i].inst,
                     _whereIs( r, r->fault[i].from, where, sizeof( where ) ), _whereIs( r, r->fault[i].to, w2, sizeof( w2 ) ) );
        }

        fprintf( f, "\n" );
    }

    fprintf( f, "Where the decoder is\n--------------------\n" );
    fprintf( f, "Next address      : %s\n", _whereIs( r, r->op.workingAddr, where, sizeof( where ) ) );

    if ( r->op.h )
    {
        fprintf( f, "Last instruction  : %s\n", _whereIs( r, r->op.h->addr, where, sizeof( where ) ) );
    }

    fprintf( f, "Open calls        : %d\n", r->substacklen );

    for ( int i = r->substacklen - 1; ( i >= 0 ) && ( i >= r->substacklen - 12 ); i-- )
    {
        fprintf( f, "   %3d  %s\n", i, _whereIs( r, r->substack[i].sig.dst, where, sizeof( where ) ) );
    }

    fprintf( f, "\nThe last %d seconds\n-------------------\n", r->sampCount );
    fprintf( f, "Each line is one second. 'cpu' is how much of that second the decoding thread was running:\n" );
    fprintf( f, "near 1000 ms means it was working flat out, much less means it was waiting or held up.\n" );
    fprintf( f, "'core' is the processor it was on. If it decodes fewer instructions with the same cpu time, the\n" );
    fprintf( f, "processor was slower: an efficiency core, or the PC lowering its speed.\n" );

    if ( r->fastCores )
    {
        fprintf( f, "The process was restricted to the %d performance cores of this PC (%d efficiency cores not used).\n", r->fastCores, r->slowCores );
    }

    fprintf( f, "\n" );
    fprintf( f, "    time   received    decoded    waiting      instr   skipped    cpu   live  on block  core\n" );
    fprintf( f, "       s       MB/s       MB/s         MB        M/s        /s     ms     ms        ms\n" );

    for ( int i = 1; i < r->sampCount; i++ )
    {
        struct dropSample *a = &r->samp[( r->sampHead + DROP_SAMPLES - r->sampCount + i - 1 ) % DROP_SAMPLES];
        struct dropSample *b = &r->samp[( r->sampHead + DROP_SAMPLES - r->sampCount + i ) % DROP_SAMPLES];
        double dt = ( b->ms - a->ms ) / 1000.0;

        if ( dt <= 0 )
        {
            continue;
        }

        fprintf( f, "%8.1f %10.1f %10.1f %10.1f %10.1f %9.0f %6.0f %6.0f %9u %5d\n", b->ms / 1000.0,
                 ( b->rxBytes - a->rxBytes ) / 1e6 / dt, ( b->decodedBytes - a->decodedBytes ) / 1e6 / dt,
                 b->waitingBlocks * ( TRANSFER_SIZE / 1e6 ), ( b->inst - a->inst ) / 1e6 / dt, ( b->lost - a->lost ) / dt,
                 ( b->cpuMs - a->cpuMs ) / dt, ( b->liveMs - a->liveMs ) / dt, b->blockMs, b->core );
    }

    fprintf( f, "\nThe trace file\n--------------\n" );
    fprintf( f, "%s.trace holds %.1f MB: %.1f MB the decoder had already been through, then the block\n", r->options->dropDump, ( before + waiting ) / 1e6, before / 1e6 );
    fprintf( f, "it was working on (at byte %" PRIu64 "), then everything that was waiting.\n", before );

    if ( ( fault ) && ( r->decodedBytes - r->faultAtDecoded <= before ) )
    {
        fprintf( f, "The first trace fault is in the block of %d KB that starts at byte %" PRIu64 " of the file.\n",
                 TRANSFER_SIZE / 1024, before - ( r->decodedBytes - r->faultAtDecoded ) );
    }

    fprintf( f, "\n" );
    fprintf( f, "To decode it again:\n   orbprofile -e <elf> -f %s.trace -E -I 600000%s%s\n", r->options->dropDump,
             ( PROT_OFLOW == r->options->protocol ) ? "" : " -p ETM", ( r->options->tProtocol == TRACE_PROT_ETM4 ) ? " -P ETM4" : "" );
    fclose( f );

    genericsFPrintf( stderr, "Wrote %s.trace (%.1f MB) and %s.txt" EOL, r->options->dropDump, ( before + waiting ) / 1e6, r->options->dropDump );
}
// ====================================================================================================
static struct dataBlock _lastResort;            /* For the closing blocks if there is no memory left */

static struct dataBlock *_allocBlock( void )

/* Memory for one capture buffer, taken from and given back to the system directly so that */
/* what a backlog needed is returned once it has been decoded.                              */

{
#ifdef WIN32
    return ( struct dataBlock * )VirtualAlloc( NULL, sizeof( struct dataBlock ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
#else
    return ( struct dataBlock * )malloc( sizeof( struct dataBlock ) );
#endif
}
// ====================================================================================================
static void _freeBlock( struct dataBlock *b )

{
#ifdef WIN32
    VirtualFree( b, 0, MEM_RELEASE );
#else
    free( b );
#endif
}
// ====================================================================================================
static bool _queueBlock( struct RunTime *r, bool force )

/* Hand the block at wp (already filled in) to the processing thread and start a new, empty one. */
/* One slot is always kept free for the end-of-data block, which is queued with force set.       */
/* Returns false if the buffer is full (decoding has fallen too far behind).                     */

{
    struct dataBlock *nb;

    pthread_mutex_lock( &r->dataForClients_m );
    int nwp = ( r->wp + 1 ) % r->numBlocks;

    if ( ( ( nwp + 1 ) % r->numBlocks == r->rp ) && ( !force ) )
    {
        pthread_mutex_unlock( &r->dataForClients_m );
        return false;
    }

    /* Memory for the next block: one just emptied by the decoder if there is one, so that a  */
    /* capture the decoder keeps up with stays in the same few buffers, however large -b is.  */
    nb = r->numSpare ? r->spareBlock[--r->numSpare] : _allocBlock();

    if ( !nb )
    {
        if ( !force )
        {
            pthread_mutex_unlock( &r->dataForClients_m );
            return false;
        }

        nb = &_lastResort;
    }

    nb->fillLevel = 0;
    nb->afterGap = false;
    r->rawBlock[nwp] = nb;
    r->wp = nwp;
    pthread_cond_signal( &r->dataForClients );
    pthread_mutex_unlock( &r->dataForClients_m );
    return true;
}
// ====================================================================================================
static double _pct( uint32_t hit, uint32_t total )

{
    return total ? ( 100.0 * hit ) / total : 0.0;
}
// ====================================================================================================
static void _liveUpdate( struct RunTime *r )

/* Live mode: rewrite the coverage file with the results so far and report progress on one line. */
/* The file is written under a temporary name and then renamed, so a reader never sees half of it. */

{
    struct coverageTotals t;
    char tmpName[1024];
    bool have = false;

    uint32_t liveStart = genericsTimestampmS();
    r->lastLive = liveStart;

    if ( !HASH_COUNT( r->insthead ) )
    {
        return;
    }

    if ( r->options->lcovfile )
    {
        snprintf( tmpName, sizeof( tmpName ), "%s.tmp", r->options->lcovfile );

        if ( ext_ff_outputLcov( tmpName, r->options->truncateDeleteMaterial ? r->options->deleteMaterial : NULL,
                                r->insthead, r->s, &t ) )
        {
            /* rename doesn't replace an existing file on Windows */
            remove( r->options->lcovfile );
            have = ( 0 == rename( tmpName, r->options->lcovfile ) );
        }
    }

    r->liveUpdates++;
    genericsFPrintf( stderr, "\r%6u s  %8.1f MB  %" PRIu64 " instr", ( genericsTimestampmS() - r->starttime ) / 1000,
                     ( double )r->intervalBytes / 1e6, r->instExecuted );

    if ( have )
    {
        genericsFPrintf( stderr, "  lines %u/%u (%.1f%%)  functions %u/%u  branches %u/%u (%.1f%%)",
                         t.linesHit, t.lines, _pct( t.linesHit, t.lines ), t.functionsHit, t.functions,
                         t.branchesHit, t.branches, _pct( t.branchesHit, t.branches ) );
    }

    if ( r->droppedBytes )
    {
        genericsFPrintf( stderr, "  DROPPED %.1f MB", ( double )r->droppedBytes / 1e6 );
    }

    if ( r->traceFaults )
    {
        genericsFPrintf( stderr, "  FAULTS %" PRIu64, r->traceFaults );
    }

    genericsFPrintf( stderr, "   " );
    fflush( stderr );
    r->liveMs += genericsTimestampmS() - liveStart;
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

        struct dataBlock *b = r->rawBlock[r->rp];
        genericsReport( V_DEBUG, "RXED Packet of %d bytes" EOL, ( int )b->fillLevel );

        /* A zero length block marks the end of the data */
        if ( b->fillLevel <= 0 )
        {
            break;
        }

        r->blockStartMs = genericsTimestampmS();

        if ( r->abandon )
        {
            /* Stopped by -X: what is still waiting has been written to the file instead */
            goto blockDone;
        }

        if ( b->afterGap )
        {
            /* Blocks before this one were discarded: wait for the trace to say where it is again. */
            /* The calls that were open can no longer be matched to their returns.                 */
            TRACEDecoderForceSync( &r->i, false );
            r->op.workingAddr = NO_DESTADDRESS;
            r->op.etm4Pending = false;
            r->op.etm4ExPending = false;
            _timelineCloseOpenCalls( r );
            r->substacklen = 0;
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

        r->decodedBytes += b->fillLevel;
        r->decodeCpuMs = _threadCpuMs();
        r->decodeCore = _currentCore();

blockDone:
        pthread_mutex_lock( &r->dataForClients_m );
        r->rawBlock[r->rp] = NULL;
        r->rp = ( r->rp + 1 ) % r->numBlocks;

        if ( ( r->options->dropDump ) && ( !r->abandon ) && ( b != &_lastResort ) )
        {
            /* Keep it for a while: the block it pushes out is the one to reuse or free */
            struct dataBlock *old = ( r->histCount == HIST_BLOCKS ) ? r->hist[r->histHead] : NULL;
            r->hist[r->histHead] = b;
            r->histHead = ( r->histHead + 1 ) % HIST_BLOCKS;

            if ( r->histCount < HIST_BLOCKS )
            {
                r->histCount++;
            }

            b = old;
        }

        if ( !b )
        {
        }
        else if ( b == &_lastResort )
        {
            b = NULL;
        }
        else if ( r->numSpare < SPARE_BLOCKS )
        {
            r->spareBlock[r->numSpare++] = b;
            b = NULL;
        }

        pthread_mutex_unlock( &r->dataForClients_m );

        if ( b )
        {
            _freeBlock( b );
        }

        /* Live mode: results so far. Done here because this thread owns the instruction table. */
        if ( ( r->options->liveInterval ) && ( r->sampling ) &&
                ( ( genericsTimestampmS() - r->lastLive ) >= ( uint32_t )r->options->liveInterval ) )
        {
            _liveUpdate( r );
        }
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

    /* Capture buffer: whole blocks of TRANSFER_SIZE, at least MIN_RAW_BLOCKS of them */
    _r.numBlocks = ( int )( ( ( uint64_t )_r.options->bufferMB * 1024 * 1024 ) / TRANSFER_SIZE );

    if ( _r.numBlocks < MIN_RAW_BLOCKS )
    {
        _r.numBlocks = MIN_RAW_BLOCKS;
    }

    _r.rawBlock = ( struct dataBlock ** )calloc( ( size_t )_r.numBlocks, sizeof( struct dataBlock * ) );
    if ( _r.rawBlock )
    {
        _r.rawBlock[0] = _allocBlock();
    }

    if ( ( !_r.rawBlock ) || ( !_r.rawBlock[0] ) )
    {
        genericsExit( -1, "Out of memory for the capture buffer" EOL );
    }

    _r.rawBlock[0]->fillLevel = 0;
    _r.rawBlock[0]->afterGap = false;

    if ( _r.options->timelineFile )
    {
        _r.timeline = fopen( _r.options->timelineFile, "wb" );

        if ( !_r.timeline )
        {
            genericsExit( -1, "Can't write %s" EOL, _r.options->timelineFile );
        }

        fprintf( _r.timeline, "{\"displayTimeUnit\":\"ns\",\"traceEvents\":[\n" );
        _r.rootFn = NO_FUNCTION;
    }

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
            _preferFastCores( &_r );
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
            /* (every instruction is decoded), so the buffer (-b, numBlocks x TRANSFER_SIZE)      */
            /* holds the capture while decoding catches up.                                     */
            struct dataBlock *rxBlock = _r.rawBlock[_r.wp];
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

            /* Pass the block on when it's full, or, when the data pause, only if the decoder has */
            /* nothing to do (otherwise half-empty blocks would use up the buffer).               */
            if ( ( rxBlock->fillLevel >= TRANSFER_SIZE ) ||
                    ( ( got == 0 ) && ( rxBlock->fillLevel > 0 ) && ( ( volatile int )_r.rp == _r.wp ) ) )
            {
                /* A file can wait for the decoder, so nothing needs to be lost */
                while ( ( _r.options->file ) && ( !_r.ending ) && ( !_queueBlock( &_r, false ) ) )
                {
                    usleep( 1000 );
                }

                if ( ( !_r.options->file ) && ( !_queueBlock( &_r, false ) ) )
                {
                    if ( _r.options->dropDump )
                    {
                        _dropDump( &_r, rxBlock, false );
                        rxBlock->fillLevel = 0;
                        _r.abandon = true;
                        _r.ending = true;
                    }
                    else if ( _r.options->sampleDuration )
                    {
                        genericsReport( V_WARN, "Capture buffer full after %u ms: stopping capture and decoding what was received" EOL,
                                        _r.sampling ? genericsTimestampmS() - _r.starttime : 0 );
                        rxBlock->fillLevel = 0;
                        _r.ending = true;
                    }
                    else
                    {
                        /* Running until stopped: discard this block and carry on. The decoder */
                        /* finds its place again at the next sync in the trace.                 */
                        _r.droppedBytes += rxBlock->fillLevel;
                        rxBlock->fillLevel = 0;

                        /* The gap is here, in front of what this block receives next: the decoder */
                        /* must not carry on across it, but everything queued before it is good.   */
                        rxBlock->afterGap = true;
                    }
                }
            }

            _dropSample( &_r );

            if ( ( _r.faultStop ) && ( !_r.abandon ) )
            {
                /* The decoder found a trace fault (-X): save the trace around it and stop */
                _dropDump( &_r, rxBlock, true );
                rxBlock->fillLevel = 0;
                _r.abandon = true;
                _r.ending = true;
            }

            /* Stop once the sample interval is over */
            if ( ( _r.options->sampleDuration ) && ( ( volatile bool ) _r.sampling ) &&
                    ( ( genericsTimestampmS() - ( volatile uint32_t )_r.starttime ) > ( uint32_t )_r.options->sampleDuration ) )
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
        if ( _r.rawBlock[_r.wp]->fillLevel > 0 )
        {
            _queueBlock( &_r, true );
        }

        genericsReport( V_INFO, "Capture done (%" PRIu64 " bytes), finishing decoding..." EOL, _r.intervalBytes );
        _r.rawBlock[_r.wp]->fillLevel = 0;
        _queueBlock( &_r, true );
        pthread_join( _r.processThread, NULL );
    }

    if ( _r.liveUpdates )
    {
        genericsFPrintf( stderr, EOL );
    }

    if ( _r.timeline )
    {
        _timelineCloseOpenCalls( &_r );

        /* Program name without its path (either separator, for Windows), made safe for JSON */
        const char *pn = _r.options->elffile;
        char pname[200];

        for ( const char *c = pn; *c; c++ )
        {
            if ( ( *c == '/' ) || ( *c == '\\' ) )
            {
                pn = c + 1;
            }
        }

        _jsonString( pn, pname, sizeof( pname ) );
        fprintf( _r.timeline, "%s{\"name\":\"process_name\",\"ph\":\"M\",\"pid\":1,\"args\":{\"name\":\"%s (time in %s)\"}}\n]}\n",
                 _r.timelineEvents ? ",\n" : "", pname, _timelineInCycles( &_r ) ? "cycles" : "instructions" );
        fclose( _r.timeline );
        _r.timeline = NULL;
        genericsReport( V_WARN, "Timeline: %" PRIu64 " calls written, %" PRIu64 " left out (time in %s)" EOL, _r.timelineEvents, _r.timelineSkipped,
                        _timelineInCycles( &_r ) ? "cycles" : "instructions" );
    }

    /* Data are collected, now process and report */
    genericsReport( V_INFO, "Received %d raw sample bytes, %ld function changes, %ld distinct addresses" EOL,
                    _r.intervalBytes, HASH_COUNT( _r.subhead ), HASH_COUNT( _r.insthead ) );

    if ( _r.droppedBytes )
    {
        genericsReport( V_WARN, "%.1f MB of trace discarded because decoding could not keep up: code that ran in those "
                        "parts can show as not run, and call costs are approximate" EOL, ( double )_r.droppedBytes / 1e6 );
    }

    if ( _r.traceFaults )
    {
        genericsReport( V_WARN, "%" PRIu64 " trace fault%s: execution ran from one function straight into the next, so trace was lost or "
                        "damaged there and a few instructions are counted in the wrong place%s" EOL, _r.traceFaults, ( _r.traceFaults == 1 ) ? "" : "s",
                        _r.options->dropDump ? "" : " (use -X to stop at the first and save the trace)" );

        for ( uint64_t i = 0; ( i < _r.traceFaults ) && ( i < FAULTS_KEPT ); i++ )
        {
            char w1[512], w2[512];
            genericsReport( V_WARN, "  after %" PRIu64 " instructions: from %s into %s" EOL, _r.fault[i].inst,
                            _whereIs( &_r, _r.fault[i].from, w1, sizeof( w1 ) ), _whereIs( &_r, _r.fault[i].to, w2, sizeof( w2 ) ) );
        }
    }

    if ( _lostInstructions )
    {
        genericsReport( V_INFO, "%" PRIu64 " instructions skipped where the trace position was not known" EOL, _lostInstructions );
    }

    if ( _r.cyclesExecuted )
    {
        genericsReport( V_INFO, "Cycle accurate: %" PRIu64 " cycles for %" PRIu64 " instructions (%" PRIu64 " from cycle count packets)" EOL,
                        _r.cyclesExecuted, _r.instExecuted, _r.packetCycles );
    }

    /* Coverage only needs executed instructions, so it doesn't depend on calls being seen */
    if ( _r.options->lcovfile )
    {
        struct coverageTotals t;

        if ( ( HASH_COUNT( _r.insthead ) ) &&
                ( ext_ff_outputLcov( _r.options->lcovfile,
                                     _r.options->truncateDeleteMaterial ? _r.options->deleteMaterial : NULL,
                                     _r.insthead, _r.s, &t ) ) )
        {
            genericsReport( V_INFO, "Output Coverage" EOL );
            genericsReport( V_WARN, "Coverage: lines %u/%u (%.1f%%), functions %u/%u (%.1f%%), branches %u/%u (%.1f%%)" EOL,
                            t.linesHit, t.lines, _pct( t.linesHit, t.lines ),
                            t.functionsHit, t.functions, _pct( t.functionsHit, t.functions ),
                            t.branchesHit, t.branches, _pct( t.branchesHit, t.branches ) );
        }
        else
        {
            genericsExit( -1, "Failed to output coverage" EOL );
        }
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
