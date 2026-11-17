/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * Data trace logger for Orbuculum
 * ===============================
 *
 * Logs the values the target writes to (or reads from) up to four watched variables, using the
 * data trace packets the DWT comparators send through the ITM. Nothing is added to the target
 * program: a comparator is given the address of a variable and reports every access to it.
 *
 * The comparators are set up in the target (debugger or firmware). --setup prints the register
 * writes for the variables given, as gdb, Keil, IAR or C lines. Comparator n watches the n'th -w.
 */

#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/time.h>

#include "generics.h"
#include "git_version_info.h"
#include "oflow.h"
#include "itmDecoder.h"
#include "msgDecoder.h"
#include "stream.h"
#include "nw.h"

#define MAX_WATCH       (4)                 /* Comparators in a Cortex-M3/M4/M7 DWT */
#define MAX_PENDING     (4096)              /* Samples held while waiting for their timestamp */
#define OBJDUMP         "arm-none-eabi-objdump"
#define OBJENVNAME      "OBJDUMP"

#define DWT_COMP(n)     (0xE0001020u + 16u * (n))
#define DWT_MASK(n)     (0xE0001024u + 16u * (n))
#define DWT_FUNCTION(n) (0xE0001028u + 16u * (n))
#define DEMCR           (0xE000EDFCu)
#define ITM_LAR         (0xE0000FB0u)
#define ITM_TCR         (0xE0000E80u)

#define FN_DATA_WRITE   (0xDu)              /* Sample data value on write */
#define FN_DATA_READ    (0xCu)              /* Sample data value on read */
#define FN_DATA_RW      (0x2u)              /* Sample data value on read and write */
#define FN_PC_DATA_WRITE (0xFu)             /* Sample PC and data value on write */
#define FN_PC_DATA_READ (0xEu)              /* Sample PC and data value on read */
#define FN_PC_DATA_RW   (0x3u)              /* Sample PC and data value on read and write */

enum Prot { PROT_OFLOW, PROT_ITM, PROT_UNKNOWN };
const char *protString[] = {"OFLOW", "ITM", NULL};

enum SetupStyle { SETUP_NONE, SETUP_GDB, SETUP_KEIL, SETUP_IAR, SETUP_C };
static const char *setupString[] = {"", "gdb", "keil", "iar", "c", NULL};

struct watch
{
    char *spec;                             /* As given on the command line */
    char name[128];                         /* Name for the output */
    uint32_t addr;                          /* Address of the variable */
    uint32_t size;                          /* 1, 2 or 4 bytes */
    char format;                            /* u, d, x or f */
    bool resolved;                          /* Address is known */

    /* Statistics */
    uint64_t count;
    double min, max, last;
    uint32_t lastPC;                        /* PC of the access, when the comparator sends it */
    bool havePC;
};

struct sample
{
    uint8_t comp;
    uint32_t data;
    uint32_t pc;
    bool havePC;
    bool isWrite;
    double hostTime;
};

/* ---------- CONFIGURATION ----------------- */
struct
{
    bool forceITMSync;
    uint32_t tag;
    char *elffile;
    char *outfile;
    char *file;
    bool endTerminate;
    uint32_t timelen;                       /* ms to record, 0 = until stopped */
    enum SetupStyle setup;
    bool withPC;
    char access;                            /* w, r or b(oth) */
    bool quiet;
    bool mono;

    struct watch w[MAX_WATCH];
    int nwatch;

    int port;
    char *server;
    enum Prot protocol;
} options =
{
    .forceITMSync = true,
    .tag = 1,
    .access = 'w',
    .port = OFCLIENT_SERVER_PORT,
    .server = "localhost"
};

/* ----------- LIVE STATE ----------------- */
struct
{
    struct ITMDecoder i;
    struct OFLOW c;
    volatile bool ending;

    FILE *out;
    uint64_t ticks;                         /* Target timestamp, accumulated */
    bool tsSeen;                            /* The target sends timestamps */
    struct sample pending[MAX_PENDING];
    int npending;
    uint32_t pcForComp[MAX_WATCH];          /* PC packet waiting for its data value */
    bool pcWaiting[MAX_WATCH];
    uint64_t samples;
    uint64_t unknownComp;
    double startTime;
} _r;

// ====================================================================================================
static double _now( void )

{
    struct timeval te;
    gettimeofday( &te, NULL );
    return te.tv_sec + te.tv_usec / 1e6;
}
// ====================================================================================================
static double _value( const struct watch *w, uint32_t data )

/* The value of a sample, by the format and size of its variable */

{
    switch ( w->format )
    {
        case 'f':
        {
            float f;
            memcpy( &f, &data, sizeof( f ) );
            return f;
        }

        case 'd':
            return ( w->size == 1 ) ? ( double )( int8_t )data : ( w->size == 2 ) ? ( double )( int16_t )data : ( double )( int32_t )data;

        default:
            return ( w->size == 1 ) ? ( double )( uint8_t )data : ( w->size == 2 ) ? ( double )( uint16_t )data : ( double )data;
    }
}
// ====================================================================================================
static void _writeSample( const struct sample *s )

{
    struct watch *w = &options.w[s->comp];
    char name[140];
    double v;

    if ( s->comp >= options.nwatch )
    {
        /* A comparator nobody named: still worth showing */
        snprintf( name, sizeof( name ), "comp%d", s->comp );
        _r.unknownComp++;
        v = s->data;
    }
    else
    {
        snprintf( name, sizeof( name ), "%s", w->name );
        v = _value( w, s->data );
        w->min = ( !w->count || v < w->min ) ? v : w->min;
        w->max = ( !w->count || v > w->max ) ? v : w->max;
        w->last = v;
        w->count++;

        if ( s->havePC )
        {
            w->lastPC = s->pc;
            w->havePC = true;
        }
    }

    _r.samples++;

    if ( !_r.out )
    {
        return;
    }

    fprintf( _r.out, "%.6f,", s->hostTime - _r.startTime );

    if ( _r.tsSeen )
    {
        fprintf( _r.out, "%" PRIu64, _r.ticks );
    }

    fprintf( _r.out, ",%s,", name );

    if ( ( s->comp < options.nwatch ) && ( w->format == 'x' ) )
    {
        fprintf( _r.out, "0x%0*" PRIx32, ( int )w->size * 2, s->data );
    }
    else if ( ( s->comp < options.nwatch ) && ( w->format == 'f' ) )
    {
        fprintf( _r.out, "%.9g", v );
    }
    else
    {
        fprintf( _r.out, "%.0f", v );
    }

    fprintf( _r.out, ",%c,", s->isWrite ? 'w' : 'r' );

    if ( s->havePC )
    {
        fprintf( _r.out, "0x%08" PRIx32, s->pc );
    }

    fprintf( _r.out, "\n" );
}
// ====================================================================================================
static void _flushPending( void )

{
    for ( int i = 0; i < _r.npending; i++ )
    {
        _writeSample( &_r.pending[i] );
    }

    _r.npending = 0;
}
// ====================================================================================================
static void _handleDataRWWP( struct watchMsg *m )

/* A data value. With timestamps on, the timestamp packet follows the packets it belongs to, */
/* so the sample waits for it.                                                                */

{
    struct sample s = { .comp = m->comp & 3, .data = m->data, .isWrite = m->isWrite, .hostTime = _now() };

    if ( _r.pcWaiting[s.comp] )
    {
        s.pc = _r.pcForComp[s.comp];
        s.havePC = true;
        _r.pcWaiting[s.comp] = false;
    }

    if ( !_r.tsSeen )
    {
        _writeSample( &s );
        return;
    }

    if ( _r.npending == MAX_PENDING )
    {
        _flushPending();
    }

    _r.pending[_r.npending++] = s;
}
// ====================================================================================================
static void _itmPumpProcess( uint8_t c )

{
    struct msg p;

    if ( ITM_EV_PACKET_RXED != ITMPump( &_r.i, c ) )
    {
        return;
    }

    if ( !ITMGetDecodedPacket( &_r.i, &p ) )
    {
        return;
    }

    switch ( p.genericMsg.msgtype )
    {
        case MSG_DATA_RWWP:
            _handleDataRWWP( ( struct watchMsg * )&p );
            break;

        case MSG_DATA_ACCESS_WP:
        {
            /* The PC of an access; its data value packet comes next */
            struct wptMsg *m = ( struct wptMsg * )&p;
            _r.pcForComp[m->comp & 3] = m->data;
            _r.pcWaiting[m->comp & 3] = true;
            break;
        }

        case MSG_TS:
            _r.ticks += ( ( struct TSMsg * )&p )->timeInc;
            _r.tsSeen = true;
            _flushPending();
            break;

        default:
            break;
    }
}
// ====================================================================================================
static void _OFLOWpacketRxed ( struct OFLOWFrame *p, void *param )

{
    if ( !p->good )
    {
        genericsReport( V_INFO, "Bad packet received" EOL );
    }
    else if ( p->tag == options.tag )
    {
        for ( int i = 0; i < p->len; i++ )
        {
            _itmPumpProcess( p->d[i] );
        }
    }
}
// ====================================================================================================
static bool _resolveWatches( void )

/* Fill in addresses and sizes: numbers as given, names from the symbol table of the ELF file */

{
    char line[2048];
    char cmd[2048];
    bool need = false;

    for ( int i = 0; i < options.nwatch; i++ )
    {
        struct watch *w = &options.w[i];
        char *end;
        uint32_t a = strtoul( w->name, &end, 0 );

        if ( ( end != w->name ) && ( !*end ) )
        {
            w->addr = a;
            w->resolved = true;
            w->size = w->size ? w->size : 4;
        }
        else
        {
            need = true;
        }
    }

    if ( !need )
    {
        return true;
    }

    if ( !options.elffile )
    {
        genericsReport( V_ERROR, "An ELF file (-e) is needed to find variables by name" EOL );
        return false;
    }

    snprintf( cmd, sizeof( cmd ), "%s -t \"%s\"", getenv( OBJENVNAME ) ? getenv( OBJENVNAME ) : OBJDUMP, options.elffile );
    FILE *f = popen( cmd, "r" );

    if ( !f )
    {
        genericsReport( V_ERROR, "No objdump found" EOL );
        return false;
    }

    /* Symbol table lines: address, flags, section, size, name */
    while ( fgets( line, sizeof( line ), f ) )
    {
        char *tok[16];
        int n = 0;

        for ( char *t = strtok( line, " \t\r\n" ); t && n < 16; t = strtok( NULL, " \t\r\n" ) )
        {
            tok[n++] = t;
        }

        if ( n < 4 )
        {
            continue;
        }

        for ( int i = 0; i < options.nwatch; i++ )
        {
            struct watch *w = &options.w[i];

            if ( ( !w->resolved ) && ( !strcmp( tok[n - 1], w->name ) ) )
            {
                uint32_t sz = strtoul( tok[n - 2], NULL, 16 );
                w->addr = strtoul( tok[0], NULL, 16 );
                w->resolved = true;

                if ( !w->size )
                {
                    w->size = ( ( sz == 1 ) || ( sz == 2 ) ) ? sz : 4;

                    if ( sz > 4 )
                    {
                        genericsReport( V_WARN, "%s is %u bytes: watching its first 4" EOL, w->name, sz );
                    }
                }
            }
        }
    }

    if ( pclose( f ) )
    {
        genericsReport( V_ERROR, "objdump failed on %s (is it on the PATH, or named by %s?)" EOL, options.elffile, OBJENVNAME );
        return false;
    }

    for ( int i = 0; i < options.nwatch; i++ )
    {
        if ( !options.w[i].resolved )
        {
            genericsReport( V_ERROR, "Variable %s not found in %s (only global and static variables have an address)" EOL,
                            options.w[i].name, options.elffile );
            return false;
        }
    }

    return true;
}
// ====================================================================================================
static bool _isIdentifier( const char *n )

/* A plain C name (not an address, not a name with a scope or a member) */

{
    if ( ( !isalpha( ( unsigned char )*n ) ) && ( *n != '_' ) )
    {
        return false;
    }

    for ( ; *n; n++ )
    {
        if ( ( !isalnum( ( unsigned char )*n ) ) && ( *n != '_' ) )
        {
            return false;
        }
    }

    return true;
}
// ====================================================================================================
static void _printSetup( void )

/* The register writes that make comparator n report accesses to watch n */

{
    uint32_t fn = options.withPC ? ( ( options.access == 'r' ) ? FN_PC_DATA_READ : ( options.access == 'b' ) ? FN_PC_DATA_RW : FN_PC_DATA_WRITE )
                  : ( ( options.access == 'r' ) ? FN_DATA_READ : ( options.access == 'b' ) ? FN_DATA_RW : FN_DATA_WRITE );
    const char *cmt = ( options.setup == SETUP_GDB ) ? "#" : "//";

    #define WR(addr, val, text) \
    switch ( options.setup ) \
    { \
        case SETUP_GDB:  printf( "set *(unsigned int *)0x%08X = 0x%08X", addr, val ); break; \
        case SETUP_KEIL: printf( "_WDWORD(0x%08X, 0x%08X);", addr, val ); break; \
        case SETUP_IAR:  printf( "__writeMemory32(0x%08X, 0x%08X, \"Memory\");", val, addr ); break; \
        default:         printf( "*(volatile unsigned int *)0x%08X = 0x%08X;", addr, val ); break; \
    } \
    printf( "   %s %s\n", cmt, text );

    #define OR(addr, val, text) \
    switch ( options.setup ) \
    { \
        case SETUP_GDB:  printf( "set *(unsigned int *)0x%08X |= 0x%08X", addr, val ); break; \
        case SETUP_KEIL: printf( "_WDWORD(0x%08X, _RDWORD(0x%08X) | 0x%08X);", addr, addr, val ); break; \
        case SETUP_IAR:  printf( "__writeMemory32(__readMemory32(0x%08X, \"Memory\") | 0x%08X, 0x%08X, \"Memory\");", addr, val, addr ); break; \
        default:         printf( "*(volatile unsigned int *)0x%08X |= 0x%08X;", addr, val ); break; \
    } \
    printf( "   %s %s\n", cmt, text );

    printf( "%s Data trace setup for orbdata (Cortex-M3/M4/M7). Run it after the trace port (SWO or\n", cmt );
    printf( "%s parallel trace) is on. Comparator n watches the n'th -w given to orbdata.\n", cmt );

    if ( options.setup == SETUP_C )
    {
        printf( "%s Variables given by name are written as &name, so the code stays right when the\n", cmt );
        printf( "%s firmware is rebuilt; put it where they are visible (a static one: in its own file).\n", cmt );
    }
    else
    {
        printf( "%s The addresses are from this build of the ELF file: print the setup again after a rebuild.\n", cmt );
    }

    OR( DEMCR, 0x01000000u, "DEMCR.TRCENA: DWT and ITM on" );
    WR( ITM_LAR, 0xC5ACCE55u, "unlock the ITM" );
    OR( ITM_TCR, 0x00000009u, "ITM enable, and pass DWT packets on (TXENA)" );

    for ( int i = 0; i < options.nwatch; i++ )
    {
        struct watch *w = &options.w[i];
        char text[200];
        uint32_t mask = ( w->size == 4 ) ? 2 : ( w->size == 2 ) ? 1 : 0;

        WR( DWT_FUNCTION( i ), 0u, "comparator off while it is changed" );
        snprintf( text, sizeof( text ), "comparator %d: address of %s", i, w->name );

        if ( ( options.setup == SETUP_C ) && _isIdentifier( w->name ) )
        {
            /* In firmware take the address from the linker: it can move at every build */
            printf( "*(volatile unsigned int *)0x%08X = (unsigned int)&%s & ~0x%Xu;   %s %s\n", DWT_COMP( i ), w->name, ( 1u << mask ) - 1, cmt, text );
        }
        else
        {
            WR( DWT_COMP( i ), w->addr & ~( ( 1u << mask ) - 1 ), text );
        }

        snprintf( text, sizeof( text ), "%u byte%s", w->size, ( w->size > 1 ) ? "s" : "" );
        WR( DWT_MASK( i ), mask, text );
        snprintf( text, sizeof( text ), "send the %svalue on %s", options.withPC ? "PC and the " : "",
                  ( options.access == 'r' ) ? "read" : ( options.access == 'b' ) ? "read and write" : "write" );
        WR( DWT_FUNCTION( i ), fn, text );
    }

    #undef WR
    #undef OR
}
// ====================================================================================================
void _printHelp( const char *const progName )

{
    genericsFPrintf( stderr, "Usage: %s [options]" EOL, progName );
    genericsFPrintf( stderr, "    -a, --access:       <w|r|b> for --setup: report writes (default), reads or both" EOL );
    genericsFPrintf( stderr, "    -e, --elf-file:     <ElfFile> to find variables by name" EOL );
    genericsFPrintf( stderr, "    -E, --eof:          Terminate when the file/socket ends/is closed" EOL );
    genericsFPrintf( stderr, "    -f, --input-file:   <filename> Take input from specified file" EOL );
    genericsFPrintf( stderr, "    -h, --help:         This help" EOL );
    genericsFPrintf( stderr, "    -l, --length:       <ms> Stop after this time (default: until CTRL-C)" EOL );
    genericsFPrintf( stderr, "    -M, --no-colour:    Supress colour in output" EOL );
    genericsFPrintf( stderr, "    -n, --itm-sync:     Enforce sync requirement for ITM (i.e. ITM needs to issue syncs)" EOL );
    genericsFPrintf( stderr, "    -o, --output-file:  <filename> CSV file for the samples (default: the screen)" EOL );
    genericsFPrintf( stderr, "    -p, --protocol:     Protocol to communicate. Defaults to OFLOW if -s is not set, otherwise ITM" EOL );
    genericsFPrintf( stderr, "    -P, --with-pc:      for --setup: also report the address of the code making the access" EOL );
    genericsFPrintf( stderr, "    -q, --quiet:        No samples on the screen, only the summary at the end" EOL );
    genericsFPrintf( stderr, "    -s, --server:       <Server>:<Port> to use" EOL );
    genericsFPrintf( stderr, "    -S, --setup:        <gdb|keil|iar|c> Print the target setup for the watched variables and exit" EOL );
    genericsFPrintf( stderr, "    -t, --tag:          <stream> Which Orbflow tag to use (normally 1)" EOL );
    genericsFPrintf( stderr, "    -v, --verbose:      <level> Verbose mode 0(errors)..3(debug)" EOL );
    genericsFPrintf( stderr, "    -V, --version:      Print version and exit" EOL );
    genericsFPrintf( stderr, "    -w, --watch:        <name|0xaddress>[,<u|d|x|f>[,<1|2|4>]] Variable for the next comparator" EOL );
    genericsFPrintf( stderr, "                        (up to %d), shown as unsigned, signed (d), hex or float, of 1, 2 or" EOL, MAX_WATCH );
    genericsFPrintf( stderr, "                        4 bytes (default: its size in the ELF file)" EOL );
    genericsFPrintf( stderr, EOL "Output: time_s,ticks,variable,value,access,pc   (ticks: target timestamps, if on)" EOL );
    genericsFPrintf( stderr, EOL "Environment Variables;" EOL );
    genericsFPrintf( stderr, "  OBJDUMP: to use non-standard objdump binary" EOL );
}
// ====================================================================================================
void _printVersion( void )

{
    genericsFPrintf( stderr, "orbdata version " GIT_DESCRIBE EOL );
}
// ====================================================================================================
static struct option _longOptions[] =
{
    {"access", required_argument, NULL, 'a'},
    {"elf-file", required_argument, NULL, 'e'},
    {"eof", no_argument, NULL, 'E'},
    {"input-file", required_argument, NULL, 'f'},
    {"help", no_argument, NULL, 'h'},
    {"length", required_argument, NULL, 'l'},
    {"no-colour", no_argument, NULL, 'M'},
    {"no-color", no_argument, NULL, 'M'},
    {"itm-sync", no_argument, NULL, 'n'},
    {"output-file", required_argument, NULL, 'o'},
    {"protocol", required_argument, NULL, 'p'},
    {"with-pc", no_argument, NULL, 'P'},
    {"quiet", no_argument, NULL, 'q'},
    {"server", required_argument, NULL, 's'},
    {"setup", required_argument, NULL, 'S'},
    {"tag", required_argument, NULL, 't'},
    {"verbose", required_argument, NULL, 'v'},
    {"version", no_argument, NULL, 'V'},
    {"watch", required_argument, NULL, 'w'},
    {NULL, no_argument, NULL, 0}
};
// ====================================================================================================
static bool _addWatch( char *spec )

{
    if ( options.nwatch == MAX_WATCH )
    {
        genericsReport( V_ERROR, "Only %d variables can be watched (one per DWT comparator)" EOL, MAX_WATCH );
        return false;
    }

    struct watch *w = &options.w[options.nwatch];
    char *c1 = strchr( spec, ',' );
    char *c2 = c1 ? strchr( c1 + 1, ',' ) : NULL;
    size_t nlen = c1 ? ( size_t )( c1 - spec ) : strlen( spec );

    if ( ( !nlen ) || ( nlen >= sizeof( w->name ) ) )
    {
        genericsReport( V_ERROR, "Bad -w %s" EOL, spec );
        return false;
    }

    memcpy( w->name, spec, nlen );
    w->name[nlen] = 0;
    w->spec = spec;
    w->format = ( c1 && c1[1] && c1[1] != ',' ) ? tolower( ( unsigned char )c1[1] ) : 'u';
    w->size = c2 ? strtoul( c2 + 1, NULL, 0 ) : 0;

    if ( !strchr( "udxf", w->format ) || ( ( w->size != 0 ) && ( w->size != 1 ) && ( w->size != 2 ) && ( w->size != 4 ) ) )
    {
        genericsReport( V_ERROR, "Bad -w %s: format is u, d, x or f and size 1, 2 or 4" EOL, spec );
        return false;
    }

    if ( w->format == 'f' )
    {
        w->size = 4;
    }

    options.nwatch++;
    return true;
}
// ====================================================================================================
bool _processOptions( int argc, char *argv[] )

{
    int c, optionIndex = 0;
    bool protExplicit = false;
    bool serverExplicit = false;
    bool portExplicit = false;

    while ( ( c = getopt_long ( argc, argv, "a:e:Ef:hl:Mno:p:Pqs:S:t:v:Vw:", _longOptions, &optionIndex ) ) != -1 )
        switch ( c )
        {
            case 'a':
                options.access = tolower( ( unsigned char ) * optarg );

                if ( !strchr( "wrb", options.access ) )
                {
                    genericsReport( V_ERROR, "-a takes w, r or b" EOL );
                    return false;
                }

                break;

            case 'e':
                options.elffile = optarg;
                break;

            case 'E':
                options.endTerminate = true;
                break;

            case 'f':
                options.file = optarg;
                break;

            case 'l':
                options.timelen = atoi( optarg );
                break;

            case 'M':
                options.mono = true;
                break;

            case 'n':
                options.forceITMSync = false;
                break;

            case 'o':
                options.outfile = optarg;
                break;

            case 'P':
                options.withPC = true;
                break;

            case 'q':
                options.quiet = true;
                break;

            case 'S':
                options.setup = SETUP_NONE;

                for ( int i = 1; setupString[i]; i++ )
                {
                    if ( !strcasecmp( setupString[i], optarg ) )
                    {
                        options.setup = i;
                    }
                }

                if ( options.setup == SETUP_NONE )
                {
                    genericsReport( V_ERROR, "--setup takes gdb, keil, iar or c" EOL );
                    return false;
                }

                break;

            case 't':
                options.tag = atoi( optarg );
                break;

            case 'v':
                if ( !isdigit( *optarg ) )
                {
                    genericsReport( V_ERROR, "-v requires a numeric argument." EOL );
                    return false;
                }

                genericsSetReportLevel( atoi( optarg ) );
                break;

            case 'w':
                if ( !_addWatch( optarg ) )
                {
                    return false;
                }

                break;

            case 'p':
                options.protocol = PROT_UNKNOWN;
                protExplicit = true;

                for ( int i = 0; protString[i]; i++ )
                {
                    if ( !strcmp( protString[i], optarg ) )
                    {
                        options.protocol = i;
                        break;
                    }
                }

                if ( options.protocol == PROT_UNKNOWN )
                {
                    genericsReport( V_ERROR, "Unrecognised protocol type" EOL );
                    return false;
                }

                break;

            case 's':
                options.server = optarg;
                serverExplicit = true;
                char *a = optarg;

                while ( ( *a ) && ( *a != ':' ) )
                {
                    a++;
                }

                if ( *a == ':' )
                {
                    *a = 0;
                    options.port = atoi( ++a );
                }

                if ( !options.port )
                {
                    options.port = NWCLIENT_SERVER_PORT;
                }
                else
                {
                    portExplicit = true;
                }

                break;

            case 'h':
                _printHelp( argv[0] );
                return false;

            case 'V':
                _printVersion();
                return false;

            default:
                return false;
        }

    if ( ( serverExplicit || options.file ) && !protExplicit )
    {
        options.protocol = PROT_ITM;
    }

    if ( ( options.protocol == PROT_ITM ) && !portExplicit )
    {
        options.port = NWCLIENT_SERVER_PORT;
    }

    if ( ( options.setup != SETUP_NONE ) && ( !options.nwatch ) )
    {
        genericsReport( V_ERROR, "--setup needs the variables to watch (-w)" EOL );
        return false;
    }

    return true;
}
// ====================================================================================================
static void _intHandler( int sig )

{
    _r.ending = true;
}
// ====================================================================================================
int main( int argc, char *argv[] )

{
    static uint8_t cbw[TRANSFER_SIZE];
    size_t receivedSize;
    struct Stream *stream = NULL;
    bool reported = false;
    struct timeval tv;

    if ( !_processOptions( argc, argv ) )
    {
        exit( -1 );
    }

    genericsScreenHandling( !options.mono );

    if ( !_resolveWatches() )
    {
        exit( -2 );
    }

    if ( options.setup != SETUP_NONE )
    {
        _printSetup();
        return 0;
    }

    for ( int i = 0; i < options.nwatch; i++ )
    {
        genericsReport( V_WARN, "Comparator %d: %s at 0x%08x, %u byte%s" EOL, i, options.w[i].name, options.w[i].addr,
                        options.w[i].size, ( options.w[i].size > 1 ) ? "s" : "" );
    }

    if ( options.outfile )
    {
        _r.out = fopen( options.outfile, "wb" );

        if ( !_r.out )
        {
            genericsExit( -2, "Could not open %s for writing" EOL, options.outfile );
        }
    }
    else if ( !options.quiet )
    {
        _r.out = stdout;
    }

    if ( _r.out )
    {
        fprintf( _r.out, "time_s,ticks,variable,value,access,pc\n" );
    }

    if ( SIG_ERR == signal( SIGINT, _intHandler ) )
    {
        genericsExit( -1, "Failed to establish Int handler" EOL );
    }

    ITMDecoderInit( &_r.i, options.forceITMSync );
    OFLOWInit( &_r.c );
    _r.startTime = _now();

    while ( !_r.ending )
    {
        stream = options.file ? streamCreateFile( options.file ) : streamCreateSocket( options.server, options.port );

        if ( !stream )
        {
            if ( !reported )
            {
                genericsReport( V_WARN, "No connection to %s:%d, waiting" EOL, options.server, options.port );
                reported = true;
            }

            usleep( 200000 );
            continue;
        }

        reported = false;

        while ( !_r.ending )
        {
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            receivedSize = 0;
            enum ReceiveResult result = stream->receive( stream, cbw, TRANSFER_SIZE, &tv, &receivedSize );

            if ( ( result == RECEIVE_RESULT_EOF ) || ( result == RECEIVE_RESULT_ERROR ) )
            {
                if ( ( options.endTerminate ) || ( options.file ) )
                {
                    _r.ending = true;
                }

                break;
            }

            if ( PROT_OFLOW == options.protocol )
            {
                OFLOWPump( &_r.c, cbw, receivedSize, _OFLOWpacketRxed, &_r );
            }
            else
            {
                for ( size_t i = 0; i < receivedSize; i++ )
                {
                    _itmPumpProcess( cbw[i] );
                }
            }

            if ( _r.out )
            {
                fflush( _r.out );
            }

            if ( ( options.timelen ) && ( ( _now() - _r.startTime ) * 1000.0 > options.timelen ) )
            {
                _r.ending = true;
            }
        }

        stream->close( stream );
        free( stream );

        if ( !_r.ending )
        {
            usleep( 200000 );
        }
    }

    _flushPending();

    if ( ( _r.out ) && ( _r.out != stdout ) )
    {
        fclose( _r.out );
    }

    /* Summary */
    genericsFPrintf( stderr, EOL "%" PRIu64 " samples in %.1f s%s" EOL, _r.samples, _now() - _r.startTime,
                     _r.tsSeen ? "" : " (no target timestamps: ITMTSEna is off)" );

    for ( int i = 0; i < options.nwatch; i++ )
    {
        struct watch *w = &options.w[i];

        if ( !w->count )
        {
            genericsFPrintf( stderr, "  %-24s no samples" EOL, w->name );
        }
        else
        {
            genericsFPrintf( stderr, "  %-24s %10" PRIu64 " samples  min %.9g  max %.9g  last %.9g" EOL, w->name, w->count, w->min, w->max, w->last );
        }
    }

    if ( _r.unknownComp )
    {
        genericsFPrintf( stderr, "  %" PRIu64 " samples came from comparators with no -w" EOL, _r.unknownComp );
    }

    if ( !_r.samples )
    {
        genericsFPrintf( stderr, "No data trace arrived. Check that the comparators are set up (orbdata --setup) and that" EOL
                         "the ITM passes DWT packets on (ITMTXEna 1, ITMEna 1)." EOL );
    }

    return 0;
}
// ====================================================================================================
