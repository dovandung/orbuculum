/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * External file format writing module for Orbuculum
 * =================================================
 *
 */

#include <stdio.h>
#include "ext_fileformats.h"

#define HANDLE_MASK         (0xFFFFFF)   /* cachegrind cannot cope with large file handle numbers */

// ====================================================================================================
// ====================================================================================================
// ====================================================================================================
// Internally available routines
// ====================================================================================================
// ====================================================================================================
// ====================================================================================================
static const char *_path( const char *prefix, const char *name )

/* prefix+name with '/' separators: KCachegrind splits object and source paths at '/' only, */
/* so with Windows '\' it can't find the ELF file for the machine code view                 */

{
    static char p[1024];

    snprintf( p, sizeof( p ), "%s%s", prefix ? prefix : "", name );

    for ( char *q = p; *q; q++ )
    {
        if ( *q == '\\' )
        {
            *q = '/';
        }
    }

    return p;
}
// ====================================================================================================
static void _costs( FILE *c, bool includeVisits, bool includeCycles, uint64_t inst, uint64_t visits, uint64_t cycles )

/* Finish a cost line with the costs of the events in the profile, in 'events:' order */

{
    fprintf( c, "%" PRIu64, inst );

    if ( includeVisits )
    {
        fprintf( c, " %" PRIu64, visits );
    }

    if ( includeCycles )
    {
        fprintf( c, " %" PRIu64, cycles );
    }

    fprintf( c, "\n" );
}
// ====================================================================================================
static int _inst_sort_fn( const void *a, const void *b )

/* Sort instructions by address */

{
    uint32_t aa = ( ( struct execEntryHash * )a )->addr;
    uint32_t ba = ( ( struct execEntryHash * )b )->addr;

    /* Unsigned compare: a difference cast to int puts addresses from 0x80000000 up first */
    return ( aa > ba ) - ( aa < ba );
}
// ====================================================================================================
static int _calls_src_sort_fn( const void *a, const void *b )

/* Sort instructions by called from address */

{
    int i;

    if ( ( i = ( int )( ( ( struct subcall * )a )->srch->functionindex ) - ( int )( ( ( struct subcall * )b )->srch->functionindex ) ) )
    {
        return i;
    }

    return ( int )( ( ( struct subcall * )a )->dsth->functionindex ) - ( int )( ( ( struct subcall * )b )->dsth->functionindex );
}
// ====================================================================================================
#if 0 // Not used for now, but left here in case its useful later...
static int _calls_dst_sort_fn( const void *a, const void *b )

/* Sort instructions by called to address */

{
    int i;

    if ( ( i = ( int )( ( ( struct subcall * )a )->dsth->functionindex ) - ( int )( ( ( struct subcall * )b )->dsth->functionindex ) ) )
    {
        return i;
    }

    return ( int )( ( ( struct subcall * )a )->srch->functionindex ) - ( int )( ( ( struct subcall * )b )->srch->functionindex );
}
#endif
// ====================================================================================================
// ====================================================================================================
// ====================================================================================================
// Externally available routines
// ====================================================================================================
// ====================================================================================================
// ====================================================================================================

// ====================================================================================================
// ====================================================================================================
// Dot support
// ====================================================================================================
// ====================================================================================================
bool ext_ff_outputDot( char *dotfile, struct subcall *subcallList, struct SymbolSet *ss )

/* Output call graph to dot file */

{
    FILE *c;
    uint32_t functionidx, dfunctionidx, fileidx, dfileidx;
    uint64_t cnt;
    struct subcall *s;

    if ( !dotfile )
    {
        return false;
    }

    if ( !subcallList )
    {
        return false;
    }

    /* Sort according to addresses visited. */

    c = fopen( dotfile, "w" );

    if ( !c )
    {
        return false;
    }
    /* Directed, so each edge points from the caller to the callee */
    fprintf( c, "digraph calls\n{\n  overlap=true; splines=true; size=\"7.75,10.25\"; orientation=portrait; sep=0.1; nodesep=1;\n" );

    /* An earlier sort (e.g. by the other writer) may have left the caller's head pointer in */
    /* the middle of the list, and sorting from there would drop the elements before it.     */
    while ( subcallList->hh.prev )
    {
        subcallList = subcallList->hh.prev;
    }

    HASH_SORT( subcallList, _calls_src_sort_fn );
    s = subcallList;

    /* Now go through and label the arrows... */

    s = subcallList;

    while ( s )
    {
        functionidx = s->srch->functionindex;
        fileidx = s->srch->fileindex;

        dfunctionidx = s->dsth->functionindex;
        dfileidx = s->dsth->fileindex;
        cnt = s->count;
        s = s->hh.next;

        while ( ( s ) && ( functionidx == s->srch->functionindex ) && ( dfunctionidx == s->dsth->functionindex ) )
        {
            cnt += s->count;
            s = s->hh.next;
        }

        /* Each end in its own file; '/' separators, since dot takes '\' as an escape */
        fprintf( c, "    \"\n(%s)\n%s\n\n\" -> ", _path( NULL, SymbolFilename( ss, fileidx ) ), SymbolFunction( ss, functionidx ) );
        fprintf( c, "\"\n(%s)\n%s\n\n\" [label=%" PRIu64 ", weight=0.1 ];\n", _path( NULL, SymbolFilename( ss, dfileidx ) ), SymbolFunction( ss, dfunctionidx ), cnt );
    }

    fprintf( c, "}\n" );
    fclose( c );
    return true;
}
// ====================================================================================================
// ====================================================================================================
// KCacheGrind support
// ====================================================================================================
// ====================================================================================================
bool ext_ff_outputProfile( char *profile, char *elffile, char *deleteMaterial, bool includeVisits, uint64_t timelen,
                           struct execEntryHash *insthead, struct subcall *subcallList, struct SymbolSet *ss )

/* Output a KCacheGrind compatible profile, with instruction coverage in insthead, calls in subcallList */

{
    struct nameEntry n;
    uint32_t prevfile = NO_FILE;
    uint32_t prevfn   = NO_FUNCTION;
    uint32_t prevaddr = NO_FUNCTION;
    uint32_t prevline = NO_LINE;
    char *e = elffile;
    char *d = deleteMaterial;
    FILE *c;

    if ( !profile )
    {
        return false;
    }

    c = fopen( profile, "w" );

    if ( !c )
    {
        return false;
    }
    /* The summary is the total of each event. Placeholder records (unknown or interrupt */
    /* positions) aren't executed code, so they are left out here and below.             */
    uint64_t totalInst = 0;
    uint64_t totalVisits = 0;
    uint64_t totalCycles = 0;

    /* A sort elsewhere may have left the head pointers we were given mid-list: find the real heads */
    while ( ( insthead ) && ( insthead->hh.prev ) )
    {
        insthead = insthead->hh.prev;
    }

    for ( struct execEntryHash *t = insthead; t; t = t->hh.next )
    {
        if ( ( t->addr & SPECIALS_MASK ) != SPECIALS_MASK )
        {
            totalInst   += t->count;
            totalVisits += t->scount;
            totalCycles += t->cycles;
        }
    }

    /* Cycles are only known from a cycle accurate trace */
    bool includeCycles = ( totalCycles != 0 );

    fprintf( c, "# callgrind format\n" );
    fprintf( c, "creator: orbprofile\npositions: instr line\nevent: Inst : CPU Instructions\n" );

    if ( includeVisits )
    {
        fprintf( c, "event: Visits : Visits to source line\n" );
    }

    if ( includeCycles )
    {
        fprintf( c, "event: Cycles : CPU Cycles\n" );
    }

    fprintf( c, "events: Inst%s%s\n", includeVisits ? " Visits" : "", includeCycles ? " Cycles" : "" );
    fprintf( c, "# trace length: %" PRIu64 "\n", timelen );
    fprintf( c, "summary: " );
    _costs( c, includeVisits, includeCycles, totalInst, totalVisits, totalCycles );

    /* Try to remove frontmatter off the elfile if nessessary and possible */
    if ( deleteMaterial )
    {
        while ( ( *d ) && ( *d == *e ) )
        {
            d++;
            e++;
        }

        if ( e - elffile != strlen( deleteMaterial ) )
        {
            /* Strings don't match, give up and use the file elffile name */
            e = elffile;
        }
    }

    /* ...and record whatever elffilename we ended up with */
    fprintf( c, "ob=%s\n", _path( NULL, e ) );

    HASH_SORT( insthead, _inst_sort_fn );
    struct execEntryHash *f = insthead;

    while ( f )
    {
        if ( ( f->addr & SPECIALS_MASK ) == SPECIALS_MASK )
        {
            f = f->hh.next;
            continue;
        }

        SymbolLookup( ss, f->addr, &n );

        if ( prevfile != n.fileindex )
        {
            fprintf( c, "fl=(%u) %s\n", n.fileindex & HANDLE_MASK, _path( deleteMaterial, SymbolFilename( ss, n.fileindex ) ) );
        }

        if ( prevfn != n.functionindex )
        {
            fprintf( c, "fn=(%u) %s\n", n.functionindex & HANDLE_MASK, SymbolFunction( ss, n.functionindex ) );

            /* Start each function with an absolute position */
            prevline = NO_LINE;
        }

        if ( ( prevline == NO_LINE ) || ( prevaddr == NO_FUNCTION ) )
        {
            fprintf( c, "0x%08x %d ", f->addr, n.line );
        }
        else
        {
            if ( prevaddr == f->addr )
            {
                fprintf( c, "* " );
            }
            else
            {
                fprintf( c, "%s%d ", f->addr > prevaddr ? "+" : "", ( int )f->addr - prevaddr );
            }

            if ( prevline == n.line )
            {
                fprintf( c, "* " );
            }
            else
            {
                fprintf( c, "%s%d ", n.line > prevline ? "+" : "", ( int )n.line - prevline );
            }
        }

        _costs( c, includeVisits, includeCycles, f->count, f->scount, f->cycles );


        prevline = n.line;
        prevaddr = f->addr;
        prevfile = n.fileindex;
        prevfn = n.functionindex;
        f = f->hh.next;
    }

    fprintf( c, "\n\n## ------------------- Calls Follow ------------------------\n" );
    while ( ( subcallList ) && ( subcallList->hh.prev ) )
    {
        subcallList = subcallList->hh.prev;
    }

    HASH_SORT( subcallList, _calls_src_sort_fn );
    struct subcall *s = subcallList;

    while ( s )
    {
        /* Now publish the call destination. By definition is is known, so can be shortformed */
        if ( prevfile != s->srch->fileindex )
        {
            fprintf( c, "fl=(%u) %s\n", s->srch->fileindex & HANDLE_MASK, _path( deleteMaterial, SymbolFilename( ss, s->srch->fileindex ) ) );
            prevfile = s->srch->fileindex;
        }

        if ( prevfn != s->srch->functionindex )
        {
            fprintf( c, "fn=(%u) %s\n", s->srch->functionindex & HANDLE_MASK, SymbolFunction( ss, s->srch->functionindex ) );
            prevfn = s->srch->functionindex;
        }

        /* Same (masked) ids as fl= and fn=, named, since the callee may not have run any code */
        fprintf( c, "cfl=(%u) %s\n", s->dsth->fileindex & HANDLE_MASK, _path( deleteMaterial, SymbolFilename( ss, s->dsth->fileindex ) ) );
        fprintf( c, "cfn=(%u) %s\n", s->dsth->functionindex & HANDLE_MASK, SymbolFunction( ss, s->dsth->functionindex ) );
        fprintf( c, "calls=%" PRIu64 " 0x%08x %d\n", s->count, s->sig.dst, s->dsth->line );

        /* The cost after calls= is the inclusive cost of those calls */
        fprintf( c, "0x%08x %d ", s->sig.src, s->srch->line );
        _costs( c, includeVisits, includeCycles, s->myCost, s->myVisits, s->myCycles );

        s = s->hh.next;
    }

    fclose( c );

    return true;
}
// ====================================================================================================
