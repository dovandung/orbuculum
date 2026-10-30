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
    uint32_t functionidx, dfunctionidx, fileidx;
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
    fprintf( c, "graph calls\n{\n  overlap=true; splines=true; size=\"7.75,10.25\"; orientation=portrait; sep=0.1; nodesep=1;\n" );

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
        cnt = s->count;
        s = s->hh.next;

        while ( ( s ) && ( functionidx == s->srch->functionindex ) && ( dfunctionidx == s->dsth->functionindex ) )
        {
            cnt += s->count;
            s = s->hh.next;
        }

        fprintf( c, "    \"\n(%s)\n%s\n\n\" -- ", SymbolFilename( ss, fileidx ), SymbolFunction( ss, functionidx ) );
        fprintf( c, "\"\n(%s)\n%s\n\n\" [label=%" PRIu64 ", weight=0.1 ];\n", SymbolFilename( ss, fileidx ), SymbolFunction( ss, dfunctionidx ), cnt );
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
    fprintf( c, "# callgrind format\n" );

    if ( includeVisits )
    {
        fprintf( c, "creator: orbprofile\npositions: instr line\nevent: Inst : CPU Instructions\nevent: Visits : Visits to source line\nevents: Inst Visits\n" );
    }
    else
    {
        fprintf( c, "creator: orbprofile\npositions: instr line\nevent: Inst : CPU Instructions\nevents: Inst\n" );
    }

    /* The summary is the total of each event. Placeholder records (unknown or interrupt */
    /* positions) aren't executed code, so they are left out here and below.             */
    uint64_t totalInst = 0;
    uint64_t totalVisits = 0;

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
        }
    }

    fprintf( c, "# trace length: %" PRIu64 "\n", timelen );

    if ( includeVisits )
    {
        fprintf( c, "summary: %" PRIu64 " %" PRIu64 "\n", totalInst, totalVisits );
    }
    else
    {
        fprintf( c, "summary: %" PRIu64 "\n", totalInst );
    }

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

        if ( includeVisits )
        {
            fprintf( c, "%" PRIu64 " %" PRIu64 "\n", f->count, f->scount );
        }
        else
        {
            fprintf( c, "%" PRIu64 "\n", f->count );
        }


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
        if ( includeVisits )
        {
            fprintf( c, "0x%08x %d %" PRIu64 " %" PRIu64 "\n", s->sig.src, s->srch->line, s->myCost, s->myVisits );
        }
        else
        {
            fprintf( c, "0x%08x %d %" PRIu64 "\n", s->sig.src, s->srch->line, s->myCost );
        }

        s = s->hh.next;
    }

    fclose( c );

    return true;
}
// ====================================================================================================
