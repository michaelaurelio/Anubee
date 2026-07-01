// SPDX-License-Identifier: GPL-2.0
// Host unit test for the switch-interpreter ShadowFrame walk (shadow_frame_pick).
// Builds a synthetic Thread -> ManagedStack -> ShadowFrame chain over sample.dex and
// asserts corroborated methods are named innermost-first and a bad dex_pc is dropped.
#include "common/art_shadow.h"
#include "common/art_buildid.h"
#include "common/art_nterp.h"
#include "common/dex.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks = 0, failures = 0;
#define CHECK(c,m) do{checks++; if(!(c)){failures++; printf("  FAIL: %s\n",m);} }while(0)

struct region { uint64_t base; const uint8_t *data; size_t len; };
struct mem { struct region r[16]; int n; };
static size_t memrd(void *ctx, uint64_t va, void *dst, size_t len){
    struct mem *m=ctx;
    for(int i=0;i<m->n;i++){ struct region*r=&m->r[i];
        if(va>=r->base && va+len<=r->base+r->len){ memcpy(dst,r->data+(va-r->base),len); return len; } }
    return 0;
}
static void add(struct mem*m,uint64_t b,const uint8_t*d,size_t l){ m->r[m->n].base=b; m->r[m->n].data=d; m->r[m->n].len=l; m->n++; }
static void w32(uint8_t*p,uint32_t v){memcpy(p,&v,4);} static void w64(uint8_t*p,uint64_t v){memcpy(p,&v,8);}
static uint8_t* slurp(const char*p,size_t*l){FILE*f=fopen(p,"rb"); if(!f){perror(p);exit(2);} fseek(f,0,SEEK_END);long n=ftell(f);fseek(f,0,SEEK_SET); uint8_t*b=malloc((size_t)n); if(fread(b,1,(size_t)n,f)!=(size_t)n)exit(2); fclose(f);*l=(size_t)n;return b;}

// ArtMethod / mirror offsets — mirror art_nterp.c's version table (same as test_art_nterp).
#define O_DECL 0x00
#define O_MIDX 0x08
#define O_CLASS_DC 0x10
#define O_DC_DF 0x10
#define O_DF_BEGIN 0x08
#define O_DF_SIZE 0x20

int main(int argc,char**argv){
    const char*path=argc>1?argv[1]:"tests/fixtures/sample.dex";
    size_t dexlen; uint8_t*dex=slurp(path,&dexlen);
    struct dex_method_map*map=dex_map_build(dex,dexlen);
    if(!map){fprintf(stderr,"map build failed\n");return 2;}
    // pick a real method index + its insns offset so dex_pc_ptr_ lands in-range.
    uint32_t midx=0, insns=0;
    { // find any method whose code_item range is known
      char nb[256];
      for(uint32_t i=0;i<4096;i++){ if(dex_name_by_index(map,i,nb,sizeof nb)==1){ midx=i; break; } }
      uint32_t rmi, rin;
      // locate the code_item offset for midx by scanning the range table
      for(uint32_t off=0; off<(uint32_t)dexlen; off++){ if(dex_lookup_range(map,off,&rmi,&rin)&&rmi==midx){ insns=rin; break; } }
    }
    char mname[256]; dex_name_by_index(map,midx,mname,sizeof mname);

    // Addresses for the synthetic image.
    const uint64_t DEX_BASE=0x40000000ULL;              // dex image
    const uint64_t DC=0x50000000ULL, DF=0x50001000ULL;  // DexCache, DexFile
    const uint64_t ARTM=0x60000000ULL;                  // ArtMethod
    const uint64_t SF1=0x70000000ULL, SF0=0x70001000ULL;// ShadowFrames (SF0 innermost)
    const uint64_t MS=0x71000000ULL;                    // ManagedStack
    const uint64_t THREAD=0x72000000ULL;
    const uint64_t TLS=0x73000000ULL;

    static uint8_t artm[0x40], dcbuf[0x40], dfbuf[0x40];
    static uint8_t sf0[0x40], sf1[0x40], ms[0x40], thr[0x100], tls[0x100];
    w32(artm+O_DECL, 0x00abc000);           // declaring_class compressed ref (points to CLASS)
    w32(artm+O_MIDX, midx);
    const uint64_t CLASS=0x00abc000ULL;
    static uint8_t clsbuf[0x40];
    w32(clsbuf+O_CLASS_DC, (uint32_t)DC);   // dex_cache compressed ref
    w64(dcbuf+O_DC_DF, DF);
    w64(dfbuf+O_DF_BEGIN, DEX_BASE);
    w64(dfbuf+O_DF_SIZE, dexlen);

    // ShadowFrame SF0 (innermost): link_ -> SF1, method_ -> ARTM, dex_pc_ptr_ in-range
    w64(sf0+0x00, SF1);
    w64(sf0+0x08, ARTM);
    w64(sf0+0x18, DEX_BASE + insns);        // dex_pc_ptr_: method start (dex_pc 0, always in-range)
    w64(sf0+0x20, DEX_BASE + insns);        // dex_instructions_
    // ShadowFrame SF1 (outer): link_ -> 0, method_ -> ARTM, dex_pc_ptr_ OUT of range (drop)
    w64(sf1+0x00, 0);
    w64(sf1+0x08, ARTM);
    w64(sf1+0x18, DEX_BASE + (uint64_t)dexlen + 0x1000); // beyond image -> no corroboration
    w64(sf1+0x20, DEX_BASE);
    // ManagedStack: link_=0, top_shadow_frame_=SF0
    w64(ms+0x08, 0);
    w64(ms+0x10, SF0);
    // Thread: managed_stack embedded at +0xA8
    w64(thr+0xA8, 0);        // ms.link_ (embedded copy start) — see note
    // We place the embedded ManagedStack AT Thread+0xA8, so map MS region there instead:
    w64(tls+0x38, THREAD);   // TLS slot 7 -> Thread*

    struct mem m={0};
    add(&m, DEX_BASE, dex, dexlen);
    add(&m, DC, dcbuf, sizeof dcbuf);
    add(&m, DF, dfbuf, sizeof dfbuf);
    add(&m, CLASS, clsbuf, sizeof clsbuf);
    add(&m, ARTM, artm, sizeof artm);
    add(&m, SF0, sf0, sizeof sf0);
    add(&m, SF1, sf1, sizeof sf1);
    add(&m, THREAD + 0xA8, ms, sizeof ms);   // embedded ManagedStack lives at Thread+0xA8
    add(&m, TLS, tls, sizeof tls);

    struct art_offsets o = { .tls_thread_slot=0x38, .managed_stack=0xA8, .ms_link=0x08,
        .ms_top_shadow=0x10, .sf_link=0x00, .sf_method=0x08, .sf_dex_pc_ptr=0x18, .sf_dex_instr=0x20 };

    char out[8][256];
    int n = shadow_frame_pick(memrd, &m, TLS, &o, out, 8);
    CHECK(n == 1, "one corroborated frame (bad dex_pc dropped)");
    if (n >= 1) {
        char want[300]; snprintf(want, sizeof want, "%s+0x0", mname);
        CHECK(strcmp(out[0], want) == 0, "innermost frame named with dex_pc suffix");
    }
    // gate: tls_base 0 -> nothing
    CHECK(shadow_frame_pick(memrd, &m, 0, &o, out, 8) == 0, "tls_base 0 -> 0 frames");

    dex_map_free(map); free(dex);
    printf("test_art_shadow: %s (%d checks, %d failures)\n", failures?"FAIL":"ok", checks, failures);
    return failures ? 1 : 0;
}
