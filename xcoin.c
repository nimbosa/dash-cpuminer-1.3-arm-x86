#include "cpuminer-config.h"
#include "miner.h"


#include <string.h>
#include <stdint.h>

//--
#include "x5/luffa_for_sse2.h" //sse2 opt
//----
#include "x5/cubehash_sse2.h" //sse2 opt
//-----simd vect128---------
#include "x5/vect128/nist.h"
//-----------
#include "x11/sph_blake.h"
#include "x11/sph_bmw.h"
#include "x11/sph_groestl.h"
#include "x11/sph_jh.h"
#include "x11/sph_keccak.h"
#include "x11/sph_skein.h"
#include "x11/sph_luffa.h"
#include "x11/sph_cubehash.h"
#include "x11/sph_shavite.h"
#include "x11/sph_simd.h"
#include "x11/sph_echo.h"

#define AES_NI
#define AES_NI_GR

#ifdef AES_NI
#include "x5/echo512/ccalik/aesni/hash_api.h"
#else
#include "x5/sph_echo.h"
#endif


//----
#include "x6/blake.c"
//#include "x5/blake/sse41/hash.c"
#include "x6/bmw.c"
#include "x6/keccak.c"
#include "x6/skein.c"
#include "x6/jh_sse2_opt64.h"
//#include "groestl.c"
#ifdef AES_NI_GR
#include "x6/groestl/aesni/hash-groestl.h"
#else
#if 1
#include "x6/grso.c"
#ifndef PROFILERUN
#include "x6/grso-asm.c"
#endif
#else
#include "x6/grss_api.h"
#endif
#endif  //AES-NI_GR

/*define data alignment for different C compilers*/
#if defined(__GNUC__)
#define DATA_ALIGNXY(x,y) x __attribute__ ((aligned(y)))
#else
#define DATA_ALIGNXY(x,y) __declspec(align(y)) x
#endif

#ifdef AES_NI
#ifdef AES_NI_GR
typedef struct {
	sph_shavite512_context  shavite1;
	hashState_echo		echo1;
	hashState_groestl groestl;
	hashState_luffa luffa;
	cubehashParam cubehash;
	hashState_sd ctx_simd1;
//	hashState_blake	blake1;
} Xhash_context_holder;
#else
typedef struct{
	sph_shavite512_context shavite1;
	hashState_echo	echo1;
	hashState_luffa	luffa;
	cubehashParam cubehash;
	hashState_sd ctx_simd1;
} Xhash_context_holder;
#endif
#else
typedef struct {
	sph_shavite512_context  shavite1;
	sph_echo512_context		echo1;
	hashState_luffa	luffa;
	cubehashParam	cubehash;
	hashState_sd ctx_simd1;
	hashState_groestl groestl;
//	hashState_blake	blake1;
} Xhash_context_holder;
#endif

Xhash_context_holder base_contexts;


void init_Xhash_contexts(){

	//---luffa---
	init_luffa(&base_contexts.luffa,512);
	//--ch sse2---
	cubehashInit(&base_contexts.cubehash,512,16,32);
	//-------
	sph_shavite512_init(&base_contexts.shavite1);
	//---echo sphlib or AESNI-----------
	#ifdef AES_NI
  	init_echo(&base_contexts.echo1, 512);
	#else
	sph_echo512_init(&base_contexts.echo1);
	#endif
	//---local simd var ---
	init_sd(&base_contexts.ctx_simd1,512);
}

inline void Xhash(void *state, const void *input)
{
    Xhash_context_holder ctx;
    
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    sph_luffa512_context     ctx_luffa;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    static unsigned char pblank[1];

    uint32_t hashA[16], hashB[16];

	memcpy(&ctx, &base_contexts, sizeof(base_contexts));
	#ifdef AES_NI_GR
	init_groestl(&ctx.groestl);
	#endif

	DATA_ALIGNXY(unsigned char hashbuf[128],16);
	size_t hashptr;
	DATA_ALIGNXY(sph_u64 hashctA,8);
	DATA_ALIGNXY(sph_u64 hashctB,8);

	#ifndef AES_NI_GR
	grsoState sts_grs;
	#endif


	DATA_ALIGNXY(unsigned char hash[128],16);
	/* proably not needed */
	memset(hash, 0, 128);
	//blake1-bmw2-grs3-skein4-jh5-keccak6-luffa7-cubehash8-shavite9-simd10-echo11
	//---blake1---
/*	  //blake init
	blake512_init(&base_contexts.blake1, 512);
	blake512_update(&ctx.blake1, input, 512);
	blake512_final(&ctx.blake1, hash);
*/
	DECL_BLK;
	BLK_I;
	BLK_W;
	BLK_C;

	//---bmw2---
	DECL_BMW;
	BMW_I;
	BMW_U;
	#define M(x)    sph_dec64le_aligned(data + 8 * (x))
	#define H(x)    (h[x])
	#define dH(x)   (dh[x])
        BMW_C;
	#undef M
	#undef H
	#undef dH
	//---grs3----

	#ifdef AES_NI_GR
	update_groestl(&ctx.groestl, (char*)hash,512);
	final_groestl(&ctx.groestl, (char*)hash);
	#else
	GRS_I;
	GRS_U;
	GRS_C;
	#endif
	//---skein4---
	DECL_SKN;
	SKN_I;
	SKN_U;
	SKN_C;
	//---jh5------
	DECL_JH;
	JH_H;
	//---keccak6---
	DECL_KEC;
	KEC_I;
	KEC_U;
	KEC_C;

//	asm volatile ("emms");
	//--- luffa7
	update_luffa(&ctx.luffa,(const BitSequence*)hash,512);
	final_luffa(&ctx.luffa,(BitSequence*)hash+64);
	//---cubehash---
	cubehashUpdate(&ctx.cubehash,(const byte*) hash+64,64);
	cubehashDigest(&ctx.cubehash,(byte*)hash);
	//---shavite---
	sph_shavite512 (&ctx.shavite1, hash, 64);
	sph_shavite512_close(&ctx.shavite1, hash+64);
	//sph_simd512 (&ctx.simd1, hashA, 64);
	// sph_simd512_close(&ctx.simd1, hashB);
	//-------simd512 vect128 --------------
	update_sd(&ctx.ctx_simd1,(const BitSequence *)hash+64,512);
	final_sd(&ctx.ctx_simd1,(BitSequence *)hash);
	//---echo---
	#ifdef AES_NI
	update_echo (&ctx.echo1,(const BitSequence *) hash, 512);
	final_echo(&ctx.echo1, (BitSequence *) hash+64);
	#else
	sph_echo512 (&ctx.echo1, hash, 64);
	sph_echo512_close(&ctx.echo1, hash+64);
	#endif

	memcpy(state, hash+64, 32);
}


void Hash9(void *output, const void *input)
{
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    sph_luffa512_context     ctx_luffa;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    static unsigned char pblank[1];


    uint32_t hashA[16], hashB[16];

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, 80);
    sph_blake512_close(&ctx_blake, hashA);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashB, 64);
    sph_groestl512_close(&ctx_groestl, hashA);

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, hashA, 64);
    sph_skein512_close(&ctx_skein, hashB);

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashB, 64);
    sph_jh512_close(&ctx_jh, hashA);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashA, 64);
    sph_keccak512_close(&ctx_keccak, hashB);

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, hashB, 64);
    sph_luffa512_close(&ctx_luffa, hashA);

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512 (&ctx_cubehash, hashA, 64);
    sph_cubehash512_close(&ctx_cubehash, hashB);

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hashB, 64);
    sph_shavite512_close(&ctx_shavite, hashA);

    sph_simd512_init(&ctx_simd);
    sph_simd512 (&ctx_simd, hashA, 64);
    sph_simd512_close(&ctx_simd, hashB);

    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo, hashB, 64);
    sph_echo512_close(&ctx_echo, hashA);

//    for (int kk = 0; kk < 8; kk++)
//    {
//            be32enc(&((uint32_t*)output)[kk], ((uint32_t*)hashA)[kk]);
//    };
    memcpy(output, hashA, 32);

}

int scanhash_X(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t n = pdata[19] - 1;
        const uint32_t first_nonce = pdata[19];
        const uint32_t Htarg = ptarget[7];

	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t hash64[8] __attribute__((aligned(32)));
        uint32_t endiandata[32];


	int kk=0;

	#pragma unroll
	for (; kk < 32; kk++){
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};
        if (ptarget[7]==0) {
                do { //1
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        Hash9(hash64, &endiandata);
                        if (((hash64[7]&0xFFFFFFFF)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);        
        }
        else if (ptarget[7]<=0xF)
        {
    		do { //2
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        Hash9(hash64, &endiandata);
                        if (((hash64[7]&0xFFFFFFF0)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);        
        }
        else if (ptarget[7]<=0xFF)
        {
                do { //3
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        Hash9(hash64, &endiandata);
                        if (((hash64[7]&0xFFFFFF00)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);        
        }
        else if (ptarget[7]<=0xFFF)
        {
                do { //4
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        Hash9(hash64, &endiandata);
                        if (((hash64[7]&0xFFFFF000)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);        

        }
        else if (ptarget[7]<=0xFFFF)
        {
                do { //5
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        Hash9(hash64, &endiandata);
                        if (((hash64[7]&0xFFFF0000)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return 1;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);        

        }
        else
        {
                do {
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        Hash9(hash64, &endiandata);
                        if (fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);        
        }
        
        
        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}
