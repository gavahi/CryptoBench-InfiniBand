/* -*- Mode: C; c-basic-offset:4 ; indent-tabs-mode:nil ; -*- */
/*
 *
 *  (C) 2001 by Argonne National Laboratory.
 *      See COPYRIGHT in top-level directory.
 */

/* Copyright (c) 2001-2018, The Ohio State University. All rights
 * reserved.
 *
 * This file is part of the MVAPICH2 software package developed by the
 * team members of The Ohio State University's Network-Based Computing
 * Laboratory (NBCL), headed by Professor Dhabaleswar K. (DK) Panda.
 *
 * For detailed copyright and licensing information, please refer to the
 * copyright file COPYRIGHT in the top level MVAPICH2 directory.
 *
 */

#include "mpiimpl.h"

unsigned int outlen_enc;
EVP_CIPHER_CTX *ctx_enc;
int nonceCounter=0,amount,sct_sz,pre_next;
//pre_start: Enc start counter; pre_end: pre-calculation end counter
int pre_start[1024], pre_end[1024], first_flag[1024];
const unsigned char gcm_key[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
unsigned char send_ciphertext[4194304+400], p[8020], IV[1024][16], enc_iv[1024][16], pre_calculator[1024][8000];
int iv_counter[1024];

/* -- Begin Profiling Symbol Block for routine MPI_Send */
#if defined(HAVE_PRAGMA_WEAK)
#pragma weak MPI_Send = PMPI_Send
#elif defined(HAVE_PRAGMA_HP_SEC_DEF)
#pragma _HP_SECONDARY_DEF PMPI_Send  MPI_Send
#elif defined(HAVE_PRAGMA_CRI_DUP)
#pragma _CRI duplicate MPI_Send as PMPI_Send
#elif defined(HAVE_WEAK_ATTRIBUTE)
int MPI_Send(const void *buf, int count, MPI_Datatype datatype, int dest, int tag,
             MPI_Comm comm) __attribute__((weak,alias("PMPI_Send")));
#endif
/* -- End Profiling Symbol Block */

/* Define MPICH_MPI_FROM_PMPI if weak symbols are not supported to build
   the MPI routines */
#ifndef MPICH_MPI_FROM_PMPI
#undef MPI_Send
#define MPI_Send PMPI_Send

#endif

#undef FUNCNAME
#define FUNCNAME MPI_Send

/*@
    MPI_Send - Performs a blocking send

Input Parameters:
+ buf - initial address of send buffer (choice) 
. count - number of elements in send buffer (nonnegative integer) 
. datatype - datatype of each send buffer element (handle) 
. dest - rank of destination (integer) 
. tag - message tag (integer) 
- comm - communicator (handle) 

Notes:
This routine may block until the message is received by the destination 
process.

.N ThreadSafe

.N Fortran

.N Errors
.N MPI_SUCCESS
.N MPI_ERR_COMM
.N MPI_ERR_COUNT
.N MPI_ERR_TYPE
.N MPI_ERR_TAG
.N MPI_ERR_RANK

.seealso: MPI_Isend, MPI_Bsend
@*/
int MPI_Send(const void *buf, int count, MPI_Datatype datatype, int dest, int tag,
	     MPI_Comm comm)
{
    static const char FCNAME[] = "MPI_Send";
    int mpi_errno = MPI_SUCCESS;
    MPID_Comm *comm_ptr = NULL;
    MPID_Request * request_ptr = NULL;
    MPID_MPI_STATE_DECL(MPID_STATE_MPI_SEND);

    MPIR_ERRTEST_INITIALIZED_ORDIE();
    
    MPID_THREAD_CS_ENTER(GLOBAL, MPIR_THREAD_GLOBAL_ALLFUNC_MUTEX);
    MPID_MPI_PT2PT_FUNC_ENTER_FRONT(MPID_STATE_MPI_SEND);
    
    /* Validate handle parameters needing to be converted */
#   ifdef HAVE_ERROR_CHECKING
    {
        MPID_BEGIN_ERROR_CHECKS;
        {
	    MPIR_ERRTEST_COMM(comm, mpi_errno);
	}
        MPID_END_ERROR_CHECKS;
    }
#   endif /* HAVE_ERROR_CHECKING */
    
    /* Convert MPI object handles to object pointers */
    MPID_Comm_get_ptr( comm, comm_ptr );

    /* Validate parameters if error checking is enabled */
#   ifdef HAVE_ERROR_CHECKING
    {
        MPID_BEGIN_ERROR_CHECKS;
        {
            MPID_Comm_valid_ptr( comm_ptr, mpi_errno, FALSE );
            if (mpi_errno) goto fn_fail;
	    
	    MPIR_ERRTEST_COUNT(count, mpi_errno);
	    MPIR_ERRTEST_SEND_RANK(comm_ptr, dest, mpi_errno);
	    MPIR_ERRTEST_SEND_TAG(tag, mpi_errno);
	    
	    /* Validate datatype handle */
	    MPIR_ERRTEST_DATATYPE(datatype, "datatype", mpi_errno);
	    
	    /* Validate datatype object */
	    if (HANDLE_GET_KIND(datatype) != HANDLE_KIND_BUILTIN)
	    {
		MPID_Datatype *datatype_ptr = NULL;

		MPID_Datatype_get_ptr(datatype, datatype_ptr);
		MPID_Datatype_valid_ptr(datatype_ptr, mpi_errno);
		if (mpi_errno) goto fn_fail;
		MPID_Datatype_committed_ptr(datatype_ptr, mpi_errno);
		if (mpi_errno) goto fn_fail;
	    }
	    
	    /* Validate buffer */
	    MPIR_ERRTEST_USERBUFFER(buf,count,datatype,mpi_errno);
        }
        MPID_END_ERROR_CHECKS;
    }
#   endif /* HAVE_ERROR_CHECKING */

    /* ... body of routine ...  */
    
    mpi_errno = MPID_Send(buf, count, datatype, dest, tag, comm_ptr, 
			  MPID_CONTEXT_INTRA_PT2PT, &request_ptr);
    if (mpi_errno != MPI_SUCCESS) goto fn_fail;

    if (request_ptr == NULL)
    {
#if defined(CHANNEL_MRAIL)
        mpi_errno = MPID_Progress_test();
        if (mpi_errno != MPI_SUCCESS)
        {
            goto fn_fail;
        }
#endif /* defined(CHANNEL_MRAIL) */
	goto fn_exit;
    }

    /* If a request was returned, then we need to block until the request 
       is complete */
    if (!MPID_Request_is_complete(request_ptr))
    {
	MPID_Progress_state progress_state;
	    
	MPID_Progress_start(&progress_state);
        while (!MPID_Request_is_complete(request_ptr))
	{
	    mpi_errno = MPID_Progress_wait(&progress_state);
	    if (mpi_errno != MPI_SUCCESS)
	    {
		/* --BEGIN ERROR HANDLING-- */
		MPID_Progress_end(&progress_state);
		goto fn_fail;
		/* --END ERROR HANDLING-- */
	    }
	}
	MPID_Progress_end(&progress_state);
    }

    mpi_errno = request_ptr->status.MPI_ERROR;
    MPID_Request_release(request_ptr);
    
    if (mpi_errno != MPI_SUCCESS) goto fn_fail;

    /* ... end of body of routine ... */
    
  fn_exit:
    MPID_MPI_PT2PT_FUNC_EXIT(MPID_STATE_MPI_SEND);
    MPID_THREAD_CS_EXIT(GLOBAL, MPIR_THREAD_GLOBAL_ALLFUNC_MUTEX);
    return mpi_errno;

  fn_fail:
    /* --BEGIN ERROR HANDLING-- */
#   ifdef HAVE_ERROR_CHECKING
    {
	mpi_errno = MPIR_Err_create_code(
	    mpi_errno, MPIR_ERR_RECOVERABLE, FCNAME, __LINE__, MPI_ERR_OTHER, "**mpi_send", 
	    "**mpi_send %p %d %D %i %t %C", buf, count, datatype, dest, tag, comm);
    }
#   endif
    mpi_errno = MPIR_Err_return_comm( comm_ptr, FCNAME, mpi_errno );
    goto fn_exit;
    /* --END ERROR HANDLING-- */
}


void init_openssl_128(){

	ctx_enc = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx_enc, EVP_aes_128_gcm(), NULL, NULL, NULL);
	ctx_dec = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_gcm(), NULL, NULL, NULL);
	int world_rank;
	MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
	if (world_rank == 0) printf("\n\t\t****** Secure MPI with OpenSSL  128  GCM ********\n");
    return;                        
}

void init_openssl_256(){

	ctx_enc = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx_enc, EVP_aes_256_gcm(), NULL, NULL, NULL);
	ctx_dec = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx_dec, EVP_aes_256_gcm(), NULL, NULL, NULL);
	int world_rank;
	MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
	if (world_rank == 0) printf("\n\t\t****** Secure MPI with OpenSSL  256  GCM ********\n");
    return;                        
}

void init_ocb_128(){

	ctx_enc = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx_enc, EVP_aes_128_ocb(), NULL, NULL, NULL);
	ctx_dec = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_ocb(), NULL, NULL, NULL);
	int world_rank;
	MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
	if (world_rank == 0) printf("\n\t\t****** Secure Run with OpenSSL  128  OCB ********\n");
    return;                        
}

void init_ocb_256(){

	ctx_enc = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx_enc, EVP_aes_256_ocb(), NULL, NULL, NULL);
	ctx_dec = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx_dec, EVP_aes_256_ocb(), NULL, NULL, NULL);
	int world_rank;
	MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
	if (world_rank == 0) printf("\n\t\t****** Secure Run with OpenSSL  256  OCB ********\n");
    return;                        
}

void init_ctr_128(){

	ctx_enc = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx_enc, EVP_aes_128_ctr(), NULL, NULL, NULL);
	ctx_dec = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_ctr(), NULL, NULL, NULL);
	int world_rank;
	MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
	if (world_rank == 0) printf("\n\t\t****** Secure Run with OpenSSL  128  CTR ********\n");
    return;                        
}
void init_ctr_256(){

	ctx_enc = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx_enc, EVP_aes_256_ctr(), NULL, NULL, NULL);
	ctx_dec = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx_dec, EVP_aes_256_ctr(), NULL, NULL, NULL);
	int world_rank;
	MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
	if (world_rank == 0) printf("\n\t\t****** Secure Run with OpenSSL  256  CTR ********\n");
    return;                        
}


void init_prectr_128(){
	int len, i, rank, world_size;
	memset(p,0,8020);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

	ctx_enc = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx_enc, EVP_aes_128_ctr(), NULL, NULL, NULL);

	//pre_calculator default 1024: 64*16
	for (i=0;i<world_size;i++){
		if(i != rank){
			RAND_bytes(&IV[i][0], 16);
			EVP_EncryptInit_ex(ctx_enc, NULL, NULL, gcm_key, &IV[i][0]);
			EVP_EncryptUpdate(ctx_enc, &pre_calculator[i][0], &len, p, 1024);
			iv_counter[i] = 64;
			pre_start[i] = 0;
			pre_end[i] = 1024;
		}
		first_flag[i] = 1;
		dec_flag[i] =1;
	}
	ctx_dec = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_ctr(), NULL, NULL, NULL);
	
	int world_rank;
	MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
	if (world_rank == 0) printf("\n\t\t****** Secure Run with OpenSSL  128  Pre-CTR ********\n");
	
    return 0;
}

void init_prectr_256(){
	int len, i, rank, world_size;
	memset(p,0,8020);
  	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

	ctx_enc = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx_enc, EVP_aes_256_ctr(), NULL, NULL, NULL);

	//pre_calculator default 1024: 64*16
	for (i=0;i<world_size;i++){
		if (i!=rank){
			RAND_bytes(&IV[i][0], 16);
			EVP_EncryptInit_ex(ctx_enc, NULL, NULL, gcm_key, &IV[i][0]);
			EVP_EncryptUpdate(ctx_enc, &pre_calculator[i][0], &len, p, 1024);
			iv_counter[i] = 64;
			pre_start[i] = 0;
			pre_end[i] = 1024;
		}
		first_flag[i] = 1;
		dec_flag[i] =1;
	}
	ctx_dec = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx_dec, EVP_aes_256_ctr(), NULL, NULL, NULL);
	
	int world_rank;
	MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
	if (world_rank == 0) printf("\n\t\t****** Secure Run with OpenSSL  256  Pre-CTR ********\n");
	
    return 0;
}


//void openssl_enc_core(unsigned char * ciphertext_send, unsigned long long src,const void *sendbuf, unsigned long long dest, unsigned long long blocktype_send){
void openssl_enc_core(unsigned char *send_ciphertext , unsigned long long src,const void *sendbuf, unsigned long long dest, unsigned long long blocktype_send){	
	const unsigned char gcm_key[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	//unsigned char gcm_iv[] = {0,0,0,0,0,0,0,0,0,0,0,0};
    //src: already sent cipher length, dest: already sent message length
	
	//unsigned char n[14];
	int rc = RAND_bytes(send_ciphertext+src, 12);
	//unsigned long err = ERR_get_error();

if(rc != 1) {
    /* RAND_bytes failed */
    /* `err` is valid    */
	printf("Nonce did not generated\n");
}

  //printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
    //    send_ciphertext[0],send_ciphertext[1],send_ciphertext[2],send_ciphertext[3],send_ciphertext[4],
	//	send_ciphertext[5],send_ciphertext[6],send_ciphertext[7],send_ciphertext[8],send_ciphertext[9],
	//	send_ciphertext[10],send_ciphertext[11]);

	/*nonceCounter++;
	memset(&send_ciphertext[src], 0, 8);
	send_ciphertext[src + 8] = (nonceCounter >> 24) & 0xFF;
	send_ciphertext[src + 9] = (nonceCounter >> 16) & 0xFF;
	send_ciphertext[src + 10] = (nonceCounter >> 8) & 0xFF;
	send_ciphertext[src+ 11] = nonceCounter & 0xFF;*/
	
/* OK to proceed */

	//int world_rank;
	//static int first_enc=1;
	
	
	EVP_EncryptInit_ex(ctx_enc, NULL, NULL, gcm_key, send_ciphertext+src);
	//EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	
	//EVP_EncryptUpdate(ctx_enc, ciphertext_send+src, &outlen_enc, sendbuf+dest, blocktype_send);
	//src: already sent cipher length, dest: already sent message length
	EVP_EncryptUpdate(ctx_enc, send_ciphertext+src+12, &outlen_enc, sendbuf+dest, blocktype_send);

	//EVP_EncryptFinal_ex(ctx_enc, ciphertext_send+src+outlen_enc, &outlen_enc);
	EVP_EncryptFinal_ex(ctx_enc, send_ciphertext+12+src+outlen_enc, &outlen_enc);
	//EVP_CIPHER_CTX_ctrl(ctx_enc, EVP_CTRL_AEAD_GET_TAG, 16, ciphertext_send+src+blocktype_send);
	/* (ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) */
	EVP_CIPHER_CTX_ctrl(ctx_enc, EVP_CTRL_AEAD_GET_TAG, 16, send_ciphertext+12+src+blocktype_send);



	//return outlen_enc;
}

int MPI_SEC_Send(const void *buf, int count, MPI_Datatype datatype, int dest, int tag, MPI_Comm comm , int max_pack)
{
    int mpi_errno = MPI_SUCCESS;
	int world_rank;
	MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
	int i=0;
			
	char * ciphertext;
	int sendtype_sz;
	unsigned long long next, src;
	MPI_Type_size(datatype, &sendtype_sz);
    	
	unsigned long long blocktype_send= (unsigned long long) sendtype_sz*count;
	
	
	openssl_enc_core(send_ciphertext,0,buf,0,blocktype_send);
		
    // BIO_dump_fp(stdout, ciphertext, count+16);
	
	//with IV size 12, tag size 16
	mpi_errno=MPI_Send(send_ciphertext,blocktype_send+16+12, MPI_CHAR, dest, tag, comm);

	return mpi_errno;
}



int MPI_CTR_Send(const void *buf, int count, MPI_Datatype datatype, int dest, int tag, MPI_Comm comm , int max_pack)
{
    int mpi_errno = MPI_SUCCESS;
	int world_rank;
	MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
	int i=0;
			
	char * ciphertext;
	int sendtype_sz;
	unsigned long long next, src;
	MPI_Type_size(datatype, &sendtype_sz);
    	
	unsigned long long blocktype_send= (unsigned long long) sendtype_sz*count;
		

	RAND_bytes(send_ciphertext, 12);
	EVP_EncryptInit_ex(ctx_enc, NULL, NULL, gcm_key, send_ciphertext);
	EVP_EncryptUpdate(ctx_enc, send_ciphertext+12, &outlen_enc, buf, blocktype_send);

	mpi_errno=MPI_Send(send_ciphertext,blocktype_send+12, MPI_CHAR, dest, tag, comm);
	return mpi_errno;
}


void IV_Count(unsigned char *IV ,int cter){
	uint32_t n = 16, c = (uint32_t) cter;
	do {
        --n;
        c += IV[n];
        IV[n] = (uint8_t)c;
        c >>= 8;
    } while (n);
}

int MPI_PreCtr_Send(const void *buf, int count, MPI_Datatype datatype, int dest, int tag, MPI_Comm comm , int max_pack)
{
    int mpi_errno = MPI_SUCCESS;
	int i,len,segments,pre_fin,enc_start;		
	int sendtype_sz;

	MPI_Type_size(datatype, &sendtype_sz);	
	unsigned long long blocktype_send= (unsigned long long)sendtype_sz*count;
	if (blocktype_send > 8000){
			printf("\nError: message size must <= 8 K !!!\n");
			return 1;
	}
	//total pre-calcu bytes
	amount= pre_end[dest] - pre_start[dest];

	if (blocktype_send >= 8000-pre_start[dest]){
		memcpy(&enc_iv[dest][0],&IV[dest][0],16);
		IV_Count(&enc_iv[dest][0],iv_counter[dest]);
		//Restart from beginning && Make sure pre_end Always= 16*N
		segments=((blocktype_send-1)/16)*16+16;	//upper integer
		EVP_EncryptInit_ex(ctx_enc, NULL, NULL, gcm_key, &enc_iv[dest][0]);
		EVP_EncryptUpdate(ctx_enc, &pre_calculator[dest][0], &len, p, segments);
		iv_counter[dest] += (segments/16);
		pre_start[dest] = 0;
		pre_end[dest] = segments;
	}else if(blocktype_send > amount){
		//Add more pre-ctr blocks
		memcpy(&enc_iv[dest][0],&IV[dest][0],16);
		IV_Count(&enc_iv[dest][0],iv_counter[dest]);
		segments =((blocktype_send-amount-1)/16)*16+16;
		pre_fin = pre_end[dest]; 
		EVP_EncryptInit_ex(ctx_enc, NULL, NULL, gcm_key, &enc_iv[dest][0]);
		EVP_EncryptUpdate(ctx_enc, &pre_calculator[dest][pre_fin], &len, p, segments); 
		iv_counter[dest] += (segments/16); //upper integer
		pre_end[dest] += segments ;
	}
	

   //Encryption 
   if (first_flag[dest] ==1){
	   memcpy(send_ciphertext,&IV[dest][0],16);
	   for(i=0; i< blocktype_send; i++){
        send_ciphertext[i+16] = (unsigned char )(pre_calculator[dest][i] ^ *((unsigned char *)(buf+i)));
	   }
	   mpi_errno=MPI_Send(send_ciphertext,blocktype_send+16, MPI_CHAR, dest, tag, comm);
	   first_flag[dest] =0;
	   pre_start[dest] +=blocktype_send;

	}else{
		for(i=0; i< blocktype_send; i++){
			enc_start = pre_start[dest];
        	send_ciphertext[i] = (unsigned char )(pre_calculator[dest][enc_start+i] ^ *((unsigned char *)(buf+i)));
	    }
		mpi_errno=MPI_Send(send_ciphertext,blocktype_send, MPI_CHAR, dest, tag, comm);
		pre_start[dest] +=blocktype_send;
	}
	
    //Regeneration
    amount= pre_end[dest] - pre_start[dest];
	if(amount<128){
		memcpy(&enc_iv[dest][0],&IV[dest][0],16);
		IV_Count(&enc_iv[dest][0],iv_counter[dest]);
		if(pre_end[dest]+128>8000){
			//Restart from beginning
			EVP_EncryptInit_ex(ctx_enc, NULL, NULL, gcm_key, &enc_iv[dest][0]);
			EVP_EncryptUpdate(ctx_enc, &pre_calculator[dest][0], &len, p, 1024);
			iv_counter[dest] += 64;
			pre_start[dest] = 0;
			pre_end[dest] = 1024;
		}else{
			EVP_EncryptInit_ex(ctx_enc, NULL, NULL, gcm_key, &enc_iv[dest][0]);
			pre_fin = pre_end[dest];
			EVP_EncryptUpdate(ctx_enc, &pre_calculator[dest][pre_fin], &len, p, 128);
			iv_counter[dest] += 8;

			//printf("\n Enc! pre_calculator: %c %c %c %c %c %c %c %c  \n",
            //pre_calculator[0][pre_end], pre_calculator[0][pre_end+1], pre_calculator[0][pre_end+2], pre_calculator[0][pre_end+4],
            //pre_calculator[0][pre_end+5], pre_calculator[0][pre_end+6], pre_calculator[0][pre_end+7], pre_calculator[0][pre_end+8]);

			pre_end[dest] = (16*iv_counter[dest])%8000;
		}
	}	
	return mpi_errno;
}