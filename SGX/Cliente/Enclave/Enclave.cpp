

#include <stdlib.h>
#include <string.h>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#define MAX_BUF_LEN 1024

#include <stdarg.h>
#include <stdio.h>      

#include "Enclave.h"
#include "Enclave_t.h"

#include <unistd.h>

#include "ippcp.h"

//- INICIALIZACIÓN VBLES -----------------------------------------------------

    sgx_ecc_state_handle_t handle;
    sgx_ec256_private_t Pv;
    sgx_ec256_public_t Pu;

    sgx_ec256_public_t application_pk;

    sgx_ec256_dh_shared_t DHKey; 

    sgx_ec256_signature_t sing;

    uint8_t *I_rand, *R_rand;

    uint8_t p_ctr_tx[16] = {0x00};
    uint8_t p_ctr_rx[16] = {0x00};

    unsigned char ebytes[MAX_BUF_LEN];
    size_t ebytes_len;

    //--------------------------------------

    uint8_t *MasterKey;

    uint8_t Cipherk_I[32] = {'\0'}, Cipherk_R[32] = {'\0'};

    uint8_t IVk_I[32] = {'\0'}, IVk_R[32] = {'\0'};

    uint8_t *IpR_rand;
    uint8_t *RpI_rand;

    uint8_t *IVNONCE_I;
    uint8_t *IVNONCE_R;

    uint8_t PKG[160] = {'\0'};

    uint8_t PKG_IV[16] = {0x00};
    uint8_t PKG_IV2[16] = {0x00};

    int offset = 0;

    int DH_Rol = '\0';

    char debug = 0x01;

    char log = 0x00;

//----------------------------------------------------------------------------

//ECALL's

void new_keypair(sgx_ec256_public_t *extern_pk, size_t len){                               //Función que genera un par de claves
                                                                                            //privada y pública.


    sgx_status_t status = sgx_ecc256_open_context(&handle);                                 //Apertura de contexto criptográfico.

    sgx_status_t statuz = sgx_ecc256_create_key_pair(&Pv, &Pu, handle);                     //Generación de claves.

    if(status == SGX_SUCCESS && statuz == SGX_SUCCESS){                                     //Si las operaciones se realizan con 
                                                                                            //éxito se devuelve la clave pública.
        *extern_pk = Pu;

    }

    printf("p_ctr_tx: ");
    
    
    printf("p_ctr_rx: ");

}

void computeDHKey( sgx_ec256_public_t *extern_pk, size_t len){                              //Función que computa la clave simétrica.

    application_pk = *extern_pk;

    sgx_ecc256_compute_shared_dhkey(&Pv, &application_pk, &DHKey, handle);                  //Computacíon de la clave.
}

//------------------------------------------------------------

void get_rand(int rol, uint8_t* pointer, size_t len){

    uint8_t rand[len];

     sgx_read_rand((unsigned char*)rand, 32);

    if(rol == 1){

        I_rand = (uint8_t*) malloc(len*sizeof(uint8_t));
        memcpy(I_rand, rand, len);
    }else{

        R_rand = (uint8_t*) malloc(len*sizeof(uint8_t));
        memcpy(R_rand, rand, len);

    }

    if(pointer != NULL) delete(pointer);

    pointer =  (uint8_t*) malloc(len*sizeof(uint8_t));
    memcpy(pointer, rand, len);

    DH_Rol = rol;

}
 
void print_hex(uint8_t* array, size_t len){                         //Muestra con formateo hexadecimal                                                                        //la información de un array uint8_t
        int i;
            for (i = 0; i < (int) len; i++) {
                printf("%02x ", array[i]);
            }
            printf("\n\n");
}


uint8_t* calculateHMAC(uint8_t *key, size_t key_len, uint8_t *nonce, size_t nonce_len, size_t out_len) {
    
    IppsHMACState *ctx;
    IppStatus status;
    int psize = 0;

    status = ippsHMAC_GetSize(&psize);

    if (status == ippStsNullPtrErr) 
        return NULL;

    ctx = (IppsHMACState*) malloc(psize);
    status = ippsHMAC_Init(key, key_len, ctx, ippHashAlg_SHA512);

    if (status != ippStsNoErr)
        return NULL;

    status = ippsHMAC_Update(nonce, nonce_len, ctx);

    if (status != ippStsNoErr)
        return NULL;

    out_len = (out_len < 64) ? out_len : 64;

    uint8_t* res_hmac = (uint8_t*)malloc(out_len*sizeof(uint8_t));

    status = ippsHMAC_Final(res_hmac, out_len, ctx);

    if (status != ippStsNoErr)
        return NULL;

    //printf("##~ HMAC: "); print_hex(res_hmac, out_len); 

    delete ctx;

    return res_hmac;

  }

uint8_t* PRF(uint8_t *key, uint8_t *label, uint8_t *seed, size_t bytes, int label_len = -1){

    uint8_t* exit = (uint8_t*)malloc(bytes*sizeof(uint8_t));
    uint counter = 0, regr_ctr = bytes, act_ctr = 0, cat_len = 0;

    //printf("Label_len = %d\n", label_len);

    label_len = (label_len == -1) ? strlen((char*)label) : label_len;

    uint8_t* cat = (uint8_t*)malloc((label_len+64)*sizeof(uint8_t));
    memcpy(cat, label, label_len);
    memcpy(cat+label_len, seed, 64);
    cat_len = label_len+64;

    //printf("--> Label + Seed: "); print_hex(cat, cat_len);

    uint8_t* hash_n_minus_one = (uint8_t*)malloc(64*sizeof(uint8_t)); 

    hash_n_minus_one = calculateHMAC(key, 32, cat, cat_len, 64);

    //printf("##~ HMAC: "); print_hex(hash_n_minus_one, 64);

    do{

        uint8_t* hash_n;

        if(regr_ctr > 64) act_ctr = 64;
        else              act_ctr = regr_ctr;

        hash_n = (uint8_t*)malloc(act_ctr*sizeof(uint8_t));

        uint8_t* cat2 = (uint8_t*)malloc((64+cat_len)*sizeof(uint8_t));
        memcpy(cat2, hash_n_minus_one, 64);
        memcpy(cat2+64, cat, cat_len);

        //printf("--> HMAC + Seed: "); print_hex(cat2, cat_len+64);

        hash_n = calculateHMAC(key, 32, cat2, 64+cat_len, act_ctr);

        //printf("--> HMAC2': "); print_hex(hash_n, act_ctr);

        memcpy(exit+counter, hash_n, act_ctr);

        if(act_ctr == 64) memcpy(hash_n_minus_one, hash_n, 64);

        delete hash_n;
        delete cat2;

        regr_ctr -= act_ctr;
        counter += act_ctr;

    }while(regr_ctr>0);

    delete hash_n_minus_one;
    delete cat;

    return exit;

}


void autoset_key(int Rol, uint8_t* randB, size_t len){

        if(Rol == 1){
            memcpy(R_rand, randB, 32);
        }else{
            memcpy(I_rand, randB, 32);
        }

        IpR_rand = (uint8_t*)malloc(64*sizeof(uint8_t));
        memcpy(IpR_rand, I_rand, 32);
        memcpy(IpR_rand+32, R_rand, 32);

        MasterKey = PRF(DHKey.s, (uint8_t*)"master secret", IpR_rand, 32);

        RpI_rand = (uint8_t*)malloc(64*sizeof(uint8_t));
        memcpy(RpI_rand, R_rand, 32);
        memcpy(RpI_rand+32, I_rand, 32);

        uint8_t *Key_Block = PRF(MasterKey, (uint8_t*)"key expansion", RpI_rand, 128);


        memcpy(Cipherk_I, Key_Block, 32);
        memcpy(Cipherk_R, Key_Block+32, 32);
        memcpy(IVk_I, Key_Block+64, 32);
        memcpy(IVk_R, Key_Block+96, 32);


        IVNONCE_I = PRF(IVk_I, (uint8_t*)"initialization vector", IpR_rand, 16);
        IVNONCE_R = PRF(IVk_R, (uint8_t*)"initialization vector", RpI_rand, 16);

        printf("\nDH_Key: "); print_hex(DHKey.s, 32);
        printf("\nMasterKey: "); print_hex(MasterKey, 32);
        printf("\nKey_Block: "); print_hex(Key_Block, 128);
        printf("\nCipherk_I: "); print_hex(Cipherk_I, 32);
        printf("\nCipherk_R: "); print_hex(Cipherk_R, 32);
        printf("\nIVk_I: "); print_hex(IVk_I, 32);
        printf("\nIVk_R: "); print_hex(IVk_R, 32);

        printf("\nIVNONCE_I: "); print_hex(IVNONCE_I, 16);
        printf("\nIVNONCE_R: "); print_hex(IVNONCE_R, 16);

//----------------------------------------------------------------------

        /*printf("\n\nDiffie-Hellman key: "); print_hex(DHKey, 32);
        printf("\nMasterKey: "); print_hex(IVk, 16);
        printf("\nCipher key: "); print_hex(CIPHERk, 16);*/

//----------------------------------------------------------------------

}

void cypher_in(char *decMessageIn, size_t lenIn, char *encMessageOut, size_t lenOut){

    uint8_t *origMessage = (uint8_t *) decMessageIn;
    uint8_t p_dst[lenOut] = {0};

    uint8_t **IV = NULL;

    if(DH_Rol) IV = &IVNONCE_I;
    else IV = &IVNONCE_R;

    uint8_t *IVk = (DH_Rol) ? IVk_I : IVk_R;
    uint8_t *CIPHERk = (DH_Rol) ? Cipherk_I : Cipherk_R;

    /*if(log){

    fputs("ENC,", arch_log);
    write(arch_log, p_ctr_tx, 16);
    fputs(",", arch_log); 
    write(arch_log, origMessage, lenIn);
    fputs(",", arch_log); 

    }*/
    // Generate the IV (nonce)
    //sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);                         //Se genera una secuencia aleatoria
                                                                                            //usada por el codificador


    printf("USED_ IVNONCE_tx: "); print_hex(PKG_IV, 16);

    sgx_aes_ctr_encrypt(

        (sgx_aes_ctr_128bit_key_t *) &CIPHERk,
        origMessage,
        (uint32_t) lenIn,
        PKG_IV,
        (uint32_t) 32,
        p_dst);

    memset(PKG_IV, 0x00, 16);

    /*if(log){

    write(arch_log, p_dst, lenIn);
    fputs(",", arch_log);
    write(arch_log, p_ctr_tx, 16);
    fputs("\n", arch_log);

    }*/

    printf("PKGE_tx: \n"); print_hex(p_dst, 160);

    printf("Key IV: "); print_hex(IVk, 32);

    printf("Cipher Key: "); print_hex(CIPHERk, 32);

    delete (*IV);

    *IV = PRF(IVk, p_dst, IpR_rand, 16, 160);

    //memcpy(*IV, p_dst+(160-16), 16);

    printf("NEW_ IVNONCE_tx: "); print_hex(*IV, 16);

    /*sgx_rijndael128GCM_encrypt(                                                             //Codificador basado en el algoritmo de
                                                                                            //Rijndael (estandar AES).
        (sgx_aes_gcm_128bit_key_t *) &DHKey,
        origMessage, lenIn, 
        p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
        p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
        NULL, 0,
        (sgx_aes_gcm_128bit_tag_t *) (p_dst));  */
    
    memcpy(encMessageOut, p_dst, lenOut);                                                   //Se devuelve el texto codificado.

}

void cypher_out(char *encMessageIn, size_t lenIn, char *decMessageOut, size_t lenOut){        //Función decodificadora de texto codificado.

    uint8_t *origMessage = (uint8_t *) encMessageIn;
    uint8_t p_dst[lenOut] = {0};

   uint8_t **IV = NULL;

    if(DH_Rol) IV = &IVNONCE_R;
    else IV = &IVNONCE_I;

    uint8_t *IVk = (DH_Rol) ? IVk_R : IVk_I;
    uint8_t *CIPHERk = (DH_Rol) ? Cipherk_R : Cipherk_I;

    /*if(log){

    fputs("DEC,", arch_log);
    write(arch_log, p_ctr_rx, 16);
    fputs(",", arch_log); 
    write(arch_log, origMessage, lenIn);
    fputs(",", arch_log); 

    }*/

    sgx_aes_ctr_decrypt(

        (sgx_aes_ctr_128bit_key_t *) &CIPHERk,
        origMessage,
        (uint32_t) lenIn,
        PKG_IV2,
        (uint32_t) 32,
        p_dst);

    /*if(log){

    write(arch_log, p_dst, lenIn);
    fputs(",", arch_log);
    write(arch_log, p_ctr_rx, 16);
    fputs("\n", arch_log);

    }*/

   if(offset == 80){

        printf("USED_ IVNONCE_rx: "); print_hex(PKG_IV2, 16);

            memset(PKG_IV2, 0x00, 16);

        memcpy(PKG+offset, origMessage, 80);

        printf("PKGE_rx: \n"); print_hex(PKG, 160);

        printf("Key IV: "); print_hex(IVk, 32);

        printf("Cipher Key: "); print_hex(CIPHERk, 32);

        delete (*IV);

        *IV = PRF(IVk, PKG, IpR_rand , 16, 160);

        //memcpy(*IV, PKG+(160-16), 16);

        printf("NEW_ IVNONCE_rx: "); print_hex(*IV, 16);

        offset = 0;

    }else{

        memcpy(PKG, origMessage, 80);
        offset = 80;
    }

    /*sgx_rijndael128GCM_decrypt(                                                             //Decodificador basado en el algoritmo
                                                                                            //Rijndael (estandar AES).
        (sgx_aes_gcm_128bit_key_t *) &DHKey,
        encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
        lenOut,
        p_dst,
        encMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
        NULL, 0,
        (sgx_aes_gcm_128bit_tag_t *) encMessage);*/

    memcpy(decMessageOut, p_dst, lenIn);

}

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

