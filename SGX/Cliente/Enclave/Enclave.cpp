
//Librerias necesarias para la compilacion de SGX

#include <stdlib.h>
#include <string.h>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include <stdarg.h>
#include <stdio.h>      

#include "Enclave.h"
#include "Enclave_t.h"

#define MAX_BUF_LEN 1024           //Tamano maximo de las tramas


//- INICIALIZACIÓN VBLES -----------------------------------------------------

    sgx_ecc_state_handle_t handle;
    sgx_ec256_private_t Pv;
    sgx_ec256_public_t Pu;

    sgx_ec256_public_t application_pk;

    sgx_ec256_dh_shared_t DHKey; 

    sgx_ec256_signature_t sing;

    unsigned char ebytes[MAX_BUF_LEN];
    size_t ebytes_len;

//----------------------------------------------------------------------------

//ECALL's

void new_keypair( sgx_ec256_public_t *extern_pk, size_t len){                               //Función que genera un par de claves
                                                                                            //privada y pública.


    sgx_status_t status = sgx_ecc256_open_context(&handle);                                 //Apertura de contexto criptográfico.

    sgx_status_t statuz = sgx_ecc256_create_key_pair(&Pv, &Pu, handle);                     //Generación de claves.

    if(status == SGX_SUCCESS && statuz == SGX_SUCCESS){                                     //Si las operaciones se realizan con 
                                                                                            //éxito se devuelve la clave pública.
        *extern_pk = Pu;

    }

}

void computeDHKey( sgx_ec256_public_t *extern_pk, size_t len){                              //Función que computa la clave simétrica.

    application_pk = *extern_pk;

    sgx_ecc256_compute_shared_dhkey(&Pv, &application_pk, &DHKey, handle);                  //Computacíon de la clave.

}

void sgx_encrypt(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut)        //Función codificadora de texto plano.
{
    uint8_t *origMessage = (uint8_t *) decMessageIn;
    uint8_t p_dst[lenOut] = {0};

    // Generate the IV (nonce)
    sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);                         //Se genera una secuencia aleatoria
                                                                                            //usada por el codificador

    sgx_rijndael128GCM_encrypt(                                                             //Codificador basado en el algoritmo de
                                                                                            //Rijndael (estandar AES).
        (sgx_aes_gcm_128bit_key_t *) &DHKey.s,
        origMessage, len, 
        p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
        p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
        NULL, 0,
        (sgx_aes_gcm_128bit_tag_t *) (p_dst));  
    memcpy(encMessageOut,p_dst,lenOut);                                                     //Se devuelve el texto codificado.
}

void sgx_decrypt(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut)        //Función decodificadora de texto codificado.
{
    uint8_t *encMessage = (uint8_t *) encMessageIn;
    uint8_t p_dst[lenOut] = {0};

    sgx_rijndael128GCM_decrypt(                                                             //Decodificador basado en el algoritmo
                                                                                            //Rijndael (estandar AES).
        (sgx_aes_gcm_128bit_key_t *) &DHKey.s,
        encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
        lenOut,
        p_dst,
        encMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
        NULL, 0,
        (sgx_aes_gcm_128bit_tag_t *) encMessage);
    memcpy(decMessageOut, p_dst, lenOut);

}


//OCALL's

void printf(const char *fmt, ...)                              //Función de escritura en el contexto de la aplicación.
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);                                   //Llamada a la función externa con los datos a representar.
} 
