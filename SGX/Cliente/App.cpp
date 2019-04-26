

// - LIBRERIAS NECESARIAS PARA SGX ----------------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>

# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"


//-----------------------------

#include <pjsua-lib/pjsua.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

//-----------------------------

#include "pj_enclave.h"

//-----------------------------

#include "sgx_tcrypto.h"

#include <sys/socket.h>    //Para uso de la función socket
#include <arpa/inet.h>     //Para uso de la definición inet_addr

// - LIBRERIAS INCLUIDAS POR MI ----------------------------------------------------------------------------------

#define MAX_BUF_LEN 1024
#define SGX_AESGCM_MAC_SIZE 16
#define SGX_AESGCM_IV_SIZE 12

#define INICIADOR 1       //Identificador del iniciador de la conexión
#define RECEPTOR  0       //Identificador del receptor de la conexión

#define Y_STR 'S'         //Variable de comparación 'S' (Sí)
#define N_STR 'N'         //Variable de comparación 'N' (No)
 
#define THIS_FILE "APP"
 
#define SIP_DOMAIN "192.168.48.170"
//#define SIP_USER "7002"
//#define SIP_PASSWD "456"

#define USE_ENCLAVE 1
#define LOG_TEXT    1

#define TX_FILE 0x01
#define RX_FILE 0x02

const char NULL_ARRAY[16] = {0x00};

FILE *arch_log_tx = NULL;
FILE *arch_log_rx = NULL;

int ctr_sync = 0;


//Funciones y variables propias de la inicialización del enclave.

    sgx_enclave_id_t global_eid = 0;                    //EID: Código de identificación del enclave para su posterior llamada.

    typedef struct _sgx_errlist_t {                     //Estructura contenedora de errores de Intel SGX(R).
        sgx_status_t err;
        const char *msg;
        const char *sug;
    } sgx_errlist_t;

    static sgx_errlist_t sgx_errlist[] = {    //ESP//         //Listado de errores posibles en tiempo de ejecución y sugerencia asociada.
        {
            SGX_ERROR_UNEXPECTED,
            "Unexpected error occurred.",
            NULL
        },
        {
            SGX_ERROR_INVALID_PARAMETER,
            "Invalid parameter.",
            NULL
        },
        {
            SGX_ERROR_OUT_OF_MEMORY,
            "Out of memory.",
            NULL
        },
        {
            SGX_ERROR_ENCLAVE_LOST,
            "Power transition occurred.",
            "Please refer to the sample \"PowerTransition\" for details."
        },
        {
            SGX_ERROR_INVALID_ENCLAVE,
            "Invalid enclave image.",
            NULL
        },
        {
            SGX_ERROR_INVALID_ENCLAVE_ID,
            "Invalid enclave identification.",
            NULL
        },
        {
            SGX_ERROR_INVALID_SIGNATURE,
            "Invalid enclave signature.",
            NULL
        },
        {
            SGX_ERROR_OUT_OF_EPC,
            "Out of EPC memory.",
            NULL
        },
        {
            SGX_ERROR_NO_DEVICE,
            "Invalid SGX device.",
            "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
        },
        {
            SGX_ERROR_MEMORY_MAP_CONFLICT,
            "Memory map conflicted.",
            NULL
        },
        {
            SGX_ERROR_INVALID_METADATA,
            "Invalid enclave metadata.",
            NULL
        },
        {
            SGX_ERROR_DEVICE_BUSY,
            "SGX device was busy.",
            NULL
        },
        {
            SGX_ERROR_INVALID_VERSION,
            "Enclave version was invalid.",
            NULL
        },
        {
            SGX_ERROR_INVALID_ATTRIBUTE,
            "Enclave was not authorized.",
            NULL
        },
        {
            SGX_ERROR_ENCLAVE_FILE_ACCESS,
            "Can't open enclave file.",
            NULL
        },
    };

    void print_error_message(sgx_status_t ret){                             //Función que muestra el error que puediese haber ocurrido.
        size_t idx = 0;
        size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

        for (idx = 0; idx < ttl; idx++) {
            if(ret == sgx_errlist[idx].err) {
                if(NULL != sgx_errlist[idx].sug)
                    printf("Información: %s\n", sgx_errlist[idx].sug);
                printf("Error: %s\n", sgx_errlist[idx].msg);
                break;
            }
        }
        
        if (idx == ttl)
        	printf("Codigo de error 0x%X. Por favor acuda a la \"Guía de desarrollo para Intel SGX - SDK\" para más detalles.\n", ret);
    }

    int initialize_enclave(void){
        sgx_launch_token_t token = {0};
        sgx_status_t ret = SGX_ERROR_UNEXPECTED;
        int updated = 0;
        
        /* Call sgx_create_enclave to initialize an enclave instance */
        /* Debug Support: set 2nd parameter to 1 */
        ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
        if (ret != SGX_SUCCESS) {
            print_error_message(ret);
            return -1;
        }

        return 0;
    }

    /* OCall functions */
    void ocall_print_string(const char *str){
        /* Proxy/Bridge will check the length and null-terminate 
         * the input string to prevent buffer overflow. 
         */
        printf("%s", str);
    }

//Funciones de testeo:

    void print_hex(uint8_t* array, size_t len){                         //Muestra con formateo hexadecimal
                                                                        //la información de un array uint8_t
        int i;
            for (i = 0; i < (int) len; i++) {
                printf("%02x ", array[i]);
            }
            printf("\n\n");
    }

    void print_hex(uint32_t* array, size_t len){                        //Muestra con formateo hexadecimal
                                                                        //la información de un array uint32_t
    	printf("\n");
        int i;
        for (i = 0; i < (int) len; i++) {
            printf("%02x ", array[i]);
        }
        printf("\n\n");
    }


    uint8_t* l2bswap8_t(const uint8_t *array, size_t tam){              //Realiza un swap de little-endian
                                                                        //a big-endian de un array uint8_t
    	uint8_t* aux = (uint8_t*) malloc(tam);

    	int a = tam-1;
        	for(int i=0; i<tam; i++){
    	
    		aux[a] = array[i];
    		a-=1;

       	}

    	return aux;
    }

    uint32_t* l2bswap32_t(const uint32_t *array, size_t tam){           //Realiza un swap de little-endian
                                                                        //a big-endian de un array uint32_t
    	uint8_t* aux8 = (uint8_t*) malloc( tam * 4);

    	aux8 = (uint8_t*)memcpy((void*)aux8, (void*)array, tam*4);

    	return (uint32_t *) l2bswap8_t(aux8, tam*4) ;
    }

    void print_log(uint8_t* array, uint8_t where, size_t len){

      if((where == TX_FILE) && (arch_log_tx != NULL) && LOG_TEXT){

        write(fileno(arch_log_tx), array, len);
        //write(fileno(arch_log_tx), NULL_ARRAY, 16);

      }

      if((where == RX_FILE) && (arch_log_rx != NULL) && LOG_TEXT){

        write(fileno(arch_log_rx), array, len);
        //write(fileno(arch_log_tx), NULL_ARRAY, 16);

      }

    }

//-----------------------------------------------------------------------------

static void Encoder_(char *decMessageIn, size_t lenIn, char *encMessageOut, size_t &lenOut){
    printf("This is a callback to SGX Encoder with length: %d \n", lenIn);

    //size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + lenOut);
    //print_hex((uint8_t*) decMessageIn, lenIn);
    
    //print_log((uint8_t*)decMessageIn, lenIn);

    printf("PKG_plain: \n"); print_hex((uint8_t*)decMessageIn, lenIn);

    //print_log((uint8_t*)decMessageIn, TX_FILE, lenIn);
    cypher_in(global_eid, decMessageIn, lenIn, encMessageOut, lenOut);
    print_log((uint8_t*)encMessageOut, TX_FILE, lenIn);

    //getchar();
    //print_hex((uint8_t*) encMessageOut, lenOut);
 }

static void Decoder_(char *encMessageIn, size_t lenIn, char *decMessageOut, size_t &lenOut){
    printf("This is a callback to SGX Decoder\n");

    //size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + lenOut);
    
    //print_log((uint8_t*)encMessageIn, lenIn);

    //memcpy(decMessageOut, encMessageIn, lenIn);

    print_log((uint8_t*)encMessageIn, RX_FILE, lenIn);
    cypher_out(global_eid, encMessageIn, lenIn, decMessageOut, lenOut);

    printf("PKG_decod: \n"); print_hex((uint8_t*)decMessageOut, lenOut);

    //getchar();
    //print_log((uint8_t*)decMessageOut, RX_FILE, lenIn);
    //print_hex((uint8_t*) decMessageOut, lenOut);
 }

/* Callback called by the library upon receiving incoming call */
 static void on_incoming_call(pjsua_acc_id acc_id, pjsua_call_id call_id,
  pjsip_rx_data *rdata)
 {
  pjsua_call_info ci;
 
  PJ_UNUSED_ARG(acc_id);
  PJ_UNUSED_ARG(rdata);
 
  pjsua_call_get_info(call_id, &ci);
 
  PJ_LOG(3,(THIS_FILE, "Incoming call from %.*s!!",
  (int)ci.remote_info.slen,
  ci.remote_info.ptr));
 
  /* Automatically answer incoming calls with 200/OK */
  pjsua_call_answer(call_id, 200, NULL, NULL);
 }
 
 /* Callback called by the library when call's state has changed */
 static void on_call_state(pjsua_call_id call_id, pjsip_event *e)
 {
  pjsua_call_info ci;
 
  PJ_UNUSED_ARG(e);
 
  pjsua_call_get_info(call_id, &ci);
  PJ_LOG(3,(THIS_FILE, "Call %d state=%.*s", call_id,
  (int)ci.state_text.slen,
  ci.state_text.ptr));
 }
 
 /* Callback called by the library when call's media state has changed */
 static void on_call_media_state(pjsua_call_id call_id)
 {
  pjsua_call_info ci;
 
  pjsua_call_get_info(call_id, &ci);
 
  if (ci.media_status == PJSUA_CALL_MEDIA_ACTIVE) {
  // When media is active, connect call to sound device.
  pjsua_conf_connect(ci.conf_slot, 0);
  pjsua_conf_connect(0, ci.conf_slot);
  }
 }

 static void on_pager(pjsua_call_id call_id, const pj_str_t *from, const pj_str_t *to, const pj_str_t *contact, const pj_str_t *mime_type, const pj_str_t *body){

  PJ_UNUSED_ARG(call_id);
  PJ_UNUSED_ARG(mime_type);
  PJ_UNUSED_ARG(to);
  PJ_UNUSED_ARG(contact);
  PJ_UNUSED_ARG(mime_type);

  printf("\nNEW MESSAGE RECEIVE!\n");
  printf("body: %s\n", (char*)body );

 }
 
 /* Display error and exit application */
 static void error_exit(const char *title, pj_status_t status)
 {
  pjsua_perror(THIS_FILE, title, status);
  pjsua_destroy();
  exit(1);
 }

//-------------------------------------------------------------------------

void Conectar_Enclaves(int tipo_conexion, int sock){

    sgx_ec256_public_t pu_A, pu_B;

    new_keypair(global_eid, &pu_A, sizeof(pu_A));

    print_hex(pu_A.gy, 32);

    uint8_t bytes[64] ={'\0'};

    uint8_t randA[32] = {0xe3, 0xfb, 0x88, 0xb2, 0xe6, 0x85, 0xda, 0x53, 0xbe, 0xed, 0xcb, 0x62, 0x5d, 0xf5,
0x27, 0xa1, 0xef, 0xeb, 0x53, 0xb0, 0x44, 0x74, 0x38, 0x20, 0x24, 0xfc, 0x3a, 0xde, 0x46, 0x70, 0x7d, 0x8d};
    uint8_t randB[32] = {0x47, 0xe5, 0x85, 0x01, 0x48, 0xfe, 0x77, 0x0e, 0x7f, 0x54, 0xcb, 0xb1, 0xd2, 0x0e,
0x27, 0x3c, 0x44, 0xdd, 0xa4, 0x8b, 0x31, 0xf5, 0x4d, 0xc5, 0x6a, 0x43, 0x4c, 0xd7, 0xab, 0xfd, 0xe5, 0x61};
    uint8_t randC[32];

    if(tipo_conexion == 1){

        puts("Este cliente inicia la conexión");

        memcpy(bytes, pu_A.gx, 32);
        memcpy(bytes+32, pu_A.gy, 32);

        /*print_hex(pu_A.gx, 32);
        print_hex(pu_A.gy, 32);

        print_hex(bytes, 64);*/

        if( send(sock, bytes , sizeof(bytes) , 0) < 0)
        {
            puts("Send Pu_A failed");
        }else printf("Pu_A enviada correctamente");

        printf("hola");

        if( recv(sock, bytes , sizeof(bytes) , 0) < 0)
        {
            puts("recv Pu_B failed");
        }else printf("Pu_B recibida correctamente");

        //get_rand(global_eid, tipo_conexion, randB, 32);

        /*if( send(sock, randA , 32 , 0) < 0)
        {
            puts("Send RandI failed");
        }else printf("RandI enviada correctamente");

        if( recv(sock, randC , 32 , 0) < 0)
        {
            puts("recv RandR failed");
        }else printf("RandR recibida correctamente");*/

        printf("hola");

        memcpy(pu_B.gx, bytes, 32);
        memcpy(pu_B.gy, bytes+32, 32);

        computeDHKey(global_eid, &pu_B, sizeof(pu_B));
        autoset_key(global_eid, tipo_conexion, randB, 32);

    }else if(tipo_conexion == 0){

        puts("Este cliente espera la conexión");

        if( recv(sock, bytes , sizeof(bytes) , 0) < 0)
        {
            puts("recv Pu_B failed");
        }else printf("Pu_B recibida correctamente");

        memcpy(pu_B.gx, bytes, 32);
        memcpy(pu_B.gy, bytes+32, 32);

        memcpy(bytes, pu_A.gx, 32);
        memcpy(bytes+32, pu_A.gy, 32);

        if( send(sock, bytes , sizeof(bytes) , 0) < 0)
        {
            puts("Send Pu_A failed");
        }else printf("Pu_A enviada correctamente");

        /*if( recv(sock, randC , 32 , 0) < 0)
        {
            puts("recv RandI failed");
        }else printf("RandI recibida correctamente");

        //get_rand(global_eid, tipo_conexion, randB, 32);

        if( send(sock, randB , 32 , 0) < 0)
        {
            puts("Send RandR failed");
        }else printf("RandR enviada correctamente");*/

        computeDHKey(global_eid, &pu_B, sizeof(pu_B));
        autoset_key(global_eid, tipo_conexion, randA, 32);

    }else puts("ERROR EN LA NEGOCIACIÓN");
}                                                                    

//-------------------------------------------------------------------------------

/* Application entry */
int SGX_CDECL main(int argc, char *argv[]){

    (void)(argc);
    (void)(argv);


    char *SIP_USER;
    char *SIP_PASSWD;

    /* Initialize the enclave */
    if(initialize_enclave() < 0){                                  //Función que inicializa el enclave Propia de SGX
        return -1;                                                  //Si la función falla el cliente se cierra pues necesita del enclave.
    }

    pjsua_acc_id acc_id;
  pj_status_t status;

  pj_enclave Enclave;

  if(USE_ENCLAVE){
    Enclave.ptr_encoder = &Encoder_;
    Enclave.ptr_decoder = &Decoder_;
    Enclave.param.global_eid = global_eid;
    //Enclave.param.codec_name = "G722 - SGX";
  }else{
    Enclave.ptr_encoder = NULL;
    Enclave.ptr_decoder = NULL;
  }
 //-----------------------------------------
 
  /* Create pjsua first! */
  status = pjsua_create();
  if (status != PJ_SUCCESS) error_exit("Error in pjsua_create()", status);
 
  /* If argument is specified, it's got to be a valid SIP URL */
  if (argc >1) {
  //status = pjsua_verify_url(argv[1]);
  //if (status != PJ_SUCCESS) error_exit("Invalid URL in argv", status);
    SIP_USER = argv[1];
    SIP_PASSWD = argv[2];

    if(LOG_TEXT){

      printf("Using LogFile\n");


      char logtxt_tx[15] = "log";
      strcat(logtxt_tx, SIP_USER);
      strcat(logtxt_tx, "tx\0");

      arch_log_tx = fopen(logtxt_tx, "w");
      if(arch_log_tx == NULL) exit(1);

      char logtxt_rx[15] = "log";
      strcat(logtxt_rx, SIP_USER);
      strcat(logtxt_rx, "rx\0");

      arch_log_rx = fopen(logtxt_rx, "w");
      if(arch_log_rx == NULL) exit(1);

    } //set_logtxt(global_eid, SIP_USER, strlen(SIP_USER));

    printf("Using LogFile\n");

  }else exit(1);
 
  /* Init pjsua */
 {
  pjsua_config cfg;
  pjsua_logging_config log_cfg;
 
  pjsua_config_default(&cfg);
  cfg.cb.on_incoming_call = &on_incoming_call;
  cfg.cb.on_call_media_state = &on_call_media_state;
  cfg.cb.on_call_state = &on_call_state;
  cfg.cb.on_pager = &on_pager;
 
  pjsua_logging_config_default(&log_cfg);
  log_cfg.console_level = 4;
 
  status = pjsua_init(&cfg, &log_cfg, NULL);
  if (status != PJ_SUCCESS) error_exit("Error in pjsua_init()", status);
  }
 
  /* Add UDP transport. */
  {
  pjsua_transport_config cfg;

  pjsua_transport_config_default(&cfg);

  srand(time(NULL));
  int random_number = rand() % 100 + 1;

  cfg.port = 6060 + random_number;

  printf("Application uses port %d", 6060 + random_number);

  status = pjsua_transport_create(PJSIP_TRANSPORT_UDP, &cfg, NULL);
  if (status != PJ_SUCCESS) error_exit("Error creating transport", status);
  }
 
  /* Initialization is done, now start pjsua */
  status = pjsua_start();
  if (status != PJ_SUCCESS) error_exit("Error starting pjsua", status);
 
  /* Register to SIP server by creating SIP account. */
  {
  pjsua_acc_config cfg;
 
  pjsua_acc_config_default(&cfg);

  char str[80];
  strcpy(str, "sip:");
  strcat(str, SIP_USER);
  strcat(str, "@");

  printf("\n%s,%s\n", SIP_USER, SIP_PASSWD);

  cfg.id = pj_str(strcat(str, SIP_DOMAIN));
  cfg.reg_uri = pj_str("sip:" SIP_DOMAIN);
  cfg.cred_count = 1;

  cfg.cred_info[0].realm = pj_str("*");
  cfg.cred_info[0].scheme = pj_str("digest");
  cfg.cred_info[0].username = pj_str(SIP_USER);
  cfg.cred_info[0].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
  cfg.cred_info[0].data = pj_str(SIP_PASSWD);
 
  status = pjsua_acc_add(&cfg, PJ_TRUE, &acc_id);
  if (status != PJ_SUCCESS) error_exit("Error adding account", status);
  }
 
  /* If URL is specified, make call to the URL. */
  /*if (argc > 1 ) {
  pj_str_t uri = pj_str(argv[1]);
  status = pjsua_call_make_call(acc_id, &uri, 0, NULL, NULL, NULL);
  if (status != PJ_SUCCESS) error_exit("Error making call", status);
  }*/

//--------------------------------------------------------------------

    pjsua_codec_info c[32];
    unsigned i, count = PJ_ARRAY_SIZE(c);

    char *ptr_comp = "G722/16000/1";

    pjsua_enum_codecs(c, &count);
    for (i=0; i<count && strcmp(c[i].codec_id.ptr, ptr_comp) != 0; ++i);

    printf("THISSSS ->> %s\n",c[i].codec_id.ptr);

    pjmedia_codec_param param;

    pjsua_codec_get_param(&c[i].codec_id, &param);

    param.info.void_ptr= (void*)&Enclave;

    pjsua_codec_set_param(&c[i].codec_id, &param);

//-------------------------------------------------------------------

/*##################################################################### MAIN-IN*/

    int sock;                                                   //Variable para almacenar el socket.
    struct sockaddr_in server;                                  //Estructura que almacena la dirección del servidor.
    char message[1000] , server_reply[2000];                    //Arrays de caracteres para los mensajes enviados y recibidos.

    char nombre[512];                                           //Array de caracteres para el nombre del usuario
    char iniciador;                                             //Variable para almacenar que tipo de conexión desea el usuario.          


    sock = socket(AF_INET , SOCK_STREAM , 0);                               //Intento de creación de un socket de comunicación.
    if (sock == -1)                                                         //Si el socket no puede crearse se produce un cierre del cliente.
    {
        printf("Could not create socket");
    }
    puts("Socket created");
     
    server.sin_addr.s_addr = inet_addr("127.0.0.1");                       //Dirección del servidor (Loopback)
    server.sin_family = AF_INET;                                           //Protocolo de Red TCP
    server.sin_port = htons( 9035 );                                       //Puerto de escucha predefinido.
 

    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)    //Se realiza un intento de conexión con el servidor definido.
    {
        perror("connect failed. Error");                                    //Si el servidor no responde se produce un cierre del cliente.
        return 1;
    }
     
    puts("Connected\n");                                                //indica que la conexión con el servidor se ha establecido

    printf("Introduzca su nombre: ");                                   //Se almacena el nombre del usuario por precaución.
    scanf("%s" , nombre);

    printf("Desea iniciar la conexion? Responda [S/N]: ");                       //Se consulta con el usuario si desea iniciar una conexión
    getchar();                                                          //con otro usuario o por el contrario esperar a recibirla.
    iniciador = (unsigned char) getchar();

    if(iniciador == Y_STR) Conectar_Enclaves(INICIADOR, sock);          //Este cliente inicia la negociación de clave simétrica.
    else if(iniciador == N_STR) Conectar_Enclaves(RECEPTOR, sock);      //Este cliente espera la negociación de clave simétrica.
    else return 1;

    //------------------------------------------------------------------

      //printf("El rol %s es %d\n",SIP_USER, iniciador );
      //autoset_key(global_eid, iniciador);

    //------------------------------------------------------------------
    
    for (;;) {
    char option[10];
 
    puts("Press 'h' to hangup all calls, 'm' for make one or 'q' to quit");
    if (fgets(option, sizeof(option), stdin) == NULL) {
    puts("EOF while reading stdin, will quit now..");
    break;
    }
 
    if (option[0] == 'q')
    break;
 
    if (option[0] == 'h')
    pjsua_call_hangup_all();

    if (option[0] == 'm'){

    char sip_dir[30];

    printf("Sip address to call: ");
    scanf("%s", sip_dir);

    printf("Direccion leida: %s", sip_dir);

    status = pjsua_verify_url(sip_dir);
    if (status != PJ_SUCCESS) error_exit("Invalid URL in argv", status);

    pj_str_t uri = pj_str(sip_dir);

    /*{
        const char* message = "Hello!";

        pj_str_t text_msg = pj_str((char*)message);

        status = pjsua_im_send(acc_id, &uri, NULL, &text_msg, NULL, NULL);

        if(status == PJ_SUCCESS) printf("Mensaje enviado con exito!\n");
    }*/

    status = pjsua_call_make_call(acc_id, &uri, 0, NULL, NULL, NULL);
    if (status != PJ_SUCCESS) error_exit("Error making call", status);
    }
    }
 
    /* Destroy pjsua */
    pjsua_destroy();                         //Si se ha salido del bucle principal ya no se necesita comunicación con el servidor
                                            //por tanto se cierra el socket.

/*##################################################################### MAIN-OUT*/


    sgx_destroy_enclave(global_eid);    //Función que destruye de manera segura el enclave.
                                        //Forma parte de la librería de Intel SGX(R).
    printf("Destroy\n");
    return 0;

}