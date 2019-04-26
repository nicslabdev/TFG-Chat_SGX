// - LIBRERIAS NECESARIAS PARA SGX ----------------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>

#include <time.h>

# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

// - LIBRERÍAS PARA PJSIP -------------------------------------------------------------------------------------------

#include <pjsua-lib/pjsua.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "pj_enclave.h"

// - LIBRERIAS EXTRAS PARA EL DESARROLLO ----------------------------------------------------------------------------

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

//-------------------------------------------------------------------------------------------------------------------

#define MAX_BUF_LEN 1024           //Tamano maximo de las tramas
#define SGX_AESGCM_MAC_SIZE 16     //Tamano del vertor de atestacion MAC
#define SGX_AESGCM_IV_SIZE 12      //Tamano del vector aleatorio IV

#include "sgx_tcrypto.h"  //Libreria criptografica de SGX

#include<sys/socket.h>    //Para uso de la función socket
#include<arpa/inet.h>     //Para uso de la definición inet_addr

#define INICIADOR 1       //Identificador del iniciador de la conexión
#define RECEPTOR  0       //Identificador del receptor de la conexión

#define Y_STR 'S'         //Variable de comparación 'S' (Sí)
#define N_STR 'N'         //Variable de comparación 'N' (No)

unsigned t0, t1;          //Variables para medir tiempo de procesamiento.

//Funciones y variables propias de la inicialización del enclave.

    sgx_enclave_id_t global_eid = 0;     //EID: Código de identificación del enclave para su posterior llamada.

    typedef struct _sgx_errlist_t {     //Estructura contenedora de errores de Intel SGX(R).
        sgx_status_t err;
        const char *msg;
        const char *sug;
    } sgx_errlist_t;

    //Listado de errores posibles en tiempo de ejecución y sugerencia asociada.
    static sgx_errlist_t sgx_errlist[] = {
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

    void print_error_message(sgx_status_t ret){   //Función que muestra el error que puediese haber ocurrido.
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


    int inicializar_enclave(void){          //Función de inicialización del enclave.

        char token_path[MAX_PATH] = {'\0'};
        sgx_launch_token_t token = {0};
        sgx_status_t ret = SGX_ERROR_UNEXPECTED;
        int updated = 0;
        
        const char *home_dir = getpwuid(getuid())->pw_dir;
        
        if (home_dir != NULL &&      //Se intenta recuperar un TOKEN guardado en $HOME
           (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
            strncpy(token_path, home_dir, strlen(home_dir));
            strncat(token_path, "/", strlen("/"));
            strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
        } else {
            strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));                 
        }

        FILE *fp = fopen(token_path, "rb");
        //En el caso de no encontrarse se crea dicho TOKEN.
        if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) { 
            printf("Warning: Error al cargar/abrir el archivo token \"%s\".\n", token_path); 
        }

        if (fp != NULL) {    
            size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp); //Se lee el el contenido del TOKEN.
            if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {

                memset(&token, 0x0, sizeof(sgx_launch_token_t));
                printf("Warning: Token inválido leido desde \"%s\".\n", token_path); 
                //Si el TOKEN es invalido se borra su contenido.
            }
        }

        //Se crea un enclave.
        ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
        if (ret != SGX_SUCCESS) {
            print_error_message(ret);
            if (fp != NULL) fclose(fp);
            return -1;
        }

            
        if (updated == FALSE || fp == NULL) {       //Se guarrda el TOKEN correspondiente a este enclave.
            if (fp != NULL) fclose(fp);
            return 0;
        }

        fp = freopen(token_path, "wb", fp);        //Se reabre el TOKEN con capacidad de lectura-escritura.
        if (fp == NULL) return 0;
        size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
        if (write_num != sizeof(sgx_launch_token_t))
            printf("Warning: Error al guardar el token en \"%s\".\n", token_path);
        fclose(fp);
        return 0;
    }

    void ocall_print_string(const char *str){       //Funcion OCALL usada para debug

        printf("%s", str);
    }

//Funciones de testeo:

    void print_hex(uint8_t* array, size_t len){                //Muestra con formateo hexadecimal
                                                               //la información de un array uint8_t
        int i;
            for (i = 0; i < (int) len; i++) {
                printf("%02x ", array[i]);
            }
            printf("\n\n");
    }

    void print_hex(uint32_t* array, size_t len){               //Muestra con formateo hexadecimal
                                                               //la información de un array uint32_t
    	printf("\n");
        int i;
        for (i = 0; i < (int) len; i++) {
            printf("%02x ", array[i]);
        }
        printf("\n\n");
    }


    uint8_t* l2bswap8_t(const uint8_t *array, size_t tam){      //Realiza un swap de little-endian
                                                                //a big-endian de un array uint8_t
    	uint8_t* aux = (uint8_t*) malloc(tam);

    	int a = tam-1;
        	for(int i=0; i<tam; i++){
    	
    		aux[a] = array[i];
    		a-=1;

       	}

    	return aux;
    }

    uint32_t* l2bswap32_t(const uint32_t *array, size_t tam){   //Realiza un swap de little-endian
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

//Esta es la funcion encargada de realizar la negociacion de claves entre los enclaves. 
void Conectar_Enclaves(int tipo_conexion, int sock){  

    sgx_ec256_public_t pu_A, pu_B;

    new_keypair(global_eid, &pu_A, sizeof(pu_A)); //Generacion de par de claves en el enclave

    unsigned char bytes[64];

    if(tipo_conexion == 1){

        //Si el cliente inicia la conexion envia primero su clave publica

        puts("Este cliente inicia la conexión");

        memcpy(bytes, pu_A.gx, 32);
        memcpy(bytes+32, pu_A.gy, 32);

        if( send(sock, bytes , sizeof(bytes) , 0) < 0)
        {
            puts("Send Pu_A failed");
        }else printf("Pu_A enviada correctamente\n");

        //Luego recibe la clave publica del otro sistema
        if( recv(sock, bytes , sizeof(bytes) , 0) < 0)
        {
            puts("recv Pu_B failed");
        }else printf("Pu_B recibida correctamente\n");

        memcpy(pu_B.gx, bytes, 32);
        memcpy(pu_B.gy, bytes+32, 32);

        //Por ultimo comprueba los datos recibidos realizando el computo de la clave simetrica
        computeDHKey(global_eid, &pu_B, sizeof(pu_B));

    }else if(tipo_conexion == 0){

        //Si el cliente no inicia la conexion espera recibir primero
        puts("Este cliente espera la conexión");

        if( recv(sock, bytes , sizeof(bytes) , 0) < 0)
        {
            puts("recv Pu_B failed");
        }else printf("Pu_B recibida correctamente\n");

        memcpy(pu_B.gx, bytes, 32);
        memcpy(pu_B.gy, bytes+32, 32);

        memcpy(bytes, pu_A.gx, 32);
        memcpy(bytes+32, pu_A.gy, 32);

        //Comprueba los datos recibidos realizando el computo de la clave
        //simetrica y envia su clave publica
        computeDHKey(global_eid, &pu_B, sizeof(pu_B)); 

        if( send(sock, bytes , sizeof(bytes) , 0) < 0)
        {
            puts("Send Pu_A failed");
        }else printf("Pu_A enviada correctamente\n");

    }else puts("ERROR EN LA NEGOCIACIÓN");
}                                                                    

//Funcion para codificar datos en el enclave de forma segura y enviarlos por el socket
int envio_cod(int sock , char *mensaje){

    size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + strlen(mensaje)); 
    char *encMessage = (char *) malloc((encMessageLen+1)*sizeof(char));

    //t0 = clock();

    sgx_encrypt(global_eid, mensaje, strlen(mensaje), encMessage, encMessageLen);

    //t1 = clock();
    //double time = (double(t1-t0)/CLOCKS_PER_SEC);             //Calculo de tiempo de procesamiento
    //printf("Tiempo de codificado: %.16g segundos \n", time);  //Usado en debug

    encMessage[encMessageLen] = '\0';

    //puts("\nSend: ");                                 //Muestra la trama cifrada, usada en debug
    //print_hex((uint8_t*)encMessage, encMessageLen);

    return send(sock, encMessage, encMessageLen, 0); 
}

//Funcion que recibe datos desde el socket y los decodifica en el enclave de forma segura
int recepcion_decod(int sock , char *mensaje){

    char *encMessage = (char *) malloc((MAX_BUF_LEN)*sizeof(char));

    int received = recv(sock, encMessage, MAX_BUF_LEN, 0);

    //puts("\nRecv: ");                             //Muestra la trama recibida (codificada)
    //print_hex((uint8_t*)encMessage, received);    //Usado en debug

    size_t decMessageLen = (received - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE);

    char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));

    //t0 = clock();

    sgx_decrypt(global_eid, encMessage, received, decMessage, decMessageLen);

    //1 = clock();
    //double time = (double(t1-t0)/CLOCKS_PER_SEC);             //Calculo de tiempo de procesamiento
    //printf("Tiempo de decodificado: %.16g segundos \n", time);//Usado en debug

    decMessage[decMessageLen] = '\0';

    memcpy(mensaje, decMessage, strlen(decMessage)+1);

    return received;                   
}

//---------------------------------------------------------------------------- PJSUA Functions

 /* Callback example: */
 static void Encoder_(char *decMessageIn, size_t lenIn, char *encMessageOut, size_t &lenOut){
    printf("This is a callback to SGX Encoder with length: %d \n", lenIn);

    //size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + lenOut);
    //print_hex((uint8_t*) decMessageIn, lenIn);
    
    //print_log((uint8_t*)decMessageIn, lenIn);

    /*memcpy(encMessageOut, decMessageIn, lenIn);
    
    if(ctr_sync >= 50){
      memcpy(encMessageOut, NULL_ARRAY, 16);
      ctr_sync = 0;
    }else ctr_sync++;*/

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
 
//----------------------------------------------------------------  PJSUA main

//Funcion main de nuestra aplicacion
int SGX_CDECL main(int argc, char *argv[]){

    (void)(argc);
    (void)(argv);

    char *SIP_USER;
    char *SIP_PASSWD;

    if(inicializar_enclave() < 0){           //Función que inicializa el enclave
        return -1;                           //Si la función falla el cliente se cierra pues necesita del enclave.
    }

/*##################################################################### MAIN-IN*/

    fd_set master;    //Descriptor de ficheros general
    fd_set read_fds;  //Descriptor de ficheros temporal *select()
    int fdmax;        //Numero del descriptor de fichero maximo


    int sock;                                          //Variable para almacenar el socket.
    struct sockaddr_in server;                         //Estructura que almacena la dirección del servidor.
    char message[1000] , server_reply[2000];           //Arrays de caracteres para los mensajes enviados y recibidos.

    char nombre[512];                                  //Array de caracteres para el nombre del usuario
    char iniciador;                                    //Variable para almacenar que tipo de conexión desea el usuario.          


    sock = socket(AF_INET , SOCK_STREAM , 0);          //Intento de creación de un socket de comunicación.
    if (sock == -1)                                    //Si el socket no puede crearse se produce un cierre del cliente.
    {
        printf("Could not create socket");
    }
    puts("Socket created");
     
    server.sin_addr.s_addr = inet_addr("127.0.0.1");   //Dirección del servidor (Loopback)
    server.sin_family = AF_INET;                       //Protocolo de Red TCP
    server.sin_port = htons( 9035 );                   //Puerto de escucha predefinido.
 
    //Se realiza un intento de conexión con el servidor definido.
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");            //Si el servidor no responde se produce un cierre del cliente.
        return 1;
    }
     
    puts("Connected\n");         //indica que la conexión con el servidor se ha establecido

    FD_ZERO(&master);           //Se limpian los grupos de ficheros descriptores
    FD_ZERO(&read_fds);

    FD_SET(sock, &master);      //Se incluye en el descriptor master el socket del servidor
    FD_SET(0, &master);         //y el descriptor del teclado o lectura estandar

    fdmax = sock;

    printf("Introduzca su nombre: ");         //Se almacena el nombre del usuario para futuras implementaciones.
    scanf("%s" , nombre);

    printf("Desea iniciar la conexion? Responda [S/N]: ");    //Se consulta con el usuario si desea iniciar una conexión
    getchar();                                                //con otro usuario o por el contrario esperar a recibirla.
    iniciador = (unsigned char) getchar();

    if(iniciador == Y_STR){
        Conectar_Enclaves(INICIADOR, sock);    //Este cliente inicia la negociación de clave simétrica.
        autoset_key(global_eid, INICIADOR);
    }else if(iniciador == N_STR){
        Conectar_Enclaves(RECEPTOR, sock);     //Este cliente espera la negociación de clave simétrica.
        autoset_key(global_eid, RECEPTOR);
    }else return 1;

//---------------------------------------------------------------------------------------------------------------------------

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

  if(iniciador == Y_STR) random_number = rand() % 100 + 1;
  cfg.port = rand()%6060 + random_number;


  printf("Application uses port %d", 6060 + random_number);

  status = pjsua_transport_create(PJSIP_TRANSPORT_UDP, &cfg, NULL);
  /*if (status != PJ_SUCCESS && status == 120098){
    do{
        cfg.port = rand()%6060 + random_number;
        status = pjsua_transport_create(PJSIP_TRANSPORT_UDP, &cfg, NULL);    
    }while(status != 120098);
  }*/
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

//--------------------------------------------------------------------
  int rol = (strcmp(SIP_USER, (const char*)"7002") == 0) ? 1 : 0;


  printf("El rol %s es %d\n",SIP_USER, rol );
  autoset_key(global_eid, rol);

  //pjsua_buddy_id  buddy;

  //pjsua_buddy_config bd_cfg;

//---------------------------------------------------------------------

  /* Wait until user press "q" to quit. */
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
  pjsua_destroy();


//-----------------------------------
     
    close(sock);        //Si se ha salido del bucle principal ya no se necesita comunicación con el servidor
                        //por tanto se cierra el socket.

/*##################################################################### MAIN-OUT*/


    sgx_destroy_enclave(global_eid);    //Función que destruye de manera segura el enclave.
                                        //Forma parte de la librería de Intel SGX(R).

    return 0;

}