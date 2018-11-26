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


// - LIBRERIAS EXTRAS PARA EL DESARROLLO ----------------------------------------------------------------------------

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

//Funcion main de nuestra aplicacion
int SGX_CDECL main(int argc, char *argv[]){

    (void)(argc);
    (void)(argv);


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

    if(iniciador == Y_STR) Conectar_Enclaves(INICIADOR, sock);    //Este cliente inicia la negociación de clave simétrica.
    else if(iniciador == N_STR) Conectar_Enclaves(RECEPTOR, sock);//Este cliente espera la negociación de clave simétrica.
    else return 1;

    while(1){             //Bucle de ejecución mientras se tiene comunicación con el servidor.

        read_fds = master; //Se copia el descriptor master para protegerlo de modificaciones
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(4);
        }

        //Si select() desbloquea es porque existe algun cambio
        for(int i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) { 
                if (i == 0) {

                    //Se lee desde teclado, se codifica y se envia al servidor
                    gets(message);

                    if( envio_cod(sock , message) < 0){
                        puts("Send failed");
                        return 1;
                    }

                }else if (i == sock){
                    
                    //Se recibe del servidor, se decodifica y se muestra por pantalla
                    if( recepcion_decod(sock , server_reply) < 0){
                        puts("recv failed");
                        break;
                    }
                    puts(server_reply);

                }
            }
        }

    }
     
    close(sock);        //Si se ha salido del bucle principal ya no se necesita comunicación con el servidor
                        //por tanto se cierra el socket.

/*##################################################################### MAIN-OUT*/


    sgx_destroy_enclave(global_eid);    //Función que destruye de manera segura el enclave.
                                        //Forma parte de la librería de Intel SGX(R).

    return 0;

}