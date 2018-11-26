#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define PORT "9035"   //Puerto de escucha del servidor


// Funcion para discernir entre conexiones IPv4 e IPv6
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(void)
{
    fd_set master;    //Descriptor de ficheros general
    fd_set read_fds;  //Descriptor de ficheros temporal *select()
    int fdmax;        //Numero del descriptor de fichero maximo

    int listener;     //Descriptor de fichero socket de escucha del servidor
    int newfd;        //Descriptor de fichero de las conexiones entrantes
    struct sockaddr_storage remoteaddr; //Direccion del cliente conectado
    socklen_t addrlen;

    char buf[1024];    //Buffer de datos recibidos
    int nbytes;

	char remoteIP[INET6_ADDRSTRLEN];

    int yes=1;        
    int i, j, rv;

	struct addrinfo hints, *ai, *p;

    FD_ZERO(&master);    //Limpieza de los grupos descriptores general y temporal
    FD_ZERO(&read_fds);

	
	memset(&hints, 0, sizeof hints);   //Configuracion del socket del servidor
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((rv = getaddrinfo(NULL, PORT, &hints, &ai)) != 0) {
		fprintf(stderr, "selectserver: %s\n", gai_strerror(rv));
		exit(1);
	}
	
    //Creacion del socket de comunicaciones
	for(p = ai; p != NULL; p = p->ai_next) {       
    	listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (listener < 0) { 
			continue;
		}
		
		//Esta funcion evita el recurrente mensaje de: "bind already in use"
		setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

		if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
			close(listener);
			continue;
		}

		break;
	}

    //Error a la hora de asociar un puerto con bind
	if (p == NULL) {
		fprintf(stderr, "selectserver: failed to bind\n");
		exit(2);
	}

	freeaddrinfo(ai); 

    //Inicializacion de la cola de escucha del servidor con 2 puestos
    if (listen(listener, 2) == -1) {
        perror("listen");
        exit(3);
    }

    //Introduccion del descriptor de fichero de la cola en el grupo de descriotores master
    FD_SET(listener, &master);

    //Es importante actualizar el fdmax con el descriptor mas grande incluido
    fdmax = listener; //En este caso solo tenemos la cola de peticiones de conexion
    
    //Bucle principal.
    while(true){

        read_fds = master; //Se copia el descriptor master para protegerlo de modificaciones

        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(4);
        }

        //Si select() desbloquea es porque existe algun cambio
        for(i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) {
                if (i == listener) {

                    //Nueva conexion entrante
                    addrlen = sizeof remoteaddr;
					newfd = accept(listener,
						(struct sockaddr *)&remoteaddr,
						&addrlen);

					if (newfd == -1) {
                        perror("accept");
                    } else {
                        FD_SET(newfd, &master); //Se incluye en el descriptor general
                        if (newfd > fdmax) {    //se actualiza fdmax si es necesario
                            fdmax = newfd;
                        }
                        printf("selectserver: new connection from %s on "
                            "socket %d\n",
							inet_ntop(remoteaddr.ss_family,
								get_in_addr((struct sockaddr*)&remoteaddr),
								remoteIP, INET6_ADDRSTRLEN),
							newfd);
                    }
                } else {
                    
                    //Datos de entrada se un cliente ya conectado
                    if ((nbytes = recv(i, buf, sizeof buf, 0)) <= 0) {
                        //Se leen 0bytes del cliente
                        if (nbytes == 0) {
                            //Cliente ha cerrado la conexion
                            printf("selectserver: socket %d hung up\n", i);
                        } else {
                            perror("recv");
                        }
                        close(i); //Se cierra el cescriptor de fichero del cliente.
                        FD_CLR(i, &master); //se elimina de descriptor master
                    } else {
                        // we got some data from a client

                        puts("\nTrama recibida: ");  //Funcion de debug de tramas
                        puts(buf);

                        for(j = 0; j <= fdmax; j++) {
                            //Reenvio de la trama recibida 
                            if (FD_ISSET(j, &master)) {
                                //Se reenvia a todos menos a la cola de entrada y
                                //al propio emisor de la trama
                                if (j != listener && j != i) {
                                    if (send(j, buf, nbytes, 0) == -1) {
                                        perror("send");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    return 0;
}
