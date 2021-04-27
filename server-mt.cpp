#include "common.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>
#include <set>
#include <vector>
#include <iostream>
#include <algorithm>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>

#define BUFSZ 1024

struct client_data {
    int csock;
    struct sockaddr_storage storage;
    std::set<std::string> tags;
};

std::vector<client_data *> clients;

//verifica se o caractere e invalido
int is_valid(char c) {
    return (c >= '0' && c <= '9')
    || (c >= 'A' && c <= 'Z')
    || (c >= 'a' && c <= 'z')
    || strchr(" ,.?!:;+-*/=@#$%()[]{}\n", c) != NULL;
}

//verifica se a mensagem contem caracteres invalidos
int message_validation(std::string msg) {
    for(auto it = msg.begin(); it != msg.end(); it++) {
        if(!is_valid(*it)) {
            return 0;
        }
    }

    return 1;
}

void disconnect_client(client_data* cdata) {
    close(cdata->csock);
    delete cdata;
}

void incomplete_message(client_data* cdata, std::string parcial_msg, size_t unsent_bytes);

void check_multiple_messages(client_data* cdata, std::string txt, size_t unsent_bytes);

void usage(int argc, char **argv) {
    printf("usage: %s <v4|v6> <server port>\n", argv[0]);
    printf("example: %s v4 51511\n", argv[0]);
    exit(EXIT_FAILURE);
}

//verifica se o client fornecido esta inscrito na tag
int has_tag(client_data* cdata, std::string tag) {
    if(cdata->tags.find(tag) != cdata->tags.end()) {
        return 1;
    }

    return 0;
}

//inscreve o client na tag fornecida
void subscribe(client_data *cdata, std::string tag) {
    char buf[BUFSZ];
    memset(buf, 0, BUFSZ);
    
    //insere a tag no set de tags do usuario e envia mensagem de confirmacao
    if(!has_tag(cdata, tag)) {
        cdata->tags.insert(tag);
        
        tag = "subscribed +" + tag + "\n";
        std::remove(tag.begin(), tag.end(), '\0'); //remove \0 da string
        send(cdata->csock, &tag[0], tag.size(), 0);   
    } else {
        tag = "already subscribed +" + tag + "\n";
        std::remove(tag.begin(), tag.end(), '\0');
        send(cdata->csock, &tag[0], tag.size(), 0);   
    }
}

//desinscreve o client da tag fornecida
void unsubscribe(client_data *cdata, std::string tag) {
    char buf[BUFSZ];
    memset(buf, 0, BUFSZ);
    
    //remove a tag do set e envia mensagem de confirmacao
    if(has_tag(cdata, tag)) {
        cdata->tags.erase(tag);
        
        tag = "unsubscribed -" + tag + "\n";
        std::remove(tag.begin(), tag.end(), '\0'); //remove \0
        send(cdata->csock, &tag[0], tag.size(), 0);   
    } else {
        tag = "not subscribed -" + tag + "\n";
        std::remove(tag.begin(), tag.end(), '\0');        
        send(cdata->csock, &tag[0], tag.size(), 0);   
    }
}

/* Insere os clientes que contem a tag fornecida em um set de subscribers. 
Essa funcao e usada para evitar que um cliente receba a mesma mensagem mais de uma vez */
void insert_subscribers(std::set<client_data *>* subscribers, std::string tag) {
    for(auto it = clients.begin(); it != clients.end(); ++it) {
        if(has_tag((*it), tag)) {
            subscribers->insert((*it));
        }
    }

}

//Encontra todos os clientes que estao inscritos em pelo menos uma das tags da mensagem
std::set<client_data *> find_subscribers(std::string txt) {
    std::set<client_data *> subscribers;
    std::string delimiter = " "; /* usamos espaco como delimitador pois cada tag precisa estar cercada 
                                    por espaco ou comeco/fim da mensagem */ 

    size_t pos = 0;
    std::string tag;
    
    //para cada delimitador encontrado verificamos se a palavra formada e uma tag
    while ((pos = txt.find(delimiter)) != std::string::npos) {
        tag = txt.substr(0, pos); //pegamos a palavra formada

        if(txt[0] == '#') {
            //pegamos a tag e inserimos seus subscribers
            tag = tag.substr(1, pos);
            insert_subscribers(&subscribers, tag);
        }
        
        txt.erase(0, pos + delimiter.length()); /* ja sabemos se a palavra atual e ou nao uma tag, 
                                                entao podemos apaga-la e continuar a busca no restante */
    }

    //verifica o caso em que temos uma tag no final da mensagem
    tag = txt.substr(0, pos);

    if(txt[0] == '#') {
        tag = tag.substr(1, pos);
        insert_subscribers(&subscribers, tag);        
    }

    return subscribers;
}

void send_messages(client_data* cdata, std::set<client_data *> subscribers, std::string msg) {
    msg += "\n";
    std::remove(msg.begin(), msg.end(), '\0');    

    /* envia a mensagem para cada cliente inscrito em uma de suas tags,
    com excecao do cliente que enviou a mensagem em si */
    for(auto it = subscribers.begin(); it != subscribers.end(); ++it) {
        if((*it)->csock != cdata->csock) {    
            send((*it)->csock, &msg[0], msg.size(), 0);
        }
    }
}

//desconecta todos os usuarios e termina a execucao do servidor
void kill_server() {
    for(auto it = clients.begin(); it != clients.end(); ++it) {
        disconnect_client(*it);
    }

    exit(EXIT_SUCCESS);
}

/* avaliamos a mensagem recebida, para saber se e uma mensagem de sub/unsub 
ou se e uma mensagem a repassar para outros clientes */
void parse_msg(client_data *cdata, std::string msg) {
    std::string txt;

    if(msg[0] == '+') {
        txt = msg.substr(1, std::string::npos); //remove o '+' da tag
        subscribe(cdata, txt);
    } else if(msg[0] == '-') {
        txt = msg.substr(1, std::string::npos); //remove o '-' da tag
        unsubscribe(cdata, txt);
    } else if(msg == "##kill") {
        kill_server();
    } else {
        txt = msg;
        auto subscribers = find_subscribers(txt);
        send_messages(cdata, subscribers, msg);
    }

}

//trata os casos em que temos mais de um \n por recv e quando temos um recv com mensagens incompletas
void check_multiple_messages(client_data* cdata, std::string txt, size_t unsent_bytes) {
    std::string delimiter = "\n";
    std::string msg;
    size_t pos = 0;
    
    /* Itera pela string recebida buscando o fim de mensagens(\n). 
    Envia cada mensagem completa encontrada */
    while((pos = txt.find(delimiter)) != std::string::npos) {
        unsent_bytes = 0;
        msg = txt.substr(0, pos);

        if(msg.size() > 500) {
            break;
        }

        parse_msg(cdata, msg);
        txt.erase(0, pos + delimiter.length()); //remove a mensagem enviada da string restante 
    }
    
    //Caso ainda existam caracteres apos o ultimo \n, temos uma mensagem incompleta
    if(!txt.empty()) {
        unsent_bytes += txt.size();

        //se temos uma mensagem incompleta com mais do que 500 bytes, desconectamos o client
        if(unsent_bytes > 500) {
            disconnect_client(cdata);
            pthread_exit(EXIT_SUCCESS);
        }

        incomplete_message(cdata, txt, unsent_bytes); //buscamos os proximos caracteres da mensagem
    } 

}

//recebe o proximo recv de uma mensagem incompleta
void incomplete_message(client_data* cdata, std::string parcial_msg, size_t unsent_bytes) {
    char buf[BUFSZ];

    memset(buf, 0, BUFSZ);
    size_t count = recv(cdata->csock, buf, BUFSZ - 1, 0);

    if(count == 0) {
        disconnect_client(cdata);
        pthread_exit(EXIT_SUCCESS);
    }

    std::string msg(buf);
    msg = parcial_msg + msg; //concatena a nova mensagem com a mensagem incompleta ja recebida

    check_multiple_messages(cdata, msg, unsent_bytes); //tenta enviar a nova mensagem
}

//cria uma thread para o client
void * client_thread(void *data) {
    struct client_data *cdata = (struct client_data *)data;
    struct sockaddr *caddr = (struct sockaddr *)(&cdata->storage);

    char caddrstr[BUFSZ];
    addrtostr(caddr, caddrstr, BUFSZ);
    printf("[log] connection from %s\n", caddrstr);

    char buf[BUFSZ];

    //permanecemos no while ate que o client seja desconectado
    while(1) {
        memset(buf, 0, BUFSZ);
        size_t count = recv(cdata->csock, buf, BUFSZ - 1, 0);

        if(count == 0) {
            break;
        }

        printf("[msg] %s, %d bytes: %s\n", caddrstr, (int)count, buf);

        std::string msg(buf);
        if(!message_validation(msg)) {
            break;
        }

        size_t unsent_bytes = 0; //variavel pra armazenar tamanho de mensagens individuais
        check_multiple_messages(cdata, msg, unsent_bytes); //verifica se recebemos mais de um \n e envia
    }

    disconnect_client(cdata);
    pthread_exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    struct sockaddr_storage storage;
    server_sockaddr_init(argv[1], &storage);

    int s;
    s = socket(storage.ss_family, SOCK_STREAM, 0);
    if (s == -1) {
        logexit("socket");
    }

    int enable = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) != 0) {
        logexit("setsockopt");
    }

    struct sockaddr *addr = (struct sockaddr *)(&storage);
    if (bind(s, addr, sizeof(storage)) != 0) {
        logexit("bind");
    }

    if (listen(s, 10) != 0) {
        logexit("listen");
    }

    char addrstr[BUFSZ];
    addrtostr(addr, addrstr, BUFSZ);
    printf("bound to %s, waiting connections\n", addrstr);

    while (1) {
        struct sockaddr_storage cstorage;
        struct sockaddr *caddr = (struct sockaddr *)(&cstorage);
        socklen_t caddrlen = sizeof(cstorage);

        int csock = accept(s, caddr, &caddrlen);
        if (csock == -1) {
            logexit("accept");
        }

	    struct client_data *cdata = new client_data; //cria o client
        if (!cdata) {
	        logexit("malloc");
	    }
	
        cdata->csock = csock;
	    memcpy(&(cdata->storage), &cstorage, sizeof(cstorage));

        clients.push_back(cdata);

        //pega o ultimo client do vector, que acabamos de inserir
        auto client_atual = clients.end();
        client_atual--;

        pthread_t tid;
        pthread_create(&tid, NULL, client_thread, *client_atual); //cria thread para o cliente criado
    }

    exit(EXIT_SUCCESS);
}
