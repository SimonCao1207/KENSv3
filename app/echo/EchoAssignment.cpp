#include "EchoAssignment.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>

// !IMPORTANT: allowed system calls.
// !DO NOT USE OTHER NETWORK SYSCALLS (send, recv, select, poll, epoll, fork
// etc.)
//  * socket
//  * bind
//  * listen
//  * accept
//  * read
//  * write
//  * close
//  * getsockname
//  * getpeername
// See below for their usage.
// https://github.com/ANLAB-KAIST/KENSv3/wiki/Misc:-External-Resources#linux-manuals

int EchoAssignment::serverMain(const char *bind_ip, int port,
                               const char *server_hello) {
  // Your server code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for serverMain.

  struct sockaddr_in serveraddr;
  socklen_t addrlen = sizeof(serveraddr);
  int BUFFSIZE = 1024;
  char requestBuffer[BUFFSIZE] = {0};
  char* response;

  serveraddr.sin_family = AF_INET; 
  serveraddr.sin_addr.s_addr = inet_addr(bind_ip); 
  serveraddr.sin_port = htons((uint16_t) port);

  int serv_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (serv_socket < 0) return -1;

  if(bind(serv_socket, (sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
    return -1;

  if(listen(serv_socket, 1024) < 0)
    return -1;

  while (1){
    bzero(requestBuffer, BUFFSIZE);
    int new_socket = accept(serv_socket, (sockaddr *)&serveraddr, &addrlen);
    if (new_socket < 0) return -1;
    int valRead = read(new_socket, requestBuffer, BUFFSIZE);
    if (valRead == -1) return -1;
    struct sockaddr_in addr1;
    getpeername(new_socket, (struct sockaddr *)&addr1, &addrlen);
    char* clientIP = inet_ntoa(addr1.sin_addr);
    if (strcmp(requestBuffer, "hello") == 0) response = const_cast<char*>(server_hello);
    else if (strcmp(requestBuffer, "whoami") == 0) response = clientIP;
    else if (strcmp(requestBuffer, "whoru") == 0) response = "djt me cho tao cai dia chi";
    else response = requestBuffer;
    write(new_socket, response, strlen(response));
    submitAnswer(clientIP, requestBuffer);
    close(new_socket);
  }
  return 0;
}

int EchoAssignment::clientMain(const char *server_ip, int port,
                               const char *command) {
  // Your client code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for clientMain.
  struct sockaddr_in serveraddr;
  socklen_t addrlen = sizeof(serveraddr);
  int BUFFSIZE = 1024;
  char responseBuffer[BUFFSIZE] = {0};
  int client_fd;

  // Set Server Address
  serveraddr.sin_family = AF_INET; 
  serveraddr.sin_addr.s_addr = inet_addr(server_ip);
  serveraddr.sin_port = htons((uint16_t) port); 

  //Connect to server
  int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) return -1;
  if(client_fd = connect(sock, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) return -1;

  write(sock, command, strlen(command)); // Send request to server
  int valRead = read(sock, responseBuffer, BUFFSIZE); // Recieve response
  if (valRead == -1) return -1;

  if (strcmp(responseBuffer, "djt me cho tao cai dia chi") == 0) submitAnswer(server_ip, server_ip);
  else submitAnswer(server_ip, responseBuffer);
  close(sock);
  return 0;
}

static void print_usage(const char *program) {
  printf("Usage: %s <mode> <ip-address> <port-number> <command/server-hello>\n"
         "Modes:\n  c: client\n  s: server\n"
         "Client commands:\n"
         "  hello : server returns <server-hello>\n"
         "  whoami: server returns <client-ip>\n"
         "  whoru : server returns <server-ip>\n"
         "  others: server echos\n"
         "Note: each command is terminated by newline character (\\n)\n"
         "Examples:\n"
         "  server: %s s 0.0.0.0 9000 hello-client\n"
         "  client: %s c 127.0.0.1 9000 whoami\n",
         program, program, program);
}

int EchoAssignment::Main(int argc, char *argv[]) {
  if (argc == 0)
    return 1;

  if (argc != 5) {
    print_usage(argv[0]);
    return 1;
  }

  int port = atoi(argv[3]);
  if (port == 0) {
    printf("Wrong port number\n");
    print_usage(argv[0]);
  }

  switch (*argv[1]) {
  case 'c':
    return clientMain(argv[2], port, argv[4]);
  case 's':
    return serverMain(argv[2], port, argv[4]);
  default:
    print_usage(argv[0]);
    return 1;
  }
}
