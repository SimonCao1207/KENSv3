/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

namespace E {

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {}

void TCPAssignment::finalize() {}

int TCPAssignment:: _syscall_socket(int pid) {
  int fd = this->createFileDescriptor(pid);
  if (fd != -1){
    std::pair<int, int> pairKey {fd, pid};
    pairKeySet.insert(pairKey);
    pairKeyToSucket[pairKey] = Sucket(pairKey, TCP_CLOSED); 
  }
  return fd;
}

void TCPAssignment:: syscall_socket(UUID syscallUUID, int pid, int type, int protocol){
  this->returnSystemCall(syscallUUID, _syscall_socket(pid));
}

std::pair<uint32_t, uint16_t> fromAddrInfoToAddr (std::pair<sockaddr, socklen_t> addrInfo) {  
  sockaddr_in address = *((sockaddr_in *) &addrInfo.first);
  uint32_t ip = ntohl(address.sin_addr.s_addr);
  uint16_t port = ntohs(address.sin_port);
  return {ip, port};
}

int TCPAssignment:: _syscall_bind(int sockfd, int pid, struct sockaddr *addr, socklen_t addrlen){

  std::pair<sockaddr, socklen_t> addrInfo = {*addr, addrlen};

  std::pair<uint32_t, uint16_t> currAddress = fromAddrInfoToAddr(addrInfo);
  std::pair<uint32_t, uint16_t> addressZero = {0U, currAddress.second};

  if (bindedAddress.count(currAddress) || bindedAddress.count(addressZero)) {
    return -1;
  }  
  std::pair<int, int> pairKey = {sockfd, pid};
  pairKeyToAddrInfo[pairKey] = addrInfo;
  bindedAddress.insert(currAddress);
  return 0;
}

void TCPAssignment:: syscall_bind( UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen){
  std::pair<int, int> pairKey = {sockfd, pid};
  if (!pairKeySet.count(pairKey) || pairKeyToAddrInfo.count(pairKey)){
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  this->returnSystemCall(syscallUUID, _syscall_bind(sockfd, pid, addr, addrlen));
}

void TCPAssignment:: syscall_getsockname( UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) {
  std::pair<int, int> pairKey {sockfd, pid};
  if (pairKeySet.find(pairKey) == pairKeySet.end() || pairKeyToAddrInfo.find(pairKey) == pairKeyToAddrInfo.end()){
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  *addr = pairKeyToAddrInfo[pairKey].first;
  *addrlen = pairKeyToAddrInfo[pairKey].second;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment:: _sendPacket(Sucket sucket, uint8_t flag){
  // TODO: Create a packet and send to IP layer
  return;
}

void TCPAssignment:: syscall_close(UUID syscallUUID, int pid, int sockfd){
  std::pair<int, int> pairKey {sockfd, pid}; 
  if (pairKeySet.find(pairKey) == pairKeySet.end()){
    this->returnSystemCall(syscallUUID, -1);
    return; 
  }

  Sucket sucket = pairKeyToSucket[pairKey];
  TCP_STATE state = sucket.state;
  switch (state)
  {
    case TCP_ESTABLISHED:
      _sendPacket(sucket, TH_FIN | TH_ACK);
      sucket.state = TCP_FIN_WAIT_1;
      break;

    case TCP_CLOSE_WAIT:
      _sendPacket(sucket, TH_FIN | TH_ACK);
      sucket.state = TCP_LAST_ACK;
      break;
    
    default:
      if (pairKeyToAddrInfo.find(pairKey) != pairKeyToAddrInfo.end()){
        std::pair<sockaddr, socklen_t> addrInfo = pairKeyToAddrInfo[pairKey];
        std::pair<uint32_t, uint16_t> addr = fromAddrInfoToAddr(addrInfo);
        bindedAddress.erase(addr);
        pairKeyToAddrInfo.erase(pairKey);
      }
      pairKeySet.erase(pairKey);
      pairKeyToSucket.erase(pairKey);
      break;
  }

  this->removeFileDescriptor(pid, sockfd);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  (void)syscallUUID;
  (void)pid;

  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
                         std::get<int>(param.params[1]));
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    break;
  case READ:
    // this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
    //                    std::get<void *>(param.params[1]),
    //                    std::get<int>(param.params[2]));
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    break;
  case CONNECT:
    // this->syscall_connect(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    break;
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    break;
  case ACCEPT:
    // this->syscall_accept(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND:
    this->syscall_bind(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case GETPEERNAME:
    // this->syscall_getpeername(
        // syscallUUID, pid, std::get<int>(param.params[0]),
        // static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        // static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
