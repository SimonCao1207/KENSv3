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
#include <random>

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

    PairKey pairKey {fd, pid};
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
PairKey pairKey {sockfd, pid};
if (pairKeySet.find(pairKey) == pairKeySet.end() || pairKeyToAddrInfo.find(pairKey) == pairKeyToAddrInfo.end()){
  this->returnSystemCall(syscallUUID, -1);
  return;
}

  *addr = pairKeyToAddrInfo[pairKey].first;
  *addrlen = pairKeyToAddrInfo[pairKey].second;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment:: _send_packet(Sucket& sucket, uint8_t flag){
  Packet packet = create_packet(sucket, flag);
  sendPacket(std::string("IPv4"), packet);
  return;
}

void TCPAssignment:: syscall_close(UUID syscallUUID, int pid, int sockfd){
  PairKey pairKey {sockfd, pid}; 
  if (pairKeySet.find(pairKey) == pairKeySet.end()){
    this->returnSystemCall(syscallUUID, -1);
    return; 
  }

  Sucket sucket = pairKeyToSucket[pairKey];
  TCP_STATE state = sucket.state;
  switch (state)
  {
    case TCP_ESTABLISHED:
      _send_packet(sucket, TH_FIN | TH_ACK);
      sucket.state = TCP_FIN_WAIT_1;
      break;

    case TCP_CLOSE_WAIT:
      _send_packet(sucket, TH_FIN | TH_ACK);
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

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  
  // DEBUG
  std::cerr << "Connecting pid=" << pid << ", sockfd=" << sockfd << '\n';
  
  PairKey pairKey {sockfd, pid};
  
  if(pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  Sucket &sucket = pairKeyToSucket[pairKey];

  sockaddr_in addr_in = * ((sockaddr_in*) addr);
  uint32_t dest_ip = ntohl(addr_in.sin_addr.s_addr);
  uint16_t dest_port = ntohs(addr_in.sin_port);
  sucket.remoteAddr = Address(dest_ip, dest_port);
  
  uint8_t flags = SYN_FLAG;
  
  Packet packet = create_packet(sucket, flags);

  // bool timeout = false;
  // TCPAssignment::addTimer(&timeout, 1000000000);
}

Packet TCPAssignment::create_packet(struct Sucket& sucket, uint8_t flags) {
  // packet data section = 0, currently not support data
  // DEBUG
  std::cerr << "Creating packet from ip=" << sucket.localAddr.ip << ",port=" << sucket.localAddr.port << " to ip=" << sucket.remoteAddr.ip << ",port=" << sucket.remoteAddr.port << " with flags=" << flags << '\n';

  size_t packet_size = 100;
  Packet packet (packet_size);

  uint8_t version_header_length = (4 << 4) + 20;
  packet.writeData(VERSION_HEADER_LENGTH_OFFSET, &version_header_length, VERSION_HEADER_LENGTH);

  uint16_t datagram_length = htons(40);
  packet.writeData(DATAGRAM_LENGTH_OFFSET, &datagram_length, DATAGRAM_LENGTH);

  uint32_t source_ip = htonl(sucket.localAddr.ip);
  uint16_t source_port = htons(sucket.localAddr.port);
  uint32_t dest_ip = htonl(sucket.remoteAddr.ip);
  uint16_t dest_port = htons(sucket.remoteAddr.port);

  packet.writeData(SOURCE_IP_OFFSET, &source_ip, SOURCE_IP_LENGTH);
  packet.writeData(DEST_IP_OFFSET, &dest_ip, DEST_IP_LENGTH);
  packet.writeData(SOURCE_PORT_OFFSET, &source_port, SOURCE_PORT_LENGTH);
  packet.writeData(DEST_PORT_OFFSET, &dest_port, DEST_PORT_LENGTH);

  uint32_t seq_num = htonl(sucket.seqNum);
  packet.writeData(SEQ_NUM_OFFSET, &seq_num, SEQ_NUM_LENGTH);

  // skip ack_num

  packet.writeData(FLAGS_OFFSET, &flags, FLAGS_LENGTH);
  
  // skip rwnd

  uint16_t zero_checksum = htons(0);
  packet.writeData(CHECKSUM_OFFSET, &zero_checksum, CHECKSUM_LENGTH);
  size_t length = 20;
  uint8_t* tcp_seg = (uint8_t*)malloc(length);
  packet.readData(SOURCE_PORT_OFFSET, tcp_seg, length); // tcp_seg = start index tcp_seg in mem
  uint16_t checksum = htons(~NetworkUtil::tcp_sum(source_ip, dest_ip, tcp_seg, length));

  packet.writeData(CHECKSUM_OFFSET, &checksum, CHECKSUM_LENGTH);
  
  // skip data

  return packet;
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
    this->syscall_connect(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
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

  uint8_t flags;
  uint8_t seqNum;
  uint32_t source_ip;
  uint16_t source_port;

  Packet packetClone = packet.clone(); 
  
  packet.readData(FLAGS_OFFSET, &flags, FLAGS_LENGTH);
  packet.readData(SEQ_NUM_OFFSET, &seqNum, SEQ_NUM_LENGTH);
  packet.readData(SOURCE_IP_OFFSET, &source_ip, SOURCE_IP_LENGTH);
  packet.readData(SOURCE_PORT_OFFSET, &source_port, SOURCE_PORT_LENGTH);

  // TODO handle flag in for each case

  switch (flags)
  {
    case (FIN_FLAG):
      std::cout << "This is FIN_ FLAG \n"; 
      break;

    case (FIN_FLAG | ACK_FLAG):
      std::cout << "This is FIN_ACK FLAG \n"; 
      break;
    
    case (SYN_FLAG):
      std::cout << "This is SYN FLAG \n";
      std::cout << "Receiving packet from ip=" << source_ip << ",port=" << source_port << '\n';
      
      break; 

    case (SYN_FLAG | ACK_FLAG):
      std::cout << "This is SYN_ACK FLAG \n"; 
      break;

    case (ACK_FLAG):
      std::cout << "This is ACK_ FLAG \n"; 
     break;

    default:
      std::cout << "No FLAG seen: " << unsigned(flags); 
      break;
  }


}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  // *payload = true;
}

} // namespace E
