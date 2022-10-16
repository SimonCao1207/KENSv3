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
    pairKeyToSucket[pairKey] = Sucket(pairKey, TCP_CLOSED); 
  }
  return fd;
}

void TCPAssignment:: syscall_socket(UUID syscallUUID, int pid, int type, int protocol){
  this->returnSystemCall(syscallUUID, _syscall_socket(pid));
}

int TCPAssignment:: _syscall_bind(int sockfd, int pid, struct sockaddr *addr, socklen_t addrlen){
  std::pair<int, int> pairKey = {sockfd, pid};
  std::pair<sockaddr, socklen_t> addrInfo = {*addr, addrlen};

  Address currAddress = addrInfoToAddr(addrInfo);
  Address addressZero = {0U, currAddress.second};

  if (bindedAddress.find(currAddress) != bindedAddress.end() || bindedAddress.find(addressZero) != bindedAddress.end()) {
    return -1;
  }  
  
  pairKeyToAddrInfo[pairKey] = addrInfo;
  bindedAddress[currAddress] = pairKey;

  Sucket& sucket = pairKeyToSucket[pairKey];
  sucket.localAddr = currAddress;

  return 0;
}

void TCPAssignment:: syscall_bind( UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen){
  std::pair<int, int> pairKey = {sockfd, pid};
  if (pairKeyToSucket.find(pairKey) == pairKeyToSucket.end() || pairKeyToAddrInfo.count(pairKey)){
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  this->returnSystemCall(syscallUUID, _syscall_bind(sockfd, pid, addr, addrlen));
}

void TCPAssignment:: syscall_getsockname( UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) {
  PairKey pairKey {sockfd, pid};
  if (pairKeyToSucket.find(pairKey) == pairKeyToSucket.end() || pairKeyToAddrInfo.find(pairKey) == pairKeyToAddrInfo.end()){
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
  if (pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()){
    this->returnSystemCall(syscallUUID, -1);
    return; 
  }

  Sucket& sucket = pairKeyToSucket[pairKey];
  PairAddress pairAddress = PairAddress{sucket.localAddr, sucket.remoteAddr};
  TCP_STATE state = sucket.state;
  switch (state)
  {
    case TCP_ESTABLISHED:
      _send_packet(sucket, FIN_FLAG | ACK_FLAG);
      sucket.state = TCP_FIN_WAIT_1;
      break;

    case TCP_CLOSE_WAIT:
      _send_packet(sucket, FIN_FLAG | ACK_FLAG);
      sucket.state = TCP_LAST_ACK;
      break;
    
    default:
      if (pairKeyToAddrInfo.find(pairKey) != pairKeyToAddrInfo.end()){
        std::pair<sockaddr, socklen_t> addrInfo = pairKeyToAddrInfo[pairKey];
        std::pair<uint32_t, uint16_t> addr = addrInfoToAddr(addrInfo);
        bindedAddress.erase(addr);
        pairKeyToAddrInfo.erase(pairKey);
      }
      pairKeyToSucket.erase(pairKey);
      pairAddressToPairKey.erase(pairAddress);
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

  // START: assign destination address
  sockaddr_in addr_in = * ((sockaddr_in*) addr);
  uint32_t dest_ip = ntohl(addr_in.sin_addr.s_addr);
  uint16_t dest_port = ntohs(addr_in.sin_port);
  sucket.remoteAddr = Address(dest_ip, dest_port);
  // END: assign destination address

  // START: assign source address
  ipv4_t ipv4_dest_ip = NetworkUtil::UINT64ToArray<std::size_t(4)>(dest_ip);
  int NIC_port = getRoutingTable(ipv4_dest_ip);
  std::optional<ipv4_t> ipv4_local_ip_opt = getIPAddr(NIC_port);

  if(ipv4_local_ip_opt.has_value() == false) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  } else {
    uint32_t source_ip = ntohl(NetworkUtil::arrayToUINT64(ipv4_local_ip_opt.value()));
    uint16_t source_port = ntohs(uint16_t(rand()) * uint16_t(rand()));
    AddressInfo localAddrInfo = addrToAddrInfo(Address{source_ip, source_port});

    // loop to generate port number 
    // CHECK HERER: possibly loop forever
    while(_syscall_bind(sockfd, pid, &localAddrInfo.first, localAddrInfo.second) != 0) {
      source_port = ntohs(uint16_t(rand()) * uint16_t(rand()));
      localAddrInfo = addrToAddrInfo(Address{source_ip, source_port});
    }
  }
  // END: assign source address

  sucket.seqNum = random_seqnum();

  _send_packet(sucket, SYN_FLAG);
  sucket.state = TCP_SYN_SENT;

  bool timeout = false;
  UUID timerId = TCPAssignment::addTimer(&timeout, 1000000000);
  while(sucket.state == TCP_SYN_SENT) {
    if(timeout) { // timeout => failed to connect
      sucket.state = TCP_CLOSED;
      this->returnSystemCall(syscallUUID, -1);
      return;
    }
  }
  TCPAssignment::cancelTimer(timerId);

  pairAddressToPairKey[{sucket.localAddr, sucket.remoteAddr}] = pairKey;
  this->returnSystemCall(syscallUUID, 0);
  return;
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog) {
  //DEBUG
  std::cout << "SYSCALL_LISTEN: Opening listen on sockfd=" << sockfd << ", backlog=" << backlog;

  PairKey pairKey = {sockfd, pid};
  if(pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  Sucket& sucket = pairKeyToSucket[pairKey];
  Address localAddr = sucket.localAddr;
  if(bindedAddress.find(localAddr) == bindedAddress.end() || bindedAddress[localAddr] != pairKey) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  //DEBUG
  std::cout << "...Succeeded => listening on: local_ip=" << localAddr.first << ", local_port=" << localAddr.second << "\n";

  if(sucket.state != TCP_LISTEN) {
    sucket.listenQueue = ListenQueue(backlog);
  } else {
    sucket.listenQueue.capacity = backlog;
  }
  sucket.state = TCP_LISTEN;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
  //DEBUG
  std::cout << "SYSCALL_ACCEPT: accepting connection on sockfd=" << sockfd;

  PairKey listener_pairKey = {sockfd, pid};
  if(pairKeyToSucket.find(listener_pairKey) == pairKeyToSucket.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  Sucket& listener_sucket = pairKeyToSucket[listener_pairKey];

  Address incoming_addr = addrInfoToAddr(AddressInfo{*addr, *addrlen});
  
  PairKey pairKey = {_syscall_socket(pid), pid};
  Sucket& sucket = pairKeyToSucket[pairKey];
  sucket.state = TPC_SYN_RCVD;
  sucket.localAddr = listener_sucket.localAddr;
  sucket.remoteAddr = incoming_addr;
  sucket.seqNum = random_seqnum();

  _send_packet(sucket, SYN_FLAG);

  bool timeout = false;
  UUID timerId = TCPAssignment::addTimer(&timeout, 1000000000);
  while(sucket.state == TPC_SYN_RCVD) {
    if(timeout) { // timeout => failed to connect
      sucket.state = TCP_LISTEN;
      this->returnSystemCall(syscallUUID, -1);
      return;
    }
  }
  TCPAssignment::cancelTimer(timerId);

  pairAddressToPairKey[PairAddress{sucket.localAddr, sucket.remoteAddr}] = pairKey;
  sucket.state = TCP_ESTABLISHED;
  // DEBUG
  std::cout << "...succeeded => connection established: (source_ip=" << sucket.localAddr.first << ",source_port=" << sucket.localAddr.second << " and (dest_ip=" << sucket.remoteAddr.first << ",dest_port" << sucket.remoteAddr.second << "\n";

  this->returnSystemCall(syscallUUID, 0);
  return;
}

Packet TCPAssignment::create_packet(struct Sucket& sucket, uint8_t flags) {
  // packet data section = 0, currently not support data
  // DEBUG
  std::cerr << "Creating packet from ip=" << sucket.localAddr.first << ",port=" << sucket.localAddr.second << " to ip=" << sucket.remoteAddr.first << ",port=" << sucket.remoteAddr.second << " with flags=" << flags << '\n';

  size_t packet_size = 100;
  Packet packet (packet_size);

  uint8_t version_header_length = (4 << 4) + 20;
  packet.writeData(VERSION_HEADER_LENGTH_OFFSET, &version_header_length, VERSION_HEADER_LENGTH);

  uint16_t datagram_length = htons(40);
  packet.writeData(DATAGRAM_LENGTH_OFFSET, &datagram_length, DATAGRAM_LENGTH);

  uint32_t source_ip = htonl(sucket.localAddr.first);
  uint16_t source_port = htons(sucket.localAddr.second);
  uint32_t dest_ip = htonl(sucket.remoteAddr.first);
  uint16_t dest_port = htons(sucket.remoteAddr.second);

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
  packet.writeData(SOURCE_PORT_OFFSET, tcp_seg, length); // tcp_seg = start index tcp_seg in mem
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
    this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
                         std::get<int>(param.params[1]));
    break;
  case ACCEPT:
    this->syscall_accept(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
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
  uint32_t source_ip, dest_ip;
  uint16_t source_port, dest_port;

  Packet packetClone = packet.clone(); 
  
  packet.readData(FLAGS_OFFSET, &flags, FLAGS_LENGTH);
  packet.readData(SEQ_NUM_OFFSET, &seqNum, SEQ_NUM_LENGTH);
  packet.readData(SOURCE_IP_OFFSET, &source_ip, SOURCE_IP_LENGTH);
  packet.readData(SOURCE_PORT_OFFSET, &source_port, SOURCE_PORT_LENGTH);
  packet.writeData(DEST_IP_OFFSET, &dest_ip, DEST_IP_LENGTH);
  packet.writeData(DEST_PORT_OFFSET, &dest_port, DEST_PORT_LENGTH);
  
  PairAddress pairAddress {{source_ip, source_port} , {dest_ip,dest_port}};
  
  Sucket& sucket = pairKeyToSucket[pairAddressToPairKey[pairAddress]];

  // TODO: handle ackNum and seqNum in each flag

  switch (flags)
  {
    case (FIN_FLAG):
      std::cout << "This is FIN_ FLAG \n"; 
      break;

    case (FIN_FLAG | ACK_FLAG):
      std::cout << "This is FIN_ACK FLAG \n";
      if (sucket.state == TCP_FIN_WAIT_1){
       
        sucket.state = TCP_CLOSING;
        _send_packet(sucket, ACK_FLAG);        
      }
      else if (sucket.state == TCP_FIN_WAIT_2){
        _send_packet(sucket, ACK_FLAG);
        sucket.state = TCP_TIME_WAIT;
        // TODO: Add a timer here
      }
      else if (sucket.state == TCP_ESTABLISHED){
        _send_packet(sucket, ACK_FLAG);
        sucket.state = TCP_CLOSE_WAIT;
      }
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
  try {
    *std::any_cast<bool*>(payload) = true;
  } catch (const std::bad_any_cast& e) {
    std::cout << e.what() << "\n";
  }
}

} // namespace E
