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

  // DEBUG
  // std::cout << "Binding (sockfd=" << sockfd << ",pid=" << pid << ") at (ip=" << currAddress.first << ",port=" << currAddress.second << "\n" << std::flush; 
  
  // pairKeyToAddrInfo[pairKey] = addrInfo;
  bindedAddress[currAddress] = pairKey;

  Sucket& sucket = pairKeyToSucket[pairKey];
  sucket.localAddr = currAddress;

  return 0;
}

void TCPAssignment:: syscall_bind( UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen){
  std::pair<int, int> pairKey = {sockfd, pid};
  if (pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()){
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  Sucket& sucket = pairKeyToSucket[pairKey];
  Address address = addrInfoToAddr(addrToAddrInfo(sucket.localAddr));
  if(bindedAddress.find(address) != bindedAddress.end() || subBindedAddress.find(address) != subBindedAddress.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  this->returnSystemCall(syscallUUID, _syscall_bind(sockfd, pid, addr, addrlen));
}

int TCPAssignment::_syscall_getpeername(int sockfd, int pid, struct sockaddr * addr, socklen_t * addrlen){
  PairKey pairKey {sockfd, pid};
  Sucket sucket = pairKeyToSucket[pairKey];
  if (pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()){
    return -1;
  }
  AddressInfo addrInfo = addrToAddrInfo(sucket.remoteAddr);
  *addr = addrInfo.first;
  *addrlen = addrInfo.second;
  return 0;
}


void TCPAssignment:: syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen){
  return this->returnSystemCall(syscallUUID, _syscall_getpeername(sockfd, pid, addr, addrlen));
}

void TCPAssignment:: syscall_getsockname( UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) {
  // DEBUG
    // std::cout << "SYSCALL_getsockname\n" << std::flush;
  // end DEBUG
  
  PairKey pairKey {sockfd, pid};
  if (pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()){
    // DEBUG
      // std::cout << "getsockname fail: cannot find sucket\n" << std::flush;
    // end DEBUG
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  Sucket& sucket = pairKeyToSucket[pairKey];
  if(bindedAddress.find(sucket.localAddr) == bindedAddress.end() && subBindedAddress.find(sucket.localAddr) == subBindedAddress.end()) {
    // DEBUG
      // std::cout << "getsockname fail: cannot find binded address\n" << std::flush;
    // end DEBUG
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  AddressInfo addrInfo = addrToAddrInfo(sucket.localAddr);
  
  *addr = addrInfo.first;
  *addrlen = addrInfo.second;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment:: _send_packet(Sucket& sucket, uint8_t flag){
  Packet packet = create_packet(sucket, flag);
  sendPacket(std::string("IPv4"), packet);
  return;
}

void TCPAssignment::_syscall_close(PairKey pairKey) {
  Sucket& sucket = pairKeyToSucket[pairKey];
  if (sucket.state == TCP_ESTABLISHED){
    _send_packet(sucket, FIN_FLAG | ACK_FLAG);
    sucket.state = TCP_FIN_WAIT_1;

    // DEBUG
      // std::cout << "sended FIN_ACK packet, state = TCP_FIN_WAIT_1\n" << std::flush;
    // end DEBUG
  }
  else if (sucket.state == TCP_CLOSE_WAIT){
    _send_packet(sucket, FIN_FLAG | ACK_FLAG);
    sucket.state = TCP_LAST_ACK; 

    // DEBUG
      // std::cout << "sended FIN_ACK packet, state = TCP_LAST_ACK\n" << std::flush;
    // end DEBUG
  }
  else if(sucket.state == TCP_SYN_SENT) {
    sucket.isPendingClose = true;
    // DEBUG
      // std::cout << "in handshaking process...pending close\n" << std::flush;
    // end DEBUG
  }
  else {
    bindedAddress.erase(sucket.localAddr);
    subBindedAddress.erase(sucket.localAddr);
    pairAddressToPairKey.erase(PairAddress{sucket.localAddr, sucket.remoteAddr});
    pairKeyToSucket.erase(pairKey);
    if (sucket.state == TCP_LISTEN)     
      pairKeyToConnectionQueue.erase(pairKey);
    this->removeFileDescriptor(pairKey.second, pairKey.first);  

    // DEBUG
      // std::cout << "removed sucket sockfd=\n" << std::flush;
    // end DEBUG
  }
}

void TCPAssignment:: syscall_close(UUID syscallUUID, int pid, int sockfd){

  // DEBUG
    // std::cout << "SYSCALL_CLOSE: closing sockfd=" << sockfd << ",pid=" << pid<<"\n" << std::flush;
  // end DEBUG

  PairKey pairKey {sockfd, pid};
  if (pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()){
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  _syscall_close(pairKey);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  // DEBUG
  // std::cout << "Connecting pid=" << pid << ", sockfd=" << sockfd << "\n" << std::flush;
  
  PairKey pairKey {sockfd, pid};
  if(pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  Sucket &sucket = pairKeyToSucket[pairKey];

  if(sucket.state != TCP_CLOSED) {
    // DEBUG
    // std::cout << "fail to connect: sucket state should = TCP_CLOSED\n" << std::flush;
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  // Assign remote address for Sucket
  sucket.remoteAddr =  addrInfoToAddr(AddressInfo(*addr, addrlen));

  if(bindedAddress.find(sucket.localAddr) == bindedAddress.end()) {
    // START: Assign source address for Sucket
    ipv4_t ipv4_dest_ip = NetworkUtil::UINT64ToArray<std::size_t(4)>(sucket.remoteAddr.first);
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
      // CHECK HERE: possibly loop forever
      while(_syscall_bind(sockfd, pid, &localAddrInfo.first, localAddrInfo.second) != 0) {
        source_port = ntohs(uint16_t(rand()) * uint16_t(rand()));
        localAddrInfo = addrToAddrInfo(Address{source_ip, source_port});
      }
      sucket.localAddr = Address{source_ip, source_port};
    }
    // END: assign source address
  }

  PairAddress pairAddress = {sucket.localAddr, sucket.remoteAddr};
  handshaking[pairAddress] = pairKey;

  sucket.state = TCP_SYN_SENT;
  _send_packet(sucket, SYN_FLAG);

  // bool timeout = false;
  // UUID timerId = TCPAssignment::addTimer(&timeout, 1000000000);
  // while(sucket.state == TCP_SYN_SENT) {
  //   if(timeout) { // timeout => failed to connect
  //     sucket.state = TCP_CLOSED;
  //     this->returnSystemCall(syscallUUID, -1);
  //     return;
  //   }
  // }
  // TCPAssignment::cancelTimer(timerId);
  // handshaking.erase(pairAddress);
  // pairAddressToPairKey[pairAddress] = pairKey;

  this->returnSystemCall(syscallUUID, 0);

  // DEBUG
  // std::cout << "...done\n" << std::flush;
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog) {
  //DEBUG
  // std::cout << "SYSCALL_LISTEN: Opening listen on sockfd=" << sockfd << ", pid=" << pid << ", backlog=" << backlog;

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

  if(sucket.state != TCP_LISTEN) {
    ConnectionQueue newQueue = ConnectionQueue(backlog);
    pairKeyToConnectionQueue[pairKey] = newQueue;
  } else {
    ConnectionQueue& connection_queue = pairKeyToConnectionQueue[pairKey];
    connection_queue.capacity = backlog;
  }

  // DEBUG
      ConnectionQueue& temp = pairKeyToConnectionQueue[pairKey];
      // std::cout << "created new connectionQueue: cap=" << temp.capacity << "\n" << std::flush;
  // end DEBUG

  sucket.state = TCP_LISTEN;

  //DEBUG
    // std::cout << "...Succeeded => listening on: local_ip=" << localAddr.first << ", local_port=" << localAddr.second;
    // std::cout << ", backlog=" << backlog << "\n" << std::flush;
  // end DEBUG

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
  //DEBUG
  // std::cout << "SYSCALL_ACCEPT: accepting connection on sockfd=" << sockfd << ", pid=" << pid;
  // end DEBUG

  PairKey listener_pairKey = {sockfd, pid};
  if(pairKeyToSucket.find(listener_pairKey) == pairKeyToSucket.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  Sucket& listener_sucket = pairKeyToSucket[listener_pairKey];

  if(listener_sucket.state != TCP_LISTEN) {
    // DEBUG
    // std::cout << "...fail: sucket state should tcp_listen\n" << std::flush;
    // end DEBUG

    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  
  ConnectionQueue& connection_queue = pairKeyToConnectionQueue[listener_pairKey];
  if(connection_queue.cqueue.empty()) {
    // DEBUG
    // std::cout << "...done: pending accept syscallUUID=" << syscallUUID << "\n" << std::flush;
    // end DEBUG

    listener_sucket.pendingAccept.isPending = true;
    listener_sucket.pendingAccept.syscallUUID = syscallUUID;
    listener_sucket.pendingAccept.addr = addr;
    listener_sucket.pendingAccept.addrlen = addrlen;
    return;
  }

  // DEBUG
    // std::cout << "connection queue cap=" << connection_queue.capacity << "..." << std::flush;
    // Sucket* temp = connection_queue.cqueue.front();
    // std::cout << "queue_size=" << connection_queue.capacity << "...check sucketid:" << temp->pairKey.first << " " << temp->pairKey.second;
    // std::cout << "...ip=" << temp->localAddr.first << ",port=" << temp->localAddr.second << "...ip=" << temp->remoteAddr.first << ",port=" << temp->remoteAddr.second << "\n" << std::flush;
  // end DEBUG
  

  PairKey pairKey = connection_queue.cqueue.front();
  Sucket& sucketPtr = pairKeyToSucket[pairKey]; 
  connection_queue.cqueue.pop();

  _syscall_getpeername(sucketPtr.pairKey.first, sucketPtr.pairKey.second, addr, addrlen);

  // DEBUG
    // std::cout << "...done => server connection accepted: (source_ip=" << sucketPtr.localAddr.first << ",source_port=" << sucketPtr.localAddr.second << " and (dest_ip=" << sucketPtr.remoteAddr.first << ",dest_port" << sucketPtr.remoteAddr.second << ")\n" << std::flush;
  // end DEBUG

  this->returnSystemCall(syscallUUID, sucketPtr.pairKey.first);
  return;
}

Packet TCPAssignment::create_packet(Sucket& sucket, uint8_t flags, int bytes) {
  // packet data section = bytes
  // DEBUG
  // std::cerr << "Creating packet from ip=" << sucket.localAddr.first << ",port=" << sucket.localAddr.second << " to ip=" << sucket.remoteAddr.first << ",port=" << sucket.remoteAddr.second << " with flags=" << unsigned(flags) << "..." << std::flush;

  size_t packet_size = 54 + bytes;
  Packet packet = Packet(packet_size);

  // uint8_t version_header_length = (4 << 4) + 20;
  // packet.writeData(VERSION_HEADER_LENGTH_OFFSET, &version_header_length, VERSION_HEADER_LENGTH);

  uint16_t datagram_length = htons(20);
  packet.writeData(DATAGRAM_LENGTH_OFFSET, &datagram_length, DATAGRAM_LENGTH);

  uint32_t source_ip = htonl(sucket.localAddr.first);
  uint16_t source_port = htons(sucket.localAddr.second);
  uint32_t dest_ip = htonl(sucket.remoteAddr.first);
  uint16_t dest_port = htons(sucket.remoteAddr.second);

  packet.writeData(SOURCE_IP_OFFSET, &source_ip, SOURCE_IP_LENGTH);
  packet.writeData(DEST_IP_OFFSET, &dest_ip, DEST_IP_LENGTH);
  packet.writeData(SOURCE_PORT_OFFSET, &source_port, SOURCE_PORT_LENGTH);
  packet.writeData(DEST_PORT_OFFSET, &dest_port, DEST_PORT_LENGTH);

  uint32_t numByte = sucket.sendBuffer.acked_bytes + sucket.sendBuffer.not_sent; // acked bytes + sent but unacked bytes
  uint32_t seq_num = htonl(sucket.seqNum + numByte);
  packet.writeData(SEQ_NUM_OFFSET, &seq_num, SEQ_NUM_LENGTH);

  uint32_t ack_num = htonl(sucket.ackNum);
  packet.writeData(ACK_NUM_OFFSET, &ack_num, ACK_NUM_LENGTH);

  packet.writeData(FLAGS_OFFSET, &flags, FLAGS_LENGTH);
  
  uint16_t rwnd = htons(sucket.receiveBuffer.rwnd);
  packet.writeData(RWND_OFFSET, &rwnd, RWND_LENGTH);

  // uint16_t zero_checksum = 0;
  // packet.writeData(CHECKSUM_OFFSET, &zero_checksum, CHECKSUM_LENGTH);
  
  // Data
  if (bytes){
    std::cout << "Create Packet contains data, bytes = " << bytes << "\n";
    int notSentPos = sucket.sendBuffer.not_sent;
    // std::cout << "notSentPos = " << notSentPos << "\n";
    for (int i=0; i<bytes; i++){
      
      packet.writeData(54+i, &sucket.sendBuffer.buffer[notSentPos + i] ,1);
    }
  
  }
  
  size_t length = 20 + bytes;
  uint8_t* tcp_seg = (uint8_t*)malloc(length);
  packet.readData(SOURCE_PORT_OFFSET, tcp_seg, length); // tcp_seg = start index tcp_seg in mem
  uint16_t checksum = htons(~NetworkUtil::tcp_sum(source_ip, dest_ip, tcp_seg, length));

  packet.writeData(CHECKSUM_OFFSET, &checksum, CHECKSUM_LENGTH);
  

  // DEBUG
  // std::cout << "created packet...now sending\n" << std::flush;
  // end DEBUG

  return packet;
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void * buf, size_t count){
  
  PairKey pairKey = {sockfd, pid};
  if(pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  Sucket& sucket = pairKeyToSucket[pairKey];
  
  // Initialize
  if (sucket.receiveBuffer.buffer.empty()){
    sucket.receiveBuffer.containData = true;
    sucket.receiveBuffer.count = count;
    sucket.receiveBuffer.uuid = syscallUUID;
    sucket.receiveBuffer.application_buffer = buf;
  }
  
  // If receive buffer contains data --> the data is copied to the application’s buffer and the call returns immediately.
  if (sucket.receiveBuffer.containData){
    int readBytes = std::min(sucket.receiveBuffer.count, (int) sucket.receiveBuffer.buffer.size());
    for(int i=0; i<readBytes; i++){
      memcpy(sucket.receiveBuffer.application_buffer + i, &sucket.receiveBuffer.buffer[0], 1);
      sucket.receiveBuffer.buffer.pop_front();
    }
    sucket.receiveBuffer.rwnd += readBytes;
    this->returnSystemCall(sucket.receiveBuffer.uuid, readBytes);
}
}


void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, void * buf, size_t count){
  // write in sockfd what data in buf
  // std::cout << "Writing on sockfd = " << sockfd << " with count =" << count << "\n";

  PairKey pairKey = {sockfd, pid};
  if(pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  Sucket& sucket = pairKeyToSucket[pairKey];

  // data is copied to the send buffer
  int writtenBytes = 0;
  uint8_t *v = (uint8_t *) buf;
  for (int i=0; i < count; i++){
    sucket.sendBuffer.buffer.push_back(*v);
    v++;
    writtenBytes ++;
  }

  std::cout << "Writing on sockfd = " << sockfd << " with buffer size = " << sucket.sendBuffer.buffer.size() << " and writtenBytes = " << writtenBytes << "\n";

  sendChunkData(sucket);
  this->returnSystemCall(syscallUUID, writtenBytes);
}


void TCPAssignment::sendChunkData(struct Sucket &sucket){
  if (sucket.sendBuffer.buffer.empty()) 
    std::cout << "Send buffer is empty" << "\n";
  else 
    std::cout << "Send buffer not empty and buffer size = " << (int) sucket.sendBuffer.buffer.size() << "\n";
    
  int bytes_to_send = std::min((int) sucket.sendBuffer.buffer.size() - sucket.sendBuffer.not_sent, sucket.sendBuffer.can_receive);
  std::cout << "Send chunk data size = " << (unsigned int) bytes_to_send << "\n";

  // Make the packet with ACK flag and send to network layer a chunk of data at a time.
  while (bytes_to_send > 0){
    int chunkLength = std::min(512, bytes_to_send);
    std::cout << "sending ACK for chunk of data length = " << chunkLength << "\n";
    bytes_to_send -= chunkLength;
    sucket.sendBuffer.not_sent += chunkLength;
    Packet packet = create_packet(sucket, ACK_FLAG, chunkLength);
    sendPacket(std::string("IPv4"), packet);
  }

  sucket.sendBuffer.can_receive -= bytes_to_send;
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
    this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
                       std::get<void *>(param.params[1]),
                       std::get<int>(param.params[2]));
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
                        std::get<void *>(param.params[1]),
                        std::get<int>(param.params[2]));
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
    this->syscall_getpeername(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::_handle_SYN(Address sourceAddr, Address destAddr, uint32_t seqNum) {
  // DEBUG
    // std::cout << "This is SYN FLAG\n" << std::flush;
  // end DEBUG

  // check simultaneousConnect
  PairAddress pairAddress = PairAddress{destAddr,sourceAddr};
  if(handshaking.find(pairAddress) != handshaking.end()) {
    // DEBUG
      // std::cout << "Simultaneous connection...";
    // end DEBUG
    PairKey pairKey = handshaking[pairAddress];
    Sucket& sucket = pairKeyToSucket[pairKey];
    if(sucket.state == TCP_SYN_SENT) {
      sucket.state = TCP_SYN_RCVD;
      sucket.localAddr = destAddr;
      sucket.remoteAddr = sourceAddr;
      sucket.ackNum = seqNum + 1;
      _send_packet(sucket, SYN_FLAG | ACK_FLAG);
      subBindedAddress[sucket.localAddr] = pairKey;

      // DEBUG
        // std::cout << "Sent SYN_ACK packet for simultaneous connection\n";
      // end DEBUG
    }
    return;
  }

  Address listening_zero_addr = destAddr; listening_zero_addr.first = 0;

  if(bindedAddress.find(destAddr) == bindedAddress.end() && bindedAddress.find(listening_zero_addr) == bindedAddress.end()) {
    // DEBUG
      // std::cout << "handlesyn...no sucket binded to addr\n" << std::flush;
    // end DEBUG
    return;
  }

  Sucket& listener_sucket = (bindedAddress.find(destAddr) == bindedAddress.end()) ? pairKeyToSucket[bindedAddress[listening_zero_addr]] : pairKeyToSucket[bindedAddress[destAddr]];

  // DEBUG
    // std::cout << "state:" << (handshaking.find(pairAddress) != handshaking.end()) << '\n';
  // end DEBUG

  if (listener_sucket.state == TCP_LISTEN) {
    ConnectionQueue& connection_queue = pairKeyToConnectionQueue[listener_sucket.pairKey];

    if(connection_queue.capacity == 0) {
      // DEBUG
      // std::cout << "handlesyn...listening queue overloaded\n" << std::flush;
      return;
    }

    PairKey pairKey = {_syscall_socket(listener_sucket.pairKey.second), listener_sucket.pairKey.second};
    Sucket& sucket = pairKeyToSucket[pairKey];
    sucket.state = TCP_SYN_RCVD;
    sucket.localAddr = destAddr;
    sucket.remoteAddr = sourceAddr;
    sucket.ackNum = seqNum + 1;
    sucket.parentPairKey = listener_sucket.pairKey;
    subBindedAddress[sucket.localAddr] = pairKey;

    _send_packet(sucket, SYN_FLAG | ACK_FLAG);

    handshaking[PairAddress{sucket.localAddr, sucket.remoteAddr}] = pairKey;
    connection_queue.capacity --;

    // pairAddressToPairKey[PairAddress{sucket.localAddr, sucket.remoteAddr}] = pairKey;

    // DEBUG
    // std::cout << "handlesyn...done sent syn_ack_package, new socket (sockfd=" << pairKey.first << ",pid=" << pairKey.second << ") created..." << std::flush;
    // std::cout << "from (ip=" << destAddr.first << ",port=" << destAddr.second << ") to (ip=" << sourceAddr.first << "port=" << sourceAddr.second << ")\n" << std::flush;
    // end DEBUG

    return;
  }
}

void TCPAssignment::_handle_SYN_ACK(Address sourceAddr, Address destAddr, uint32_t ackNum, uint32_t seqNum) {
  // DEBUG
  // std::cout << "This is SYN|ACK FLAG\n" << std::flush;

  PairAddress pairAddress = {destAddr, sourceAddr};
  if(handshaking.find(pairAddress) == handshaking.end()) {
    // DEBUG  
      // std::cout << "handle syn/ack fail: fail: cannot find pair address in handshaking\n" << std::flush;
    // end DEBUG

    return;
  }

  Sucket& sucket = pairKeyToSucket[handshaking[pairAddress]];
  if(sucket.state == TCP_SYN_RCVD) {
    // DEBUG  
      // std::cout << "Simultaneous connection handle synack..." << std::flush;
    // end DEBUG
    sucket.state = TCP_ESTABLISHED;
    sucket.ackNum = seqNum + 1;
    pairAddressToPairKey[pairAddress] = handshaking[pairAddress];
    handshaking.erase(pairAddress);
    // DEBUG  
      // std::cout << "connected\n" << std::flush;
    // end DEBUG

    if(sucket.isPendingClose) {
      sucket.isPendingClose = false;
      _syscall_close(sucket.pairKey);

      // DEBUG
        // std::cout << "handle syn/ack continue: isPendingClose = true => closing sucket now\n";
      // end DEBUG
    }

    return;
  }
  else if(sucket.state != TCP_SYN_SENT || ackNum != sucket.seqNum + 1) {
    // DEBUG  
      // std::cout << "handle syn/ack fail: sucket state must be TCP_SYN_SENT or wrong ackNum=" << (ackNum != sucket.seqNum + 1) << '\n';
    // end DEBUG
    return;
  }

  sucket.state = TCP_ESTABLISHED;
  sucket.ackNum = seqNum + 1;
  
  _send_packet(sucket, ACK_FLAG);
  pairAddressToPairKey[pairAddress] = handshaking[pairAddress];
  handshaking.erase(pairAddress);

  // DEBUG  
  // std::cout << "handle syn/ack done: client connection established (" << sourceAddr.first << "," << sourceAddr.second << ") and (" << destAddr.first << "," << destAddr.second << ")\n" << std::flush;
  // end DEBUG

  if(sucket.isPendingClose) {
    sucket.isPendingClose = false;
    _syscall_close(sucket.pairKey);

    // DEBUG
      // std::cout << "handle syn/ack continue: isPendingClose = true => closing sucket now\n";
    // end DEBUG
  }

  return;
}


// void TCPAssignment:: pop_front(std::vector<uint8_t>& vec){
//     if (vec.empty()) {
//       std::cout << "The buffer is empty" << "\n";
//       return;
//     }
//     else {
//       std::cout << "vec size " << vec.size() << "\n";
//     }
//     vec.front() = std::move(vec.back());
//     vec.pop_back();
//   }


void TCPAssignment::_handle_ACK(Address sourceAddr, Address destAddr, uint32_t ackNum, uint32_t seqNum, int rwnd) {
  // DEBUG
  // std::cout << "This is ACK FLAG\n" << std::flush;
  
  PairAddress pairAddress = {destAddr, sourceAddr};
  if(pairAddressToPairKey.find(pairAddress) != pairAddressToPairKey.end()) {
    Sucket& sucket = pairKeyToSucket[pairAddressToPairKey[pairAddress]];
    PairKey pairKey = sucket.pairKey;
    
    
    if (sucket.state == TCP_ESTABLISHED){
      std::cout << "receive ACK, sender buffer size =" << (int)sucket.sendBuffer.buffer.size() << "\n";

      // Free the send buffer space allocated for acked data
      int bytes_to_ack = ackNum - sucket.seqNum - sucket.sendBuffer.acked_bytes;
      for (int i=0; i<bytes_to_ack; i++){
        sucket.sendBuffer.buffer.pop_front();
      }

      // move the sender window (the number of in-flight bytes should be decreased)
      sucket.sendBuffer.acked_bytes += bytes_to_ack;
      sucket.sendBuffer.not_sent -= bytes_to_ack;

      // adjust the sender window size (from advertised receive buffer size)
      sucket.sendBuffer.can_receive = rwnd;

      // send data if there is waiting data in the send buffer and if the data is sendable
      sendChunkData(sucket);
      return;
    }

      
    if(sucket.seqNum + 1 != ackNum) 
      return;
 
    sucket.ackNum = seqNum + 1;
    if(sucket.state == TCP_FIN_WAIT_1) {
      sucket.state = TCP_FIN_WAIT_2;

      // DEBUG
        // std::cout << "changed socket state FIN_WAIT_1 -> FIN_WAIT_2\n" << std::flush;
      // end DEBUG
    } else if(sucket.state == TCP_LAST_ACK) {
      bindedAddress.erase(sucket.localAddr);
      subBindedAddress.erase(sucket.localAddr);
      pairAddressToPairKey.erase(pairAddress);
      pairKeyToSucket.erase(pairKey);

      // DEBUG
        // std::cout << "disconnected server socket: fd=" << pairKey.first << ",pid=" << pairKey.second << "\n" << std::flush;
      // end DEBUG
    }
  } else if(handshaking.find(pairAddress) != handshaking.end()) {
    Sucket& currSucket = pairKeyToSucket[handshaking[pairAddress]];
    currSucket.state = TCP_ESTABLISHED;
    handshaking.erase(pairAddress);
    pairAddressToPairKey[pairAddress] = currSucket.pairKey;
    ConnectionQueue& connection_queue = pairKeyToConnectionQueue[currSucket.parentPairKey];

    // DEBUG
    // std::cout << "...done: connection ready to accept from (ip=" << sourceAddr.first << ",port=" << sourceAddr.second << ") to (ip=" << destAddr.first << ",port=" << destAddr.second;
    // end DEBUG

    // FIX HERE
    PairKey parentPairKey = currSucket.parentPairKey;
    Sucket& parentSucket = pairKeyToSucket[parentPairKey];
    if(parentSucket.pendingAccept.isPending) {
      struct sockaddr * addr = parentSucket.pendingAccept.addr;
      socklen_t * addrlen = parentSucket.pendingAccept.addrlen;
      UUID syscallUUID = parentSucket.pendingAccept.syscallUUID;
      _syscall_getpeername(currSucket.pairKey.first, currSucket.pairKey.second, addr, addrlen);
      this->returnSystemCall(syscallUUID, currSucket.pairKey.first);

      parentSucket.pendingAccept.isPending = false;
      // DEBUG
        // std::cout << "...Pushed new connection for pending accept syscallUUID=" << syscallUUID << "\n" << std::flush;
      // end DEBUG
    } else {
      connection_queue.cqueue.push(currSucket.pairKey);
      // DEBUG
        // std::cout << "...Pushed new connection to connection_queue\n" << std::flush;
      // end DEBUG
    }
    connection_queue.capacity ++;

  } else {
    // DEBUG
    // std::cout << "...fail: connection not found\n" << std::flush;
  }

}

void TCPAssignment::_handle_FIN_ACK(Address sourceAddr, Address destAddr, uint32_t seqNum) {
  // DEBUG
    // std::cout << "this is FIN | ACK flag\n" << std::flush;
  // end DEBUG
  
  PairAddress pairAddress = {destAddr, sourceAddr};
  if(pairAddressToPairKey.find(pairAddress) == pairAddressToPairKey.end()) {
    // DEBUG
      // std::cout << "finack handle fail: cannot find connection\n" << std::flush;
    // end DEBUG
    return;
  }

  Sucket& sucket = pairKeyToSucket[pairAddressToPairKey[pairAddress]];
  if(sucket.state == TCP_FIN_WAIT_2) {
    sucket.ackNum = seqNum + 1; 
    _send_packet(sucket, ACK_FLAG);

    bindedAddress.erase(sucket.localAddr);
    subBindedAddress.erase(sucket.localAddr);
    pairAddressToPairKey.erase(pairAddress);
    PairKey pairKey = sucket.pairKey;
    pairKeyToSucket.erase(pairKey);
    // DEBUG
      // std::cout << "finack handle done: disconnected on client\n" << std::flush;
    // end DEBUG
    return;
  }
  else if(sucket.state != TCP_ESTABLISHED) {
    // DEBUG
      // std::cout << "sucket state should be TCP_ESTABLISHED\n" << std::flush;
    // end DEBUG
    return;
  }

  // server with state == TCP_ESTABLISHED
  sucket.ackNum = seqNum + 1;
  sucket.state = TCP_CLOSE_WAIT;  
  _send_packet(sucket, ACK_FLAG);
  
  if (sucket.receiveBuffer.containData){
    this->returnSystemCall(sucket.receiveBuffer.uuid, -1);
  }

  // DEBUG
    // std::cout << "done: closed connection on socket moved -> TCP_CLOSE_WAIT, fd=" << sucket.pairKey.first << ",pid=" << sucket.pairKey.second << "\n" << std::flush;
  // end DEBUG
  return;
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;

  uint8_t flags;
  uint32_t seqNum;
  uint32_t ackNum;
  uint32_t source_ip, dest_ip;
  uint16_t source_port, dest_port;
  uint16_t payload;
  uint16_t rwnd = 0;


  packet.readData(FLAGS_OFFSET, &flags, FLAGS_LENGTH);
  packet.readData(SEQ_NUM_OFFSET, &seqNum, SEQ_NUM_LENGTH);
  packet.readData(ACK_NUM_OFFSET, &ackNum, ACK_NUM_LENGTH);
  packet.readData(SOURCE_IP_OFFSET, &source_ip, SOURCE_IP_LENGTH);
  packet.readData(SOURCE_PORT_OFFSET, &source_port, SOURCE_PORT_LENGTH);
  packet.readData(DEST_IP_OFFSET, &dest_ip, DEST_IP_LENGTH);
  packet.readData(DEST_PORT_OFFSET, &dest_port, DEST_PORT_LENGTH);
  packet.readData(RWND_OFFSET, &rwnd, RWND_LENGTH);
  
  // Packet packetClone = packet.clone();
  
  // std::cout << "RECEIVE Packet size " << packet.getSize() << " , flag = " << (unsigned int) flags << "\n";
  
  if (packet.getSize() > 54){
    std::cout << "RECEIVE packet contains payload size " << packet.getSize() - 54 << "\n";
    PairAddress pairAddress {{source_ip, source_port} , {dest_ip,dest_port}};
    PairKey pairKey = pairAddressToPairKey[pairAddress];
    Sucket sucket = pairKeyToSucket[pairKey];

    // Copy the payload to the corresponding TCP socket’s receive buffer
    int sizeData = packet.getSize() - 54;
    for (int i=0; i<sizeData; i++){
      packet.readData(54+i, &payload, 1);
      sucket.receiveBuffer.buffer.push_back(payload);
    }

    sucket.ackNum = sucket.seqNum + sizeData;
    sucket.receiveBuffer.rwnd = MSS - (int) sucket.receiveBuffer.buffer.size();
    
    // If receive buffer contains data --> the data is copied to the application’s buffer and the call returns immediately.
    if (sucket.receiveBuffer.containData){
      int readBytes = std::min(sucket.receiveBuffer.count, (int) sucket.receiveBuffer.buffer.size());
      for(int i=0; i<readBytes; i++){
        memcpy(sucket.receiveBuffer.application_buffer + i, &sucket.receiveBuffer.buffer[0], 1);
        sucket.receiveBuffer.buffer.pop_front();
      }
      sucket.receiveBuffer.rwnd += readBytes;
      returnSystemCall(sucket.receiveBuffer.uuid, readBytes);
    }

    //Acknowledge received packet :  Send ACK
    Packet new_packet = create_packet(sucket, ACK_FLAG);
    sendPacket(std::string("IPv4"), new_packet);
    return;
  }
  
  seqNum = ntohl(seqNum);
  ackNum = ntohl(ackNum);
  source_ip = ntohl(source_ip);
  source_port = ntohs(source_port);
  dest_ip = ntohl(dest_ip);
  dest_port = ntohs(dest_port);
  
  PairAddress pairAddress {{source_ip, source_port} , {dest_ip,dest_port}};
  Address sourceAddr = {source_ip, source_port};
  Address destAddr = {dest_ip,dest_port};
  
  // DEBUG
    // std::cout << "packet arrived from (ip=" << sourceAddr.first << ",port=" << sourceAddr.second << ") to (ip=" << dest_ip << ",port=" << dest_port << ") flags=" << unsigned(flags) << "\n" << std::flush;
  // end DEBUG

  if(flags == SYN_FLAG) _handle_SYN(sourceAddr, destAddr, seqNum);
  else if(flags == (SYN_FLAG | ACK_FLAG)) _handle_SYN_ACK(sourceAddr, destAddr, ackNum, seqNum);
  else if(flags == ACK_FLAG) _handle_ACK(sourceAddr, destAddr, ackNum, seqNum, rwnd);
  else if(flags == (FIN_FLAG | ACK_FLAG)) _handle_FIN_ACK(sourceAddr, destAddr, seqNum);
  else {
    // std::cout << "packet handle fail: No FLAG seen: " << unsigned(flags) << "...checking for connection establish..." << std::flush;
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  try {
    *std::any_cast<bool*>(payload) = true;
  } catch (const std::bad_any_cast& e) {
    std::cout << e.what() << "\n" << std::flush;
  }
}

} // namespace E
