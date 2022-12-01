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
#include <E/E_TimeUtil.hpp>
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

void TCPAssignment::_delete_sucket(Sucket& sucket) {
  // DEBUG
    // std::cout << "Deleting sucket\n";
  // end DEBUG
  
  PairKey pairKey = sucket.pairKey;
  if(sucket.isPendingCloseWait == false) // active closing
    this->removeFileDescriptor(sucket.pairKey.second, sucket.pairKey.first);
  this->cancelTimer(sucket.timerKey);
  bindedAddress.erase(sucket.localAddr);
  subBindedAddress.erase(sucket.localAddr);
  pairAddressToPairKey.erase(PairAddress{sucket.localAddr, sucket.remoteAddr});
  pairKeyToSucket.erase(pairKey);
  if (sucket.state == TCP_LISTEN)     
    pairKeyToConnectionQueue.erase(pairKey);
}

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
  this->returnSystemCall(syscallUUID, _syscall_getpeername(sockfd, pid, addr, addrlen));
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

void TCPAssignment:: _send_packet(Sucket& sucket, uint8_t flag, int dataLength=0){
  Packet packet = create_packet(sucket, flag, dataLength);
  sendPacket(std::string("IPv4"), packet);
  sucket.sendBuffer.pending_packets.push_back(packet);
  if(sucket.sendBuffer.pending_packets.size() == 1) {
    // DEBUG
      std::cout << "send_packet: added timer\n";
    // end DEBUG
    this->cancelTimer(sucket.timerKey);
    UUID key = this->addTimer(sucket.pairKey, TIME_OUT);
    sucket.timerKey = key;
  }

  if(flag == ACK_FLAG) {
    while(!sucket.receiveBuffer.lastAckPacket.empty())
      sucket.receiveBuffer.lastAckPacket.pop_front();
    sucket.receiveBuffer.lastAckPacket.push_front(packet);
  }

  return;
}

void TCPAssignment::_syscall_close(PairKey pairKey) {
  Sucket& sucket = pairKeyToSucket[pairKey];
  if (sucket.state == TCP_ESTABLISHED){
    if(sucket.sendBuffer.nextSeqNum < sucket.sendBuffer.data.size()) {
      sucket.isPendingClose = true;
      // DEBUG
        std::cout << "syscall_close: pending close after sending all data buffer\n" << std::flush;
      // end DEBUG

      return;
    }

    _send_packet(sucket, FIN_FLAG | ACK_FLAG);
    sucket.state = TCP_FIN_WAIT_1;
    // DEBUG
      std::cout << "syscall_close: sended FIN_ACK packet, state = TCP_FIN_WAIT_1\n" << std::flush;
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
    _delete_sucket(sucket);
    // bindedAddress.erase(sucket.localAddr);
    // subBindedAddress.erase(sucket.localAddr);
    // pairAddressToPairKey.erase(PairAddress{sucket.localAddr, sucket.remoteAddr});
    // pairKeyToSucket.erase(pairKey);
    // if (sucket.state == TCP_LISTEN)     
    //   pairKeyToConnectionQueue.erase(pairKey);
    // this->removeFileDescriptor(pairKey.second, pairKey.first);  // DELETED HERE - CHECK

    // DEBUG
      // std::cout << "removed sucket sockfd=\n" << std::flush;
    // end DEBUG
  }
}

void TCPAssignment:: syscall_close(UUID syscallUUID, int pid, int sockfd){
  // DEBUG
    std::cout << "SYSCALL_CLOSE: closing sockfd=" << sockfd << ",pid=" << pid<<"\n" << std::flush;
  // end DEBUG
  PairKey pairKey {sockfd, pid};
  if (pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()){
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  _syscall_close(pairKey);
  this->removeFileDescriptor(pairKey.second, pairKey.first);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  // DEBUG
  std::cout << "Connecting pid=" << pid << ", sockfd=" << sockfd << "\n" << std::flush;
  
  PairKey pairKey {sockfd, pid};
  if(pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  Sucket &sucket = pairKeyToSucket[pairKey];

  if(sucket.state != TCP_CLOSED) {
    // DEBUG
    std::cout << "fail to connect: sucket state should = TCP_CLOSED\n" << std::flush;
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
  sucket.connect_syscallUUID = syscallUUID;
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

  // this->returnSystemCall(syscallUUID, 0);

  // DEBUG
  std::cout << "syscall_connect: pushed connection for pending\n" << std::flush;
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
  std::cout << "SYSCALL_ACCEPT: accepting connection on sockfd=" << sockfd << ", pid=" << pid << '\n';
  // end DEBUG

  PairKey listener_pairKey = {sockfd, pid};
  if(pairKeyToSucket.find(listener_pairKey) == pairKeyToSucket.end()) {
    //DEBUG
      std::cout << "SYSCALL_ACCEPT: failed => cannot find listener_pairKey\n";
    // end DEBUG

    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  Sucket& listener_sucket = pairKeyToSucket[listener_pairKey];

  if(listener_sucket.state != TCP_LISTEN) {
    // DEBUG
    std::cout << "SYSCALL_ACCEPT: fail - sucket state should tcp_listen\n" << std::flush;
    // end DEBUG

    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  
  ConnectionQueue& connection_queue = pairKeyToConnectionQueue[listener_pairKey];
  if(connection_queue.cqueue.empty()) {
    // DEBUG
    std::cout << "SYSCALL_ACCEPT: done - pending accept syscallUUID=" << syscallUUID << "\n" << std::flush;
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
    std::cout << "SYSCALL_ACCEPT: done => server connection accepted: (source_ip=" << sucketPtr.localAddr.first << ",source_port=" << sucketPtr.localAddr.second << " and (dest_ip=" << sucketPtr.remoteAddr.first << ",dest_port" << sucketPtr.remoteAddr.second << ")\n" << std::flush;
  // end DEBUG

  this->returnSystemCall(syscallUUID, sucketPtr.pairKey.first);
  return;
}

void TCPAssignment::process_send_buffer(int sockfd, int pid) {
  // DEBUG
    std::cout << "process_send_buffer: sockfd=" << sockfd << ",pid=" << pid << '\n';
  // end DEBUG

  PairKey pairKey = {sockfd, pid};
  if(pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()) {
    // DEBUG
      std::cout << "process_send_buffer: cannot find pairKey\n";
    // end DEBUG
    return;
  }

  Sucket& sucket = pairKeyToSucket[pairKey];
  SendBuffer& sendBuffer = sucket.sendBuffer;

  int send_length = 0;
  do {
    int sent_bytes = sendBuffer.nextSeqNum;
    
    if(sendBuffer.windowSize <= sent_bytes) {
      // DEBUG
        std::cout << "process_send_buffer: receiver windowSize filled,sendBuffer.windowSize=" << sendBuffer.windowSize;
        std::cout << ",sent_bytes=" << sent_bytes << '\n';
      // end DEBUG
      
      return;
    }
    
    // DEBUG
      std::cout << "process_send_buffer: sent_bytes=" << sent_bytes << '\n';
    // end DEBUG

    int send_length = std::min(std::min(sendBuffer.windowSize, int(sendBuffer.data.size())) - sent_bytes, MSS); // check here
    if(send_length <= 0) break;
    _send_packet(sucket, ACK_FLAG, send_length);
    
  } while(send_length > 0);

  if(sucket.state == TCP_CLOSE_WAIT && sucket.sendBuffer.data.size() == sucket.sendBuffer.nextSeqNum && sucket.isPendingCloseWait) {
    // DEBUG
      std::cout << "handle_ACK: continue close wait process... sending FIN_ACK packet\n";
    // end DEBUG

    _syscall_close(sucket.pairKey);
  }

  if(sucket.state != TCP_FIN_WAIT_1 && sucket.sendBuffer.data.size() == sucket.sendBuffer.nextSeqNum && sucket.isPendingClose) {
      // DEBUG
      std::cout << "handle_ACK: continue closing process... sending FIN_ACK packet\n";
    // end DEBUG

    sucket.state = TCP_FIN_WAIT_1;
    _send_packet(sucket, FIN_FLAG|ACK_FLAG);
    
    return;
  }

  if(sucket.sendBuffer.data.size() == sucket.sendBuffer.nextSeqNum) {
    // DEBUG
      std::cout << "process_send_buffer: all data sent - not sure all acked\n";
    // end DEBUG

    this->cancelTimer(sucket.timerKey);
  }

}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, const void* buf, int count) {
  // DEBUG
    std::cout << "syscall_write: pid=" << pid << ",sockfd=" << sockfd << ",count=" << count << '\n';
  // end DEBUG
  
  PairKey pairKey = {sockfd, pid};
  if(pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()) {
    // DEBUG
      std::cout << "syscall_write: cannot find pairKey\n";
    // end DEBUG
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  Sucket& sucket = pairKeyToSucket[pairKey];

  uint8_t* ptr = (uint8_t*)buf;
  for(int i = 0; i < count; ++i) {
    sucket.sendBuffer.data.push_back(*ptr);
    ptr++;
  }

  // DEBUG
    std::cout << "syscall_write: done writing\n";
  // end DEBUG

  process_send_buffer(sockfd, pid);
  this->returnSystemCall(syscallUUID, count);
}

void TCPAssignment::_syscall_read(UUID syscallUUID, struct ReceiveBuffer& receiveBuffer, void* buf, int count) {
  int readLength = std::min(count, int(receiveBuffer.data.size()));
  
  for(int i = 0; i < readLength; ++i) {
    memcpy(buf + i, &receiveBuffer.data[0], 1);
    receiveBuffer.data.pop_front();
  }

  // DEBUG
    std::cout << "syscall_read: done reading #bytes=" << readLength << '\n';
  // end DEBUG

  this->returnSystemCall(syscallUUID, readLength);
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void* buf, int count) {
  PairKey pairKey = {sockfd, pid};
  if(pairKeyToSucket.find(pairKey) == pairKeyToSucket.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }

  Sucket& sucket = pairKeyToSucket[pairKey];
  ReceiveBuffer& receiveBuffer = sucket.receiveBuffer;

  if(receiveBuffer.data.size() == 0) {
    receiveBuffer.isPending = true;
    receiveBuffer.buf = buf;
    receiveBuffer.count = count;
    receiveBuffer.syscallUUID = syscallUUID;
    return;
  }

  _syscall_read(syscallUUID, receiveBuffer, buf, count);
} 

Packet TCPAssignment::create_packet(Sucket& sucket, uint8_t flags, int dataLength) {
  // packet data section = 0, currently not support data

  size_t packet_size = 54 + dataLength;
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

  uint32_t seq_num = htonl(sucket.seqNum + sucket.sendBuffer.nextSeqNum);
  packet.writeData(SEQ_NUM_OFFSET, &seq_num, SEQ_NUM_LENGTH);

  uint32_t ack_num = htonl(sucket.ackNum);
  packet.writeData(ACK_NUM_OFFSET, &ack_num, ACK_NUM_LENGTH);

  packet.writeData(FLAGS_OFFSET, &flags, FLAGS_LENGTH);
  
  uint16_t rwnd = htons(MBS - sucket.receiveBuffer.data.size());
  // DEBUG
    // std::cout << "CHECK WINDOWSIZE => " << MBS - sucket.receiveBuffer.data.size() << '\n';
  // end DEBUG
  packet.writeData(RWND_OFFSET, &rwnd, RWND_LENGTH);

    //DEBUG
    std::cerr << "Creating packet from ip=" << sucket.localAddr.first << ",port=" << sucket.localAddr.second << " to ip=" << sucket.remoteAddr.first << ",port=" << sucket.remoteAddr.second << " with flags=" << unsigned(flags) << std::flush;
    std::cout << " ackNum=" << sucket.ackNum << ",seqNum=" << ntohl(seq_num) << ",dataLength=" << dataLength << '\n';
  // end DEBUG

  SendBuffer& sendBuffer = sucket.sendBuffer;

  // DEBUG
    // std::cout << "create_packet: sendBuffer.data.size=" << sendBuffer.data.size() << ' ' << sendBuffer.nextSeqNum << '\n';
  // end DEBUG

  for(int i = 0; i < dataLength; ++i) {
    uint8_t dataByte = sendBuffer.data[sendBuffer.nextSeqNum + i];
    packet.writeData(DATA_OFFSET + i, &dataByte, 1);
  }
  sendBuffer.nextSeqNum += dataLength; // update nextSeqNum
  

  uint16_t zero_checksum = 0;
  packet.writeData(CHECKSUM_OFFSET, &zero_checksum, CHECKSUM_LENGTH);
  size_t length = 20 + dataLength;
  uint8_t* tcp_seg = (uint8_t*)malloc(length);
  packet.readData(SOURCE_PORT_OFFSET, tcp_seg, length); // tcp_seg = start index tcp_seg in mem
  uint16_t checksum = htons(~NetworkUtil::tcp_sum(source_ip, dest_ip, tcp_seg, length));

  packet.writeData(CHECKSUM_OFFSET, &checksum, CHECKSUM_LENGTH);
 
  // DEBUG
  // std::cout << "created packet...now sending\n" << std::flush;
  // end DEBUG

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

void TCPAssignment::_update_pending_packets(Sucket& sucket) {
  sucket.sendBuffer.pending_packets.pop_front();
  // DEBUG
    std::cout << "update_pending_packet: pop_front first pending packet, #remain=" << sucket.sendBuffer.pending_packets.size() << '\n';
  // end DEBUG

  this->cancelTimer(sucket.timerKey); // delete current timer anyway
  if(!sucket.sendBuffer.pending_packets.empty()) {
    // DEBUG
      std::cout << "update_pending_packet: RESET TIMER" << '\n';
    // end DEBUG
    UUID key = this->addTimer(sucket.pairKey, TIME_OUT);
    sucket.timerKey = key;
  }
}

void TCPAssignment::_handle_SYN(Address sourceAddr, Address destAddr, uint32_t seqNum, uint16_t windowSize) {
  // DEBUG
    std::cout << "This is SYN FLAG\n" << std::flush;
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
    _update_pending_packets(sucket); // CHECK HERE
    
    sucket.ackNum = seqNum + 1;
    sucket.sendBuffer.windowSize = windowSize;
    return;
  }

  Address listening_zero_addr = destAddr; listening_zero_addr.first = 0;

  if(bindedAddress.find(destAddr) == bindedAddress.end() && bindedAddress.find(listening_zero_addr) == bindedAddress.end()) {
    // DEBUG
      std::cout << "handlesyn...no sucket binded to addr\n" << std::flush;
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
    sucket.sendBuffer.windowSize = windowSize;
    subBindedAddress[sucket.localAddr] = pairKey;

    _send_packet(sucket, SYN_FLAG | ACK_FLAG);

    handshaking[PairAddress{sucket.localAddr, sucket.remoteAddr}] = pairKey;
    connection_queue.capacity --;

    // pairAddressToPairKey[PairAddress{sucket.localAddr, sucket.remoteAddr}] = pairKey;

    // DEBUG
    std::cout << "handlesyn...done sent syn_ack_package, new socket (sockfd=" << pairKey.first << ",pid=" << pairKey.second << ") created..." << std::flush;
    std::cout << "from (ip=" << destAddr.first << ",port=" << destAddr.second << ") to (ip=" << sourceAddr.first << "port=" << sourceAddr.second << ")\n" << std::flush;
    // end DEBUG

    return;
  }
}

void TCPAssignment::_handle_SYN_ACK(Address sourceAddr, Address destAddr, uint32_t ackNum, uint32_t seqNum, uint16_t windowSize) {
  // DEBUG
  // std::cout << "This is SYN|ACK FLAG\n" << std::flush;

  PairAddress pairAddress = {destAddr, sourceAddr};
  if(handshaking.find(pairAddress) == handshaking.end()) {
    // DEBUG  
      std::cout << "handle syn/ack fail: fail: cannot find pair address in handshaking\n" << std::flush;
    // end DEBUG

    return;
  }

  Sucket& sucket = pairKeyToSucket[handshaking[pairAddress]];
  if(sucket.state == TCP_SYN_RCVD) {
    // DEBUG  
      std::cout << "Simultaneous connection handle synack..." << std::flush;
    // end DEBUG
    sucket.state = TCP_ESTABLISHED;
    sucket.ackNum = seqNum + 1;
    sucket.sendBuffer.windowSize = windowSize;
    pairAddressToPairKey[pairAddress] = handshaking[pairAddress];
    handshaking.erase(pairAddress);
    // DEBUG  
      std::cout << "connected\n" << std::flush;
    // end DEBUG
    
    _update_pending_packets(sucket); // CHECK HERE

    if(sucket.isPendingClose) {
      sucket.isPendingClose = false;
      _syscall_close(sucket.pairKey);

      // DEBUG
        std::cout << "handle syn/ack continue: isPendingClose = true => closing sucket now\n";
      // end DEBUG
    }

    return;
  }
  else if(sucket.state != TCP_SYN_SENT || ackNum != sucket.seqNum + 1) {
    // DEBUG  
      std::cout << "handle syn/ack fail: sucket state must be TCP_SYN_SENT or wrong ackNum=" << ackNum << ",seqNum=" << sucket.seqNum << '\n';
    // end DEBUG
    return;
  }

  sucket.state = TCP_ESTABLISHED;
  sucket.ackNum = seqNum + 1;
  sucket.seqNum += 1;
  sucket.sendBuffer.windowSize = windowSize;
  _update_pending_packets(sucket);
  this->returnSystemCall(sucket.connect_syscallUUID, 0);
  
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

void TCPAssignment::_handle_ACK(Address sourceAddr, Address destAddr, uint32_t ackNum, uint32_t seqNum, uint16_t windowSize) {
  // DEBUG
  std::cout << "This is ACK FLAG\n" << std::flush;

  
  PairAddress pairAddress = {destAddr, sourceAddr};
  if(pairAddressToPairKey.find(pairAddress) != pairAddressToPairKey.end()) {
    Sucket& sucket = pairKeyToSucket[pairAddressToPairKey[pairAddress]];
    PairKey pairKey = sucket.pairKey;

    if(sucket.sendBuffer.pending_packets.empty()) {
      // DEBUG
        std::cout << "handle_ACK: not pending packet to ack\n";
      // end DEBUG
      
      return;
    }

    sucket.sendBuffer.windowSize = windowSize;

    bool ackForData = false;
    if(sucket.state == TCP_ESTABLISHED || (sucket.sendBuffer.pending_packets.front().getSize() - 54) > 0)
      ackForData = true;

    if(ackForData) {
      uint32_t dataLength = sucket.sendBuffer.pending_packets.front().getSize() - 54;

      // DEBUG
        std::cout << "handle ACK for data transfer, ackNum=" << ackNum << ", dataLength=" << dataLength << '\n' << std::flush;
      // end DEBUG

      // DEBUG
        std::cout << "handle_ACK datalength=" << dataLength << '\n' << std::flush;
      // end DEBUG
      
      if(ackNum != sucket.seqNum + dataLength) {
        // DEBUG
          std::cout << "handle ACK for data transfer: wrong ACK number=" << ackNum <<", shouldbe=" << sucket.seqNum + dataLength << "\n" << std::flush;
        // end DEBUG
        return;
      }
      
      // ack bytes
      for(int i = 0; i < dataLength; ++i) {
        sucket.sendBuffer.data.pop_front();
      }
      sucket.sendBuffer.nextSeqNum -= dataLength;
      _update_pending_packets(sucket);
      sucket.seqNum += dataLength;

      // free(packet);
      // DEBUG
        std::cout << "acked #bytes=" << dataLength << '\n' << std::flush;
      // end DEBUG

      process_send_buffer(sucket.pairKey.first, sucket.pairKey.second);

      return;
    }
    
    if(sucket.isPendingSimulClose && sucket.state == TCP_FIN_WAIT_1) {
      // DEBUG
        std::cout << "handle_ACK: simultaneous close ending\n";
      // end DEBUG
      if(sucket.seqNum != ackNum) {
        // DEBUG
          std::cout << "handle_ACK: simultaneous close - wrong ackNum=" << ackNum << ",should seqNum=" << sucket.seqNum << '\n';
        // end DEBUG
      }

      // _delete_sucket(sucket);
      sucket.state = TCP_TIME_WAIT;
      this->cancelTimer(sucket.timerKey);
      sucket.isLastTimer = true;
      UUID key = this->addTimer(sucket.pairKey, 4 * TIME_OUT);
      sucket.timerKey = key;
      return;
    }

    if(sucket.seqNum + 1 != ackNum) {
      // DEBUG
        std::cout << "handle_ACK: wrong ackNum=" << ackNum << ",should seqNum + 1=" << sucket.seqNum + 1 << '\n';
      // end DEBUG

      return;
    }
    
    // sucket.seqNum += bytes; -- no data 
    // sucket.ackNum = seqNum + 1;
    // sucket.seqNum += 1;
    _update_pending_packets(sucket);
    if(sucket.state == TCP_FIN_WAIT_1) {
      sucket.state = TCP_FIN_WAIT_2;
      sucket.seqNum += 1;
      // DEBUG
        std::cout << "changed socket state FIN_WAIT_1 -> FIN_WAIT_2\n" << std::flush;
      // end DEBUG
      
    } else if(sucket.state == TCP_LAST_ACK) {
      _delete_sucket(sucket);

      // DEBUG
        std::cout << "disconnected server socket: fd=" << pairKey.first << ",pid=" << pairKey.second << "\n" << std::flush;
      // end DEBUG
    }
  } else if(handshaking.find(pairAddress) != handshaking.end()) {
    Sucket& currSucket = pairKeyToSucket[handshaking[pairAddress]];

    if(currSucket.sendBuffer.pending_packets.empty()) {
      // DEBUG
        std::cout << "handle_ack: handshaking => no pending packet to ack\n";
      // end DEBUG

      return;
    }

    currSucket.state = TCP_ESTABLISHED;
    handshaking.erase(pairAddress);
    pairAddressToPairKey[pairAddress] = currSucket.pairKey;
    ConnectionQueue& connection_queue = pairKeyToConnectionQueue[currSucket.parentPairKey];

    currSucket.seqNum += 1; // UPDATE FOR NEW SEQ-NUM
    currSucket.sendBuffer.windowSize = windowSize;
    // currSucket.sendBuffer.pending_packets.pop_front();
    _update_pending_packets(currSucket);

    // DEBUG
      std::cout << "handle_ack: done connection ready to accept from (ip=" << sourceAddr.first << ",port=" << sourceAddr.second << ") to (ip=" << destAddr.first << ",port=" << destAddr.second << '\n';
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
        std::cout << "Pushed new connection for pending accept syscallUUID=" << syscallUUID << "\n" << std::flush;
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
    std::cout << "handle_ack: connection not found\n" << std::flush;
  }
  
}

void TCPAssignment::_handle_FIN_ACK(Address sourceAddr, Address destAddr, uint32_t ackNum, uint32_t seqNum, uint16_t windowSize) {
  // DEBUG
    std::cout << "this is FIN | ACK flag\n" << std::flush;
  // end DEBUG
  
  PairAddress pairAddress = {destAddr, sourceAddr};
  if(pairAddressToPairKey.find(pairAddress) == pairAddressToPairKey.end()) {
    // DEBUG
      std::cout << "finack handle fail: cannot find connection\n" << std::flush;
    // end DEBUG
    return;
  }

  Sucket& sucket = pairKeyToSucket[pairAddressToPairKey[pairAddress]];
  // sucket.seqNum += 1; 

  if(sucket.state == TCP_TIME_WAIT) {
    if(ackNum != sucket.seqNum + 1) {
      // DEBUG
        std::cout << "handle fin-ack: wrong acknum=" << ackNum << ",shouldbe seqNum+1=" << sucket.seqNum + 1 << '\n';
      // end DEBUG
      return;
    }
    if(seqNum != sucket.ackNum) {
      // DEBUG
        std::cout << "handle fin-ack: wrong seqNum=" << seqNum << ",shouldbe ackNum=" << sucket.ackNum << '\n';
      // end DEBUG
      return;
    }

    sucket.ackNum = seqNum + 1; 
    sucket.sendBuffer.windowSize = windowSize;
    sucket.state = TCP_TIME_WAIT;
    _send_packet(sucket, ACK_FLAG);
    sucket.sendBuffer.pending_packets.pop_front(); // remove FIN-ACK packet
    // check to handle dropped packet here

    _delete_sucket(sucket);
    // bindedAddress.erase(sucket.localAddr);
    // subBindedAddress.erase(sucket.localAddr);
    // pairAddressToPairKey.erase(pairAddress);
    // PairKey pairKey = sucket.pairKey;
    // pairKeyToSucket.erase(pairKey);
    // DEBUG
      std::cout << "finack handle done: disconnected on client\n" << std::flush;
    // end DEBUG
    return;
  }
  else if(sucket.state == TCP_FIN_WAIT_1) {
    if(ackNum != sucket.seqNum) {
      // DEBUG
        std::cout << "handle fin-ack: wrong acknum=" << ackNum << ",shouldbe seqNum=" << sucket.seqNum << '\n';
      // end DEBUG
      return;
    }
    // DEBUG
      std::cout << "handle fin-ack: simultaneous close\n";
    // end DEBUG

    sucket.isPendingSimulClose = true;
    sucket.ackNum = seqNum + 1;
    sucket.seqNum += 1;
    _send_packet(sucket, ACK_FLAG);

    // _delete_sucket(sucket);
    return;
  }
  else if(sucket.state != TCP_ESTABLISHED) {
    // DEBUG
      std::cout << "finack handle fail: sucket state should be TCP_ESTABLISHED\n" << std::flush;
    // end DEBUG
    return;
  }

  if(seqNum != sucket.ackNum) {
    // DEBUG
      std::cout << "handle fin-ack: wrong seqNum=" << seqNum << ",shouldbe ackNum=" << sucket.ackNum << '\n';
    // end DEBUG
    return;
  }

  // server with state == TCP_ESTABLISHED
  sucket.ackNum = seqNum + 1;
  sucket.state = TCP_CLOSE_WAIT;  
  sucket.sendBuffer.windowSize = windowSize;
  _send_packet(sucket, ACK_FLAG);
  sucket.sendBuffer.pending_packets.pop_front();

  // handle auto close-wait
  sucket.isPendingCloseWait = true;
  // this->removeFileDescriptor(sucket.pairKey.second, sucket.pairKey.first);
  // check to handle dropped packet here

  // DEBUG
    std::cout << "finack handle done: closed connection on socket moved -> TCP_CLOSE_WAIT, fd=" << sucket.pairKey.first << ",pid=" << sucket.pairKey.second << "\n" << std::flush;
  // end DEBUG

  if(sucket.sendBuffer.data.size() == sucket.sendBuffer.nextSeqNum) {
    // DEBUG
      std::cout << "handle_ACK: continue close wait process... sending FIN_ACK packet\n";
    // end DEBUG

    _syscall_close(sucket.pairKey);
  }

  return;
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;

  uint8_t flags;
  uint16_t windowSize;
  uint32_t seqNum;
  uint32_t ackNum;
  uint32_t source_ip, dest_ip;
  uint16_t source_port, dest_port;
  uint16_t checksum = 0;
  
  packet.readData(FLAGS_OFFSET, &flags, FLAGS_LENGTH);
  packet.readData(SEQ_NUM_OFFSET, &seqNum, SEQ_NUM_LENGTH);
  packet.readData(ACK_NUM_OFFSET, &ackNum, ACK_NUM_LENGTH);
  packet.readData(SOURCE_IP_OFFSET, &source_ip, SOURCE_IP_LENGTH);
  packet.readData(SOURCE_PORT_OFFSET, &source_port, SOURCE_PORT_LENGTH);
  packet.readData(DEST_IP_OFFSET, &dest_ip, DEST_IP_LENGTH);
  packet.readData(DEST_PORT_OFFSET, &dest_port, DEST_PORT_LENGTH);
  packet.readData(RWND_OFFSET, &windowSize, RWND_LENGTH);
  packet.readData(CHECKSUM_OFFSET, &checksum, CHECKSUM_LENGTH);

  seqNum = ntohl(seqNum);
  ackNum = ntohl(ackNum);
  source_ip = ntohl(source_ip);
  source_port = ntohs(source_port);
  dest_ip = ntohl(dest_ip);
  dest_port = ntohs(dest_port);
  windowSize = ntohs(windowSize);
  checksum = ntohs(checksum);

  uint16_t zero_checksum = 0;
  packet.writeData(CHECKSUM_OFFSET, &zero_checksum, CHECKSUM_LENGTH);
  size_t length = 20 + (int)(packet.getSize() - 54);
  uint8_t* tcp_seg = (uint8_t*)malloc(length);
  packet.readData(SOURCE_PORT_OFFSET, tcp_seg, length); // tcp_seg = start index tcp_seg in mem
  uint16_t expected_checksum = ~NetworkUtil::tcp_sum(htonl(source_ip), htonl(dest_ip), tcp_seg, length);
  
  if(checksum != expected_checksum) {
    // DEBUG
      std::cout << "packetArrived: Wrong checksum\n";
    // end DEBUG
    return;
  }

  Address sourceAddr = {source_ip, source_port};
  Address destAddr = {dest_ip,dest_port};
  PairAddress pairAddress {destAddr, sourceAddr};
  
  // DEBUG
    std::cout << "packetArrived: packet arrived from (ip=" << sourceAddr.first << ",port=" << sourceAddr.second << ") to (ip=" << dest_ip << ",port=" << dest_port << ") flags=" << unsigned(flags) << std::flush;
    std::cout << " ackNum=" << ackNum << ",seqNum=" << seqNum << ",dataLength=" << packet.getSize() - 54 << '\n';
  // end DEBUG

  // START - Handle incoming data
  if(packet.getSize() > 54) {
    // DEBUG
      std::cout << "packetArrived: handling data ACK\n";
    // end DEBUG

    if(flags != ACK_FLAG) {
      std::cout << "Data packet should has flag = ACK\n";
      return;
    }
    
    if(pairAddressToPairKey.find(pairAddress) == pairAddressToPairKey.end()) {
      // DEBUG
        std::cout << "handle_incoming_data: cannot find pairAddress\n";
      // end DEBUG
      return;
    }
    
    Sucket& sucket = pairKeyToSucket[pairAddressToPairKey[pairAddress]];
    if(ackNum != sucket.seqNum) {
      // DEBUG
        std::cout << "handle_incoming_data: packet wrong ACKNUM, currSeqNum=" << sucket.seqNum << '\n';      
      // end DEBUG
      if(!sucket.receiveBuffer.lastAckPacket.empty())
        sendPacket(std::string("IPv4"), sucket.receiveBuffer.lastAckPacket.front());
      return;
    }
    
    if(seqNum != sucket.ackNum) {
      // DEBUG
        std::cout << "handle_incoming_data: packet wrong SeqNum, ackNum=" << sucket.ackNum << '\n';      
      // end DEBUG
      if(!sucket.receiveBuffer.lastAckPacket.empty())
        sendPacket(std::string("IPv4"), sucket.receiveBuffer.lastAckPacket.front());

      return;
    }

    sucket.sendBuffer.windowSize = windowSize;
    int dataLength = packet.getSize() - 54;
    for(int i = 0; i < dataLength; ++i) { // check out of memory here
      uint8_t byte = 0;
      packet.readData(DATA_OFFSET + i, &byte, 1);
      sucket.receiveBuffer.data.push_back(byte);
    }
    sucket.ackNum = seqNum + dataLength; // CHECK here

    // DEBUG
      std::cout << "packetArrived: acked #bytes=" << dataLength << '\n';
    // end DEBUG

    if(sucket.receiveBuffer.isPending) {
      _syscall_read(sucket.receiveBuffer.syscallUUID, sucket.receiveBuffer, sucket.receiveBuffer.buf, sucket.receiveBuffer.count);
      sucket.receiveBuffer.isPending = false;
    }
    _send_packet(sucket, ACK_FLAG);

    return;
  }
  // END - Handle incoming data

  if(flags == SYN_FLAG) _handle_SYN(sourceAddr, destAddr, seqNum, windowSize);
  else if(flags == (SYN_FLAG | ACK_FLAG)) _handle_SYN_ACK(sourceAddr, destAddr, ackNum, seqNum, windowSize);
  else if(flags == ACK_FLAG) _handle_ACK(sourceAddr, destAddr, ackNum, seqNum, windowSize);
  else if(flags == (FIN_FLAG | ACK_FLAG)) _handle_FIN_ACK(sourceAddr, destAddr, ackNum, seqNum, windowSize);
  else {
    std::cout << "packetArrived: packet handle fail: No FLAG seen: " << unsigned(flags) << "\n" << std::flush;
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  std::cout << "timeout\n";
  try {
    PairKey pairKey = std::any_cast<PairKey>(payload);
    Sucket& sucket = pairKeyToSucket[pairKey];

    if(sucket.isLastTimer) {
      // DEBUG
        std::cout << "timer: last Timer - closing connection\n";
      // end DEBUG
      _delete_sucket(sucket);
      return;
    }

    if(sucket.sendBuffer.pending_packets.empty()) {
      // DEBUG
        std::cout << "timer: empty pending queue\n";
      // end DEBUG
      return;
    }
    for(Packet packet: sucket.sendBuffer.pending_packets) {
      sendPacket(std::string("IPv4"), packet);
    }

    // DEBUG
      std::cout << "timer: re-send #packets=" << sucket.sendBuffer.pending_packets.size() << '\n';
      if(sucket.state == TCP_FIN_WAIT_2) {
        sucket.finWait2 += 1;
        if(sucket.finWait2 >= 200) {
          _delete_sucket(sucket);
        }
      }
    // end DEBUG
    UUID key = this->addTimer(pairKey, TIME_OUT);
    sucket.timerKey = key;

  } catch (const std::bad_any_cast& e) {
    std::cout << "ERROR timerCallback: " << e.what() << "\n" << std::flush;
  }
}

} // namespace E
