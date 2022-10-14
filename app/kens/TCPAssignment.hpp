/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

namespace E {

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

protected:

  enum TCP_STATE {
    TCP_CLOSED,
    TCP_LISTEN,
    TPC_SYN_RCVD,
    TCP_ESTABLISHED,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    //----------//
    TCP_SYN_SENT,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_TIME_WAIT,
  }; 

  // structs
  struct Address {
    int port;
    int ip;
    Address(int port, int ip): port(port), ip(ip) {}
  };

  struct BufferRcv {
    int bytesRcvd;
    std::queue<uint8_t> bufferData;
    BufferRcv() : bytesRcvd(0), bufferData(std::queue<uint8_t>()) {}
  };

  struct BufferSnd {
    int bytesSnd;
    int bytesAck;
    int cwnd;
    std::queue<uint8_t> bufferData;
    BufferSnd(): bytesSnd(0), bytesAck(0), bufferData(std::queue<uint8_t>()) {}
  };

  struct Sucket {
    // Address localAddr();
    // Address remoteAddr();
    std::pair<int, int> pairKey;
    BufferRcv bufferRcv;
    BufferSnd bufferSnd;
    TCP_STATE state;
    UUID syscall_id;
    uint32_t seqNum;
    uint32_t ackNum;
    Sucket() : state(TCP_CLOSED) {}
    Sucket(std::pair<int, int> pairKey, TCP_STATE state): pairKey(pairKey), state(state) {}
  };

  // maps & set
  std::unordered_map<std::pair<int, int>, std::pair<sockaddr, socklen_t>> pairKeyToAddrInfo; 
  std::unordered_map<std::pair<int, int>, Sucket> pairKeyToSucket;  
  std::unordered_set<std::pair<int, int>> pairKeySet;
  std::unordered_set<std::pair<uint32_t, uint16_t>> bindedAddress; 



  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
  virtual int _syscall_socket(int pid) final;
	virtual void syscall_socket(UUID syscallUUID, int pid, int type, int protocol) final;
  virtual int _syscall_bind( int sockfd, int pid, struct sockaddr *addr, socklen_t addrlen) final;
  virtual void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) final;
  virtual void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) final;
  virtual void syscall_close(UUID syscallUUID, int pid, int sockfd) final;
  virtual void _sendPacket(Sucket sucket, uint8_t type) final;
}; 

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
