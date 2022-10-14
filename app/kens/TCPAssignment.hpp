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
  // define
  #define VERSION_HEADER_LENGTH_OFFSET 14
  // #define SERVICE_TYPE_OFFSET 15 
  #define DATAGRAM_LENGTH_OFFSET 16
  #define SOURCE_IP_OFFSET 26 // 14 + 12
  #define DEST_IP_OFFSET 30 // 26 + 4
  #define SOURCE_PORT_OFFSET 34 
  #define DEST_PORT_OFFSET 36
  #define SEQ_NUM_OFFSET 38
  #define ACK_NUM_OFFSET 42
  #define FLAGS_OFFSET 47 
  #define RWND_OFFSET 48 // ADD 1 FOR HEADER
  #define CHECKSUM_OFFSET 50
  #define URGDATA_OFFSET 52
  #define OPTIONS_OFFSET 54
  // #define DATA_OFFSET 52 + buffer_size

  #define VERSION_HEADER_LENGTH 1 // BYTE
  // #define SERVICE_TYPE_OFFSET 1
  #define DATAGRAM_LENGTH 2
  #define SOURCE_PORT_LENGTH 2
  #define SOURCE_IP_LENGTH 4
  #define DEST_PORT_LENGTH 2
  #define DEST_IP_LENGTH 4
  #define SEQ_NUM_LENGTH 4
  #define ACK_NUM_LENGTH 4
  #define FLAGS_LENGTH 1 // ADD 1 FOR HEADER
  #define RWND_LENGTH 2
  #define CHECKSUM_LENGTH 2
  #define URGDATA_LENGTH 2
  #define OPTIONS_LENGTH 4
  #define DATA_LENGTH 4

  // constants
  const uint8_t CWR_FLAG = (1 << 7);
  const uint8_t ECE_FLAG = (1 << 6);
  const uint8_t URG_FLAG = (1 << 5);
  const uint8_t ACK_FLAG = (1 << 4);
  const uint8_t PSH_FLAG = (1 << 3);
  const uint8_t RST_FLAG = (1 << 2);
  const uint8_t SYN_FLAG = (1 << 1);
  const uint8_t FIN_FLAG = (1 << 0);


  // typedef
  typedef std::pair<int, int> PairKey; // (sockfd, id)

  // structs
  struct Address {
    uint16_t port;
    uint32_t ip;
    Address(uint32_t ip, uint16_t port): port(port), ip(ip) {}
  };

  struct BufferRcv {
    int bytesRcvd;
    int bytesAck;
    std::queue<uint8_t> bufferData;
    BufferRcv() : bytesRcvd(0), bytesAck(0), bufferData(std::queue<uint8_t>()) {}
  };

  struct BufferSnd {
    int bytesSnd;
    int bytesAck;
    int cwnd;
    std::queue<uint8_t> bufferData;
    BufferSnd(): bytesSnd(0), bytesAck(0), bufferData(std::queue<uint8_t>()) {}
  };

  struct Sucket {
    Address localAddr;
    Address remoteAddr;
    PairKey pairKey;
    BufferRcv bufferRcv;
    BufferSnd bufferSnd;
    uint8_t state;
    UUID syscall_id;
    uint32_t seqNum;
    uint32_t ackNum;

    Sucket(PairKey pairKey, Address localAddr, uint8_t state): pairKey(pairKey), localAddr(localAddr), remoteAddr(localAddr), state(state) {}
  };

  // maps & set
  std::unordered_map<PairKey, std::pair<sockaddr, socklen_t>> processToAddrInfo; 
  std::unordered_set<PairKey> pairKeySet;
  std::unordered_set<std::pair<uint32_t, uint16_t>> bindedAddress;
  std::unordered_map<PairKey, Sucket> pairKeyToSucket;  



  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;

  virtual int _syscall_socket(int pid) final;
	virtual void syscall_socket(UUID syscallUUID, int pid, int type, int protocol) final;
  virtual int _syscall_bind( int sockfd, int pid, struct sockaddr *addr, socklen_t addrlen) final;
  virtual void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) final;
  virtual void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) final;
  virtual void syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen) final;
  virtual Packet* create_packet(struct Sucket&, uint8_t) final;
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
