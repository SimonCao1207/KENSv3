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
#include <random>

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
  #define DATA_OFFSET 54

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

  #define FIN_FLAG	0x01
  #define SYN_FLAG	0x02
  #define RST_FLAG	0x04
  #define PSH_FLAG	0x08
  #define ACK_FLAG	0x10
  #define URG_FLAG	0x20
  #define MSS 1460 // max segment size
  #define MBS 51200// max buffer size
  #define TIME_OUT 5000000

  // constants

  
  // typedef
  typedef std::pair<int, int> PairKey; // (sockfd, id) - sucketkey
  typedef std::pair<uint32_t, uint16_t> Address; // (ip, port)
  typedef std::pair<Address, Address> PairAddress; // localAddr, remoteAddr
  typedef std::pair<sockaddr, socklen_t> AddressInfo; // (sockaddr, socklen_t)

  enum TCP_STATE {
    TCP_CLOSED,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RCVD,
    TCP_ESTABLISHED,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    //----------//
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_TIME_WAIT,
  }; 

  AddressInfo addrToAddrInfo(Address addr) {
    sockaddr_in addr_in;
    socklen_t len = sizeof(addr_in);
    memset(&addr_in, 0, len);

    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = htonl(addr.first);
    addr_in.sin_port = htons(addr.second);
    return AddressInfo{*((sockaddr *) &addr_in), len};
  }

  Address addrInfoToAddr (AddressInfo addrInfo) {  
    sockaddr_in address = *((sockaddr_in *) &addrInfo.first);
    uint32_t ip = ntohl(address.sin_addr.s_addr);
    uint16_t port = ntohs(address.sin_port);
    return std::make_pair(ip, port);
  }

  struct PendingAccept {
    bool isPending;
    UUID syscallUUID;
    struct sockaddr * addr;
    socklen_t * addrlen;
    PendingAccept(): isPending(false) {}
  };

  struct SendBuffer {
    int nextSeqNum; // index of next byte to send
    int windowSize;
    std::deque<uint8_t> data;
    std::deque<Packet> pending_packets;
    SendBuffer(): data(std::deque<uint8_t>()),
                  windowSize(0),
                  nextSeqNum(0),
                  pending_packets(std::deque<Packet>())
                  {}
  };

  struct ReceiveBuffer {
    bool isPending;
    UUID syscallUUID;
    int count;
    void* buf;
    std::deque<uint8_t> data;
    std::deque<Packet> lastAckPacket;
    ReceiveBuffer(): isPending(false), data(std::deque<uint8_t>()) {}
  };

  // struct ConnectionController {
  //   bool isConnecting;
  //   UUID syscallUUID;
  // };

  struct Sucket {
    Address localAddr;
    Address remoteAddr;
    PairKey pairKey;
    PairKey parentPairKey;
    TCP_STATE state;
    uint32_t seqNum;
    uint32_t ackNum;
    PendingAccept pendingAccept;
    SendBuffer sendBuffer;
    ReceiveBuffer receiveBuffer;
    bool isPendingClose;
    bool isPendingSimulClose;
    bool isLastTimer;
    bool isPendingCloseWait;
    UUID connect_syscallUUID;
    UUID timerKey;
    uint8_t lastActionFlag;
    int finWait2;
    Sucket() : state(TCP_CLOSED), isPendingClose(false) {
      seqNum = uint32_t(rand()) + uint32_t(rand()) * uint32_t(rand());
      isPendingSimulClose = false;
      isLastTimer = false;
      isPendingCloseWait = false;
      finWait2 = 0;
    }
    Sucket(PairKey pairKey, TCP_STATE state) : pairKey(pairKey), state(state), isPendingClose(false) {
      // Initialize random seq_num here
      seqNum = uint32_t(rand()) + uint32_t(rand()) * uint32_t(rand());
      isPendingSimulClose = false;
      isLastTimer = false;
      isPendingCloseWait = false;
      finWait2 = 0;
    }
    Sucket(PairKey pairKey, Address localAddr, Address remoteAddr, TCP_STATE state): pairKey(pairKey), localAddr(localAddr), remoteAddr(localAddr), state(state), isPendingClose(false) {
      seqNum = uint32_t(rand()) + uint32_t(rand()) * uint32_t(rand());
      isPendingSimulClose = false;
      isLastTimer = false;
      isPendingCloseWait = false;
      finWait2 = 0;
    }
  };

  struct ConnectionQueue { // queue of established connection ready for accept (from server)
    int capacity;
    std::queue<PairKey> cqueue;
    ConnectionQueue(): capacity(0), cqueue(std::queue<PairKey>()) {}
    ConnectionQueue(int capacity): capacity(capacity), cqueue(std::queue<PairKey>()) {}
  };

  // maps & set
  // std::unordered_map<PairKey, AddressInfo> pairKeyToAddrInfo; 
  std::unordered_map<Address, PairKey> bindedAddress; // directly binded suckets (server listener or client connector)
  std::unordered_map<Address, PairKey> subBindedAddress; // children-suckets of server listener (each listener spawn new child-sucket when handle SYN packet)
  std::unordered_map<PairKey, Sucket> pairKeyToSucket;  
  std::unordered_map<PairAddress, PairKey> pairAddressToPairKey;
  std::unordered_map<PairAddress, PairKey> handshaking; // map from pairAddr to sucket which is currently in handshaking state (not established)
  std::unordered_map<PairKey, ConnectionQueue> pairKeyToConnectionQueue;

  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
  virtual int _syscall_socket(int pid) final;
	virtual void syscall_socket(UUID syscallUUID, int pid, int type, int protocol) final;
  virtual int _syscall_bind( int sockfd, int pid, struct sockaddr *addr, socklen_t addrlen) final;
  virtual void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) final;
  virtual void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) final;
  virtual void syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen) final;
  virtual Packet create_packet(struct Sucket&, uint8_t, int) final;
  virtual void syscall_close(UUID syscallUUID, int pid, int sockfd) final;
  virtual void _send_packet(Sucket& sucket, uint8_t type, int) final;
  virtual void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog) final;
  virtual void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr* addr, socklen_t* addrlen) final;
  virtual int _syscall_getpeername(int sockfd, int pid, struct sockaddr * addr, socklen_t * addrlen) final;
  virtual void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen) final;
  virtual void _handle_SYN(Address sourceAddr, Address destAddr, uint32_t ackNum, uint16_t windowSize) final;
  virtual void _handle_SYN_ACK(Address sourceAddr, Address destAddr, uint32_t ackNum, uint32_t seqNum, uint16_t windowSize) final;
  virtual void _handle_ACK(Address sourceAddr, Address destAddr, uint32_t ackNum, uint32_t seqNum, uint16_t windowSize) final;
  virtual void _handle_FIN_ACK(Address sourceAddr, Address destAddr, uint32_t ackNum, uint32_t seqNum, uint16_t windowSize) final;
  virtual void _syscall_close(PairKey pairKey) final;
  virtual void syscall_write(UUID syscallUUID, int pid, int sockfd, const void* buf, int count) final;
  virtual void process_send_buffer(int sockfd, int pid) final;
  virtual void syscall_read(UUID syscallUUID, int pid, int sockfd, void* buf, int count) final;
  virtual void _syscall_read(UUID syscallUUID, struct ReceiveBuffer& receiveBuffer, void* buf, int count) final;
  virtual void _update_pending_packets(Sucket& sucket) final;
  virtual void _delete_sucket(Sucket& sucket) final;
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
