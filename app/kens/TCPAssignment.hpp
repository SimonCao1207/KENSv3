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

  // struct myHash {
	// size_t operator()(const std::pair<int, int> &x) const {
	// 	return x.first ^ x.second;
	// }
  // };

  // struct myAddrHash {
	// size_t operator()(const std::pair<uint32_t, uint16_t> &addr) const{
	// 	return addr.first ^ addr.second;
	// }
  // };

  // std::unordered_map<std::pair<int, int>, std::pair<sockaddr, socklen_t>, myHash> processToAddrInfo; 
  // std::unordered_set<std::pair<int, int>, myHash> pairKeySet;

  std::unordered_map<std::pair<int, int>, std::pair<sockaddr, socklen_t>> processToAddrInfo; 
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
