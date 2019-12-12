/******************************************************************************
 * Project:   3BIT ISA, Project, DHCPv6 relay                                 *
 *            Faculty of Information Technology                               *
 *            Brno University of Technology                                   *
 * File:      packet_handler.cpp                                              *
 * Date:      18.11.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

/***** Local modules *****/
#include "../headers/packet_handler.h"
#include "../headers/relay_struc.h"
#include "../headers/colors.h"

/***** Standard libraries *****/
#include <iostream>
#include <unistd.h> 
#include <string.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h>
#include <err.h>

/***** Network libraries *****/
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>

/***** Useful macros *****/
#define IPv6_HEADER_LENGTH 40
#define UDP_HEADER_LENGTH 8
#define ETH_HEADER_LENGTH 14
#define PACKET_SIZE 550
#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547
#define SOLICIT_MSG_TYPE 0x01
#define REQUEST_MSG_TYPE 0x03
#define CONFIRM_MSG_TYPE 0x04
#define RENEW_MSG_TYPE 0x05
#define REBIND_MSG_TYPE 0x06
#define RELAY_FORWARD_MSG_TYPE 0x0c
#define IPV6_LL_TYPE 0
#define IPV6_GUA_ULA_TYPE 1
#define MAC_ADDR_SIZE 20

/***** Method gets ipv6 link-local address of specific interface *****/
int PacketHandler::get_ipv6_addr(RelayStruc *relay_struc, char *ipv6_lladdr, char *interface, int address_type) {
    struct ifaddrs *ifa, *ifa_tmp;

    if (getifaddrs(&ifa) == -1) {
        std::cerr << KRED "ERROR: Getifaddrs failed\n" KWHT;
        return 1;
    }

    ifa_tmp = ifa;
    while (ifa_tmp) {
        if ((ifa_tmp->ifa_addr) && (ifa_tmp->ifa_addr->sa_family == AF_INET6)) {
            
            // create IPv6 string
            struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
            inet_ntop(AF_INET6, &in6->sin6_addr, ipv6_lladdr, INET6_ADDRSTRLEN);

            if (address_type == IPV6_LL_TYPE) {
              if (!memcmp(ipv6_lladdr, "fe80::", 6) && !(strcmp(ifa_tmp->ifa_name, interface))) {
                  return 0;
              }
            }
            else if (address_type == IPV6_GUA_ULA_TYPE) {
              if (!memcmp(relay_struc->parse_struc.server_id.c_str(), "fc", 2) || !memcmp(relay_struc->parse_struc.server_id.c_str(), "fd", 2)) {
                if ((!memcmp(ipv6_lladdr, "fc", 2) || !memcmp(ipv6_lladdr, "fd", 2)) && !(strcmp(ifa_tmp->ifa_name, interface))) {
                  return 0;
                }
              }
              else {
                if (!memcmp(ipv6_lladdr, "2001:", 5) && !(strcmp(ifa_tmp->ifa_name, interface))){
                  return 0;
                }
              }
            }
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }

    ifa_tmp = ifa;
    while (ifa_tmp) {
        if ((ifa_tmp->ifa_addr) && (ifa_tmp->ifa_addr->sa_family == AF_INET6)) {
            
            // create IPv6 string
            struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
            inet_ntop(AF_INET6, &in6->sin6_addr, ipv6_lladdr, INET6_ADDRSTRLEN);
            
            if (address_type == IPV6_LL_TYPE) {
              if (!memcmp(ipv6_lladdr, "fe80::", 6) && !(strcmp(ifa_tmp->ifa_name, interface))) {
                  return 0;
              }
            }
            else if (address_type == IPV6_GUA_ULA_TYPE) {
              if (!memcmp(relay_struc->parse_struc.server_id.c_str(), "fc", 2) || !memcmp(relay_struc->parse_struc.server_id.c_str(), "fd", 2)) {
                if (!memcmp(ipv6_lladdr, "2001:", 5) && !(strcmp(ifa_tmp->ifa_name, interface))){
                  return 0;
                }
              }
              else {
                if ((!memcmp(ipv6_lladdr, "fc", 2) || !memcmp(ipv6_lladdr, "fd", 2)) && !(strcmp(ifa_tmp->ifa_name, interface))) {
                  return 0;
                }
              }
            }
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }

    return 1;
}

/***** Method gets mac address of specific interface *****/
int PacketHandler::get_mac_addr(RelayStruc *relay_struc, char *interface_name, uint8_t  *mac_address_byte)
{
  struct ifaddrs *ifaddr=NULL;
  struct ifaddrs *ifa = NULL;
  int i = 0;
  
  if (getifaddrs(&ifaddr) == -1)
  {
    std::cerr << "getifaddrs\n";
    return 1;
  }
  else
  {
    char *mac_address = (char *) malloc(6);
    if (mac_address == NULL) {
      std::cerr << "ERROR: Problem with memory allocation\n";
      return 1;
    }

    for ( ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
      if ( (ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET) && (!strcmp(ifa->ifa_name, relay_struc->parse_struc.interface_id.c_str())))
      {
        struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
        
        for (i=0; i <s->sll_halen; i++)
        {
          sprintf(mac_address+i*3,"%02x%c", (s->sll_addr[i]), (i+1!=s->sll_halen)?':':'\n');
        }
      }
    }
    sscanf(mac_address, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac_address_byte[0],
                                                          &mac_address_byte[1],
                                                          &mac_address_byte[2],
                                                          &mac_address_byte[3],
                                                          &mac_address_byte[4],
                                                          &mac_address_byte[5]);
    freeifaddrs(ifaddr);
    free(mac_address);
  }

  return 0;
}

/***** Method receives packet from client ****/
int PacketHandler::receive_client_packet(RelayStruc *relay_struc) {
  /*--- Finding interfaces ---*/
  char *dev; /* Device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */

  dev = (char *) malloc(relay_struc->parse_struc.interface_id.length());
  if (dev == NULL) {
    std::cerr << KRED "ERROR: Problem with memory allocation\n" KWHT;
    return 1;
  }
  strcpy(dev, (relay_struc->parse_struc.interface_id.c_str()));

  /*--- Getting device netmask ---*/
  bpf_u_int32 mask = 0; // The netmask of our sniffing device
  bpf_u_int32 net = 0; // The IP of our sniffing device

  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    std::cerr << KRED "ERROR: Couldn't get netmask for device " << dev << "\n" KWHT;
  	net = 0;
    mask = 0;
    return 1;
  }

  /*--- Opening interface ---*/
  pcap_t *handle; // Session handle
  if ((handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL) {
    std::cerr << KRED "ERROR: Couldn't open device " << dev << "\n" KWHT;
    return 1;
  }

  /*--- Checking link-layer header ---*/
  if (pcap_datalink(handle) != DLT_EN10MB) {
    std::cerr << KRED "ERROR: Device " << dev << " doesn't provide Ethernet headers - not supported\n" KWHT;
    free(dev);
    pcap_close(handle);
    return 1;
  }

  /*--- Setting up sniffing filter ---*/
  char filter_exp[] = "port 546 or port 547"; // The filter expression
  struct bpf_program fp; // The compiled filter expression

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    std::cerr << KRED "ERROR: Couldn't parse filter\n" KWHT;
    return 1;
  }

  if (pcap_setfilter(handle, &fp) == -1) {
      std::cerr << KRED "ERROR: Couldn't install filter\n" KWHT;
		 return 1;
	}

  /*--- Starts with sniffing ---*/
  struct pcap_pkthdr header; // The header that pcap gives us
  const u_char *packet; // The actual packet
  struct ether_header *eptr;
  struct ip6_hdr *my_ip6;
  const u_char *dhcpv6_header;

  /*--- Grab a packet ---*/
  packet = pcap_next(handle,&header);
  
  /*--- Analyze pacclient_ket ---*/
  eptr = (struct ether_header *) packet;

  /*--- Copy MAC address for relay output ---*/
  relay_struc->client_mac_addr = (char *) malloc(MAC_ADDR_SIZE);
  if (relay_struc->client_mac_addr == NULL) {
    std::cerr << KRED "ERROR: Problem with memory allocation\n" KWHT;
    return 1;
  }
  relay_struc->client_mac_addr = ether_ntoa((const struct ether_addr *)&eptr->ether_shost);

  /* Analyzing captured packet */
  if (ntohs(eptr->ether_type) == ETHERTYPE_IPV6) 
  { 
    my_ip6 = (struct ip6_hdr*) (packet + ETH_HEADER_LENGTH); // Pointer to IPv6 header
    relay_struc->client_ip_addr = my_ip6->ip6_src;
    dhcpv6_header = packet + ETH_HEADER_LENGTH + IPv6_HEADER_LENGTH + UDP_HEADER_LENGTH;

    /* Captured packet is solicit */
    if (((*dhcpv6_header) == SOLICIT_MSG_TYPE) || 
        ((*dhcpv6_header) == RENEW_MSG_TYPE) || 
        ((*dhcpv6_header) == CONFIRM_MSG_TYPE)) {
      relay_struc->client_captured_packet_type = SOLICIT_MSG_TYPE;
      /* Copy packet to parse struc */
      relay_struc->rec_client_solic_pack = (u_char *) malloc(header.len);
      if (relay_struc->rec_client_solic_pack == NULL) {
        std::cerr << KRED "ERROR: Problem with memory allocation\n" KWHT;
        return 1;
      }
      memcpy(relay_struc->rec_client_solic_pack, packet, header.len);
      relay_struc->rec_client_solic_pack_len = header.len;
    }
    /* Captured packet is request */
    else if (((*dhcpv6_header) == REQUEST_MSG_TYPE) || 
             ((*dhcpv6_header) == REBIND_MSG_TYPE)) {
      relay_struc->client_captured_packet_type = REQUEST_MSG_TYPE;
      /* Copy packet to parse struc */
      relay_struc->rec_client_request_pack = (u_char *) malloc(header.len);
      if (relay_struc->rec_client_request_pack == NULL) {
        std::cerr << KRED "ERROR: Problem with memory allocation\n" KWHT;
        return 1;
      }
      memcpy(relay_struc->rec_client_request_pack, packet, header.len);
      relay_struc->rec_client_request_pack_len = header.len;
    }
    /* Captured packet is bot valid */
    else {
      std::cerr << KRED "ERROR: Captured packet from client is not valid\n" KWHT;
      free(dev);
      pcap_close(handle);  
      return 2;
    }
  }           

  /*-- And close the session ---*/
  free(dev);
  pcap_close(handle);

  return 0;
}

/******************************************************** Method sends packet to server ****************************************************************/
int PacketHandler::send_server_solicit(RelayStruc *relay_struc) {
  /*--- Create socket ---*/
  sockaddr_in6 servaddr, relayaddr;
  
  int fd = socket(AF_INET6,SOCK_DGRAM,0);
  if(fd<0){
      std::cerr << KRED "ERROR: Cannot create socket\n" KWHT;
      return 1;
  }

  /*--- Setting source for packet ---*/
  memset(&relayaddr, 0, sizeof(relayaddr));
  relayaddr.sin6_family = AF_INET6;
  relayaddr.sin6_addr = in6addr_any;
  relayaddr.sin6_port = htons(DHCPV6_SERVER_PORT);
  
  /*--- Binding source ---*/
  if (bind(fd, (struct sockaddr *) &relayaddr, sizeof(relayaddr)) < 0) {
    std::cerr << KRED "ERROR: Cannot bind source to socket\n" KWHT;
    return 1;
  }  

  /*--- Setting destination for packet ---*/
  char *server_ip = const_cast<char*>(relay_struc->parse_struc.server_id.c_str()); 
  bzero(&servaddr,sizeof(servaddr));
  servaddr.sin6_family = AF_INET6;
  inet_pton(AF_INET6, server_ip, &(servaddr.sin6_addr));
  servaddr.sin6_port = htons(DHCPV6_SERVER_PORT);


  /*--- Filling relay message ---*/
  u_char relay_msg[PACKET_SIZE];
  int offset = 0;

  memset(relay_msg, 0, PACKET_SIZE);

  /*--- Setting message type field in relay-forward message ---*/
  relay_msg[offset++] = RELAY_FORWARD_MSG_TYPE;
  
  /*--- Setting hopcount field in relay-forward message ---*/
  relay_msg[offset++] = 0x00;

  /*--- Setting link-address in relay-forward message ---*/
  /* IP adresa rozhrania na ktorej bol prijaty packet */
  struct sockaddr_in6 in6;
  char link_address_str[INET6_ADDRSTRLEN];

  if (get_ipv6_addr(relay_struc, link_address_str, (char *) (relay_struc->parse_struc.interface_id.c_str()), IPV6_GUA_ULA_TYPE)) {
    std::cerr << KRED "ERROR: Cannot find GUA or ULA addres on interface: " << relay_struc->parse_struc.interface_id.c_str() << " and link-local is not supported\n" KWHT;
    return 1;
  }
  inet_pton(AF_INET6, link_address_str, &(in6.sin6_addr));
  int link_address_size = sizeof(in6.sin6_addr);
  memcpy(relay_msg+2, &(in6.sin6_addr), link_address_size);
  offset = offset + link_address_size;

  /*--- Setting peer-address in relay-forward message ---*/
  /* IP adresa clienta od ktoreho bol priajty packet */
  int peer_address_size = sizeof(relay_struc->client_ip_addr);
  memcpy(relay_msg+offset, &(relay_struc->client_ip_addr), peer_address_size);
  offset = offset + peer_address_size;
  
  /*--- Setting option rellay message in relay-forward message ---*/
  // Option rellay message
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = 0x09;
  // Rellay message len
  int dhcpv6_msg_len = relay_struc->rec_client_solic_pack_len - ETH_HEADER_LENGTH - IPv6_HEADER_LENGTH - UDP_HEADER_LENGTH;
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = dhcpv6_msg_len;  
  // Rellay message value
  const u_char *address; 
  address = (u_char *) relay_struc->rec_client_solic_pack + ETH_HEADER_LENGTH + IPv6_HEADER_LENGTH + UDP_HEADER_LENGTH;
  memcpy(relay_msg+offset, address, dhcpv6_msg_len);
  offset += dhcpv6_msg_len; 
  
  /*--- Setting option client link-layer in relay-forward message ---*/
  struct ether_header *eptr;
  eptr = (struct ether_header *) relay_struc->rec_client_solic_pack;
  // Option client link-layer 
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = 0x4f;
  // Length
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = sizeof(eptr->ether_shost) + 2;
  // Interface-type
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = 0x01;
  // Value
  mempcpy(relay_msg+offset, eptr->ether_shost, sizeof(eptr->ether_shost));
  offset = offset + sizeof(eptr->ether_shost);
  /*----------------------- Setting option interface-id in relay-forward message -----------------------*/
  // Option interface-id
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = 0x12;
  // Length 
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = sizeof(eptr->ether_dhost);
  // Value
  u_char if_id_value[6];
  this->get_mac_addr(relay_struc, (char *) relay_struc->parse_struc.interface_id.c_str(), if_id_value);
  mempcpy(relay_msg+offset, if_id_value, 6);
  offset = offset + 6;
  
  /*--- Sending relay message ---*/
  if (sendto(fd, &relay_msg, offset, 0, (sockaddr*)&servaddr, sizeof(servaddr)) <= 0) {
      std::cerr << KRED "ERROR: Cannot send solicit packet to server\n" KWHT;;
      close(fd);
      return 1;
  }

  // Saving socket descr for other functions
  relay_struc->fd1 = fd; 

  return 0;
}

/***** Method receives packet from server ****/
int PacketHandler::receive_server_advertise(RelayStruc *relay_struc) {
  /* Get socket descr */
  int fd = relay_struc->fd1;
  
  /* Receive packet */
  char recv_buffer[PACKET_SIZE];
  struct sockaddr_storage src_addr;
  socklen_t src_addr_len=sizeof(src_addr);
  
  ssize_t count=recvfrom(fd,recv_buffer,sizeof(recv_buffer),0,(struct sockaddr*)&src_addr,&src_addr_len);
  if (count==-1) {
      std::cerr << "ERROR: Problem with receiving advertise packet from server\n";
      return 1;
  } else if (count==sizeof(recv_buffer)) {
      std::cerr << "ERROR: Datagram too large for recv_buffer: truncated\n";
      return 1;
  } else {
    relay_struc->rec_server_advertise_pack = (u_char *) malloc(count);
    if (relay_struc->rec_server_advertise_pack == NULL) {
      std::cerr << KRED "ERROR: Problem with memory allocation\n" KWHT;
      return 1;
    }
    /* Copy packet */
    memcpy(relay_struc->rec_server_advertise_pack, recv_buffer, count);
    relay_struc->rec_server_advertise_pack_len = count;
  } 

  close(fd);
  
  return 0;
}


/***** Method sends packet to client ****/
int PacketHandler::send_client_advertise(RelayStruc *relay_struc) {
  sockaddr_in6 clientaddr, relayaddr;
  
  int fd_client_advertise = socket(AF_INET6,SOCK_DGRAM,0);
  if(fd_client_advertise<0){
      std::cerr << KRED "ERROR: Cannot open socket\n" KWHT;
      return false;
  }
  
  /*--- Setting source for packet ---*/
  memset(&relayaddr, 0, sizeof(relayaddr));
  relayaddr.sin6_family = AF_INET6;
  relayaddr.sin6_scope_id = if_nametoindex(relay_struc->parse_struc.interface_id.c_str());
  /* Finding link-local addres */
  char ipv6_lladdr[INET6_ADDRSTRLEN];
  if (get_ipv6_addr(relay_struc, ipv6_lladdr, (char *) (relay_struc->parse_struc.interface_id.c_str()), IPV6_LL_TYPE)) {
    std::cerr << KRED "ERROR: Cannot find linl-local addres on interface:" << relay_struc->parse_struc.interface_id.c_str() << "\n" KWHT;
    return 1;
  }
  
  inet_pton(AF_INET6, ipv6_lladdr, &(relayaddr.sin6_addr));
  relayaddr.sin6_port = htons(DHCPV6_SERVER_PORT);

  /*--- Binding source ---*/
  if (bind(fd_client_advertise, (struct sockaddr *) &relayaddr, sizeof(relayaddr)) < 0) {
    std::cerr << KRED "ERROR: Cannot bind source to socket\n" KWHT;
    close(fd_client_advertise);
    return 1;
  }  

  /*--- Setting destination for packet ---*/
  bzero(&clientaddr,sizeof(clientaddr));
  clientaddr.sin6_family = AF_INET6;

  char clientaddr_string[150];
  u_char clientaddr_byte[INET6_ADDRSTRLEN];
  memcpy(clientaddr_byte, relay_struc->rec_server_advertise_pack+18, INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6,clientaddr_byte, clientaddr_string, INET6_ADDRSTRLEN);
  inet_pton(AF_INET6, clientaddr_string, &(clientaddr.sin6_addr));
  
  clientaddr.sin6_port = htons(DHCPV6_CLIENT_PORT);


  /* Sending message */
  char advertise_msg[PACKET_SIZE];

  mempcpy(advertise_msg, relay_struc->rec_server_advertise_pack+48, relay_struc->rec_server_advertise_pack_len-48);
  int advertise_msg_len = relay_struc->rec_server_advertise_pack_len-48;

  if (sendto(fd_client_advertise, &advertise_msg, advertise_msg_len, 0, (sockaddr*)&clientaddr, sizeof(clientaddr)) <= 0) {
      std::cerr << KRED "ERROR: Cannot send advertise packet to cliet\n" KWHT;
      close(fd_client_advertise);
      return 1;
  }

  close(fd_client_advertise);

  return 0;

}

/********************************************************************************************************************/
/********************************************************************************************************************/
/********************************************************************************************************************/
int PacketHandler::send_server_request(RelayStruc *relay_struc) {
  /*--- Create socket ---*/
  sockaddr_in6 servaddr, relayaddr;
  
  int fd = socket(AF_INET6,SOCK_DGRAM,0);
  if(fd<0){
      std::cerr << KRED "ERROR: Cannot open socket\n" KWHT;
      return false;
  }

  /*--- Setting source for packet ---*/
  memset(&relayaddr, 0, sizeof(relayaddr));
  relayaddr.sin6_family = AF_INET6;
  relayaddr.sin6_addr = in6addr_any;
  relayaddr.sin6_port = htons(DHCPV6_SERVER_PORT);
  
  /*--- Binding source ---*/
  if (bind(fd, (struct sockaddr *) &relayaddr, sizeof(relayaddr)) < 0) {
    std::cerr << KRED "ERROR: Cannot bind source to socket\n" KWHT;
    return 1;
  }  

  /*--- Setting destination for packet ---*/
  char *server_ip = const_cast<char*>(relay_struc->parse_struc.server_id.c_str()); // parsed server ip to c string
  bzero(&servaddr,sizeof(servaddr));
  servaddr.sin6_family = AF_INET6;
  inet_pton(AF_INET6, server_ip, &(servaddr.sin6_addr));
  servaddr.sin6_port = htons(DHCPV6_SERVER_PORT);

  /*--- Filling relay message ---*/
  u_char relay_msg[PACKET_SIZE];
  int offset = 0;

  memset(relay_msg, 0, PACKET_SIZE);

  /*--- Setting message type field in relay-forward message ---*/
  relay_msg[offset++] = 0x0c;
  
  /*--- Setting hopcount field in relay-forward message ---*/
  relay_msg[offset++] = 0x00;

  /*--- Setting link-address in relay-forward message ---*/
  struct sockaddr_in6 in6;
  char link_address_str[INET6_ADDRSTRLEN];
  
  if (get_ipv6_addr(relay_struc, link_address_str, (char *) (relay_struc->parse_struc.interface_id.c_str()), IPV6_GUA_ULA_TYPE)) {
    std::cerr << KRED "ERROR: Cannot find GUA or ULA addres on interface: " << relay_struc->parse_struc.interface_id.c_str() << " and link-local is not supported\n" KWHT;
    return 1;
  }
  inet_pton(AF_INET6, link_address_str, &(in6.sin6_addr));
  int link_address_size = sizeof(in6.sin6_addr);
  memcpy(relay_msg+2, &(in6.sin6_addr), link_address_size);
  offset = offset + link_address_size;

  /*--- Setting peer-address in relay-forward message ---*/
  int peer_address_size = sizeof(relay_struc->client_ip_addr);
  memcpy(relay_msg+offset, &(relay_struc->client_ip_addr), peer_address_size);
  offset = offset + peer_address_size;
  
  /*--- Setting option rellay message in relay-forward message ---*/
  // Option rellay message
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = 0x09;
  // Rellay message len
  int dhcpv6_msg_len = relay_struc->rec_client_request_pack_len - ETH_HEADER_LENGTH - IPv6_HEADER_LENGTH - UDP_HEADER_LENGTH;
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = dhcpv6_msg_len;  
  // Rellay message value
  const u_char *address; 
  address = (u_char *) relay_struc->rec_client_request_pack + ETH_HEADER_LENGTH + IPv6_HEADER_LENGTH + UDP_HEADER_LENGTH;
  memcpy(relay_msg+offset, address, dhcpv6_msg_len);
  offset += dhcpv6_msg_len; 
  
  /*--- Setting option client link-layer in relay-forward message ---*/
  struct ether_header *eptr;
  eptr = (struct ether_header *) relay_struc->rec_client_request_pack;
  // Option client link-layer 
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = 0x4f;
  // Length
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = sizeof(eptr->ether_shost) + 2;
  // Interface-type
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = 0x01;
  // Value
  mempcpy(relay_msg+offset, eptr->ether_shost, sizeof(eptr->ether_shost));
  offset = offset + sizeof(eptr->ether_shost);
  /*----------------------- Setting option interface-id in relay-forward message -----------------------*/
  // Option interface-id
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = 0x12;
  // Length
  relay_msg[offset++] = 0x00;
  relay_msg[offset++] = sizeof(eptr->ether_dhost);
  // Value
  u_char if_id_value[6];
  this->get_mac_addr(relay_struc, (char *) relay_struc->parse_struc.interface_id.c_str(), if_id_value);
  mempcpy(relay_msg+offset, if_id_value, 6);
  offset = offset + 6;
  
  /*--- Sending relay message ---*/
  if (sendto(fd, &relay_msg, offset, 0, (sockaddr*)&servaddr, sizeof(servaddr)) <= 0) {
      std::cerr << KRED "ERROR: Cannot send request packet to server\n" KWHT;
      close(fd);
      return 1;
  }

  relay_struc->fd2 = fd;

  return 0;
}

/********************************************************************************************************************/
/********************************************************************************************************************/
/********************************************************************************************************************/
int PacketHandler::receive_server_reply(RelayStruc *relay_struc) {  
  /* Get socket descr */
  int fd = relay_struc->fd2;
  
  /* Receive reply packet */
  u_char recv_buffer[PACKET_SIZE];
  struct sockaddr_storage src_addr;
  socklen_t src_addr_len=sizeof(src_addr);

  ssize_t count=recvfrom(fd,recv_buffer,sizeof(recv_buffer),0,(struct sockaddr*)&src_addr,&src_addr_len);
  if (count==-1) {
      std::cerr << "Chyba pri prijati relay-reply\n";
      return 1;
  } else if (count==sizeof(recv_buffer)) {
      std::cerr << "datagram too large for recv_buffer: truncated\n";
      return 1;
  } else {
    relay_struc->rec_server_reply_pack = (u_char *) malloc(count);
    if (relay_struc->rec_server_reply_pack == NULL) {
      std::cerr << KRED "ERROR: Problem with memory allocation\n" KWHT;
      return 1;
    }
    /* Copy reply packet do relay_struc */
    memcpy(relay_struc->rec_server_reply_pack, recv_buffer, count);
    relay_struc->rec_server_reply_pack_len = count;
  } 

  close(fd);

  return 0;
}

/********************************************************************************************************************/
/********************************************************************************************************************/
/********************************************************************************************************************/
int PacketHandler::send_client_reply(RelayStruc *relay_struc) {
  sockaddr_in6 clientaddr, relayaddr;
  
  int fd_client_reply = socket(AF_INET6,SOCK_DGRAM,0);
  if(fd_client_reply<0){
      std::cerr << KRED "ERROR: Cannot open socket\n" KWHT;
      return false;
  }
  
  /*--- Setting source for packet ---*/
  memset(&relayaddr, 0, sizeof(relayaddr));
  relayaddr.sin6_family = AF_INET6;
  relayaddr.sin6_scope_id = if_nametoindex(relay_struc->parse_struc.interface_id.c_str());
  /* Finding link-local addres */
  char ipv6_lladdr[INET6_ADDRSTRLEN];
  if (get_ipv6_addr(relay_struc, ipv6_lladdr, (char *) (relay_struc->parse_struc.interface_id.c_str()), IPV6_LL_TYPE)) {
    std::cerr << KRED "ERROR: Cannot find linl-local addres on interface:" << relay_struc->parse_struc.interface_id.c_str() << "\n" KWHT;
    return 1;
  }
  inet_pton(AF_INET6, ipv6_lladdr, &(relayaddr.sin6_addr));
  relayaddr.sin6_port = htons(DHCPV6_SERVER_PORT);

  /*--- Binding source ---*/
  if (bind(fd_client_reply, (struct sockaddr *) &relayaddr, sizeof(relayaddr)) < 0) {
    std::cerr << KRED "ERROR: Cannot bind source to socket\n" KWHT;
    close(fd_client_reply);
    return 1;
  }  

  /*--- Setting destination for packet ---*/  
  bzero(&clientaddr,sizeof(clientaddr));
  clientaddr.sin6_family = AF_INET6;
  
  char clientaddr_string[150];
  u_char clientaddr_byte[INET6_ADDRSTRLEN];
  memcpy(clientaddr_byte, relay_struc->rec_server_reply_pack+18, INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6,clientaddr_byte, clientaddr_string, INET6_ADDRSTRLEN);
  inet_pton(AF_INET6, clientaddr_string, &(clientaddr.sin6_addr));

  clientaddr.sin6_port = htons(DHCPV6_CLIENT_PORT);

  char reply_msg[PACKET_SIZE];
  mempcpy(reply_msg, relay_struc->rec_server_reply_pack+48, relay_struc->rec_server_reply_pack_len-48);
  int reply_msg_len = relay_struc->rec_server_reply_pack_len-48;

  if (sendto(fd_client_reply, &reply_msg, reply_msg_len, 0, (sockaddr*)&clientaddr, sizeof(clientaddr)) <= 0) {
      std::cerr << KRED "ERROR: Cannot send reply packet to client\n" KWHT;
      close(fd_client_reply);
      return 1;
  }

  unsigned option_length = 0;
  unsigned next_option = option_length+4;
  while (next_option < PACKET_SIZE) {
    // test packet with ipv6
    if ((*(reply_msg+next_option) == 0x00) && (*(reply_msg+next_option+1) == 0x03)) {
      if ((*(reply_msg+next_option+16) != 0x00) || (*(reply_msg+next_option+17) != 0x05)) {
        std::cerr << KRED "ERROR: Server didn't assign address\n" KWHT; 
        return 1;
      }
      inet_ntop(AF_INET6, reply_msg+next_option+20, relay_struc->client_assigned_ipv6_addr, INET6_ADDRSTRLEN);
      break;
    }
    // test packet with prefix
    else if ((*(reply_msg+next_option) == 0x00) && (*(reply_msg+next_option+1) == 0x19)) {
      if ((*(reply_msg+next_option+16) != 0x00) || (*(reply_msg+next_option+17) != 0x1a)) {
        std::cerr << KRED "ERROR: Server didn't assign prefix\n" KWHT; 
        return 1;
      }
      relay_struc->client_ip_prefix = (unsigned) *(reply_msg+next_option+28);
      inet_ntop(AF_INET6, reply_msg+next_option+29, relay_struc->client_assigned_ipv6_addr_prefix, INET6_ADDRSTRLEN);
      break;
    }
    // Update new option length and jump to next header
    option_length = (unsigned) *(reply_msg+next_option+2) << 8 | (unsigned) *(reply_msg+next_option+3);  
    next_option += option_length+4;
  }

  close(fd_client_reply);

  return 0;
}
