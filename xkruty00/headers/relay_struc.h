/******************************************************************************
 * Project:   3BIT ISA, Project, DHCPv6 relay                                 *
 *            Faculty of Information Technology                               *
 *            Brno University of Technology                                   *
 * File:      relay_struc.h                                                   *
 * Date:      18.11.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

#ifndef _RELAY_STRUC_H_
#define _RELAY_STRUC_H_

#include "parse_struc.h"
#include "netinet/ip6.h"

typedef struct relay_struc {
  ParseStruc parse_struc;

  struct in6_addr client_ip_addr;
  

  std::string server_ip_addr;
  int server_ip_prefix;
  
  /* Packets legth */
  int rec_client_solic_pack_len = 0;
  int rec_server_advertise_pack_len = 0;
  int rec_client_request_pack_len = 0;
  int rec_server_reply_pack_len = 0;

  /* Packets */
  u_char *rec_client_solic_pack = NULL;
  u_char *rec_server_advertise_pack = NULL;
  u_char *rec_client_request_pack = NULL;
  u_char *rec_server_reply_pack = NULL;
  
  /* socket descriptors */
  int fd1;
  int fd2;

  /* Variables for relay output*/
  char client_assigned_ipv6_addr[INET6_ADDRSTRLEN];
  char *client_mac_addr = NULL;
  char client_assigned_ipv6_addr_prefix[INET6_ADDRSTRLEN];
  unsigned client_ip_prefix = 0;

  u_char client_captured_packet_type = 0x00;
} RelayStruc;

#endif /* _RELAY_STRUC_H_ */
