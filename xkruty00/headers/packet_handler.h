/******************************************************************************
 * Project:   3BIT ISA, Project, DHCPv6 relay                                 *
 *            Faculty of Information Technology                               *
 *            Brno University of Technology                                   *
 * File:      packet_handler.h                                                *
 * Date:      18.11.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

#ifndef _PACKET_HANDLER_H_
#define _PACKET_HANDLER_H_

#include "relay_struc.h"

#include <sys/socket.h>
#include <netinet/in.h>

class PacketHandler
{
public:
  /**
   * Method receives packet from client
   */
  int receive_client_packet(RelayStruc *relay_struc);
  
  /**
   * Method sends solicit packet to server
   */
  int send_server_solicit(RelayStruc *relay_struc);
  
  /**
   * Method receives advertise packet from server
   */
  int receive_server_advertise(RelayStruc *relay_struc);
  
  /**
   * Method sends advertise packet to client
   */
  int send_client_advertise(RelayStruc *relay_struc);

  /**
   * Method sends request packet to server
   */
  int send_server_request(RelayStruc *relay_struc);

  /**
   * Method receives reply packet from server
   */
  int receive_server_reply(RelayStruc *relay_struc);

  /**
   * Method sends reply packet to client
   */
  int send_client_reply(RelayStruc *relay_struc);

  /**
   * Method gets MAC address from specific interface
   */
  int get_mac_addr(RelayStruc *relay_struc, char *interface_name, uint8_t  *mac_address_byte);

  /**
   * Method gets ipv6 address from specific interface
   */
  int get_ipv6_addr(RelayStruc *relay_struc, char *ipv6_lladdr, char *interface, int address_type);
};

#endif /* _PACKET_HANDLER_H_ */
