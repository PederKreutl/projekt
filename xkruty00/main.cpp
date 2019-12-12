/******************************************************************************
 * Project:   3BIT ISA, Project, DHCPv6 relay                                 *
 *            Faculty of Information Technology                               *
 *            Brno University of Technology                                   *
 * File:      main.cpp                                                        *
 * Date:      18.11.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

/* Local modules */
#include "headers/relay_struc.h"
#include "headers/args_parser.h"
#include "headers/logger.h"
#include "headers/packet_handler.h"
#include "headers/colors.h"

/* Standard libraries */
#include <iostream>
#include <bits/stdc++.h> 
#include <string.h>
#include <sys/types.h>
#include <sys/prctl.h> // prctl(), PR_SET_PDEATHSIG
#include <signal.h> // signals
#include <unistd.h> // fork()
#include <sys/wait.h> 

/* Network libraries */
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>

#define SOLICIT_MSG_TYPE 0x01
#define REQUEST_MSG_TYPE 0x03

int main(int argc, char *argv[]) 
{
  ArgsParser args_parser;
  Logger logger;
  PacketHandler packet_handler;
  RelayStruc relay_struc;
  ParseStruc parse_struc;

  /* Arguments parsing */
  if (args_parser.parse_args_posix(argc, argv, &parse_struc)) 
  {
    std::cerr << KRED "ERROR: Problem with parsing program arguments\n" KWHT;
    return 1;
  }

  /* Arguments parsing */
  if (args_parser.parse_server_input(&parse_struc)) 
  {
    std::cerr << KRED "ERROR: Problem with parsing server identification\n" KWHT;
    return 1;
  }

  /*--- Relay capturing packets on all interfaces ---*/
  if (parse_struc.interface_id == "") 
  {
    relay_struc.parse_struc = parse_struc;

    /*--- Finding all interfaces ---*/
    struct ifaddrs *ifaddr=NULL;
    struct ifaddrs *ifa = NULL;
    std::vector <std::string> interfaces;
    int counter;

    if (getifaddrs(&ifaddr) == -1)
    {
      std::cerr << KRED "ERROR: Problem with function getifaddrs\n" KWHT;
      return 1;
    }
    else
    {
      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
      {
        if (ifa->ifa_addr)
        {
          if (counter == 0) 
          {
            interfaces.push_back(ifa->ifa_name);
          }
          std::vector<std::string>::iterator interfaces_it = std::find(interfaces.begin(), interfaces.end(), ifa->ifa_name);
          if (interfaces_it == interfaces.end()) 
          {
            interfaces.push_back(ifa->ifa_name);
          }
          counter++;
        }
      }
      freeifaddrs(ifaddr);
    }

    /*--- Creating proccess on every interface ---*/      
    pid_t child_pid, wpid;
    pid_t ppid_before_fork = getpid();
    int status;

    for (unsigned int i = 0; i < interfaces.size(); i++)
    {
      child_pid = fork();
      if (child_pid != 0) 
      {
        continue;
      }
      else 
      {
        int r = prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (r == -1) 
        { 
          perror(0); 
          exit(1); 
        }
        // test in case the original parent exited just
        // before the prctl() call
        if (getppid() != ppid_before_fork) {
            exit(1);
        }
        // continue child execution ...
        relay_struc.parse_struc.interface_id = interfaces[i];
        break;
      }
    }
    /* Main process is waiting for all childs */
    if (ppid_before_fork == getpid()) 
    {
            while ((wpid = wait(&status)) > 0);
            
            return 0;
    }
  }
  /*--- Relay capturing packets on specific interface ---*/
  else 
  {
    relay_struc.parse_struc = parse_struc;
  }


  /*--- Joining to multicast group ---*/
  /* Get socket decriptor */
  int fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if(fd<0){
      std::cerr << KRED "ERROR: Cannot create socket\n" KWHT;
      return 1;
  }

  // /* Bind socket */
  // struct sockaddr_in6 address = {AF_INET6};
  // if (bind(fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
  //   perror("bind");
  //   std::cerr << KRED "ERROR: Cannot bind source to socket\n" KWHT;
  //   return 1;
  // }

  /* Joining membership */
  struct ipv6_mreq group;
  group.ipv6mr_interface = if_nametoindex(relay_struc.parse_struc.interface_id.c_str());
  inet_pton(AF_INET6, "ff02::1:2", &group.ipv6mr_multiaddr);
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
    std::cerr << KRED "ERROR: Cannot join to multicast\n" KWHT;
    return 1;
  }

  /* Starting comunication */
NEW_PACKET_FROM_CLIENT:
  int sniffing_return_value = 0;
  /* Receiving solicit packet from client */
  if ((sniffing_return_value = packet_handler.receive_client_packet(&relay_struc)) == 2) {
    std::cerr << KRED "ERROR: Problem with receiving packet from client\n" KWHT;
    goto NEW_PACKET_FROM_CLIENT;
  }
  else if (sniffing_return_value == 1) {
    std::cerr << KRED "ERROR: Problem with interface " << relay_struc.parse_struc.interface_id << "\n" KWHT;
    return 1;
  }

  pid_t child_pid = fork();
  /* parent starts capturing packet again */
  if (child_pid != 0) 
  {
    goto NEW_PACKET_FROM_CLIENT;
  }
  /* Child handles comunication */

  /*---------------------------- Captured packet is solicit ----------------------------*/
  if (relay_struc.client_captured_packet_type == SOLICIT_MSG_TYPE) {
    /* Sending solicit packet to server */
    if (packet_handler.send_server_solicit(&relay_struc)) {
      std::cerr << KRED "ERROR: Problem with sending solicit packet to server\n" KWHT;
      return 1;
    }
    /* Receiving advertise packet from server */
    if (packet_handler.receive_server_advertise(&relay_struc)) {
      std::cerr << KRED "ERROR: Problem with receiving advertise packet from server\n" KWHT;
      return 1;
    }
    /* Sending advertise packet to client */
    if (packet_handler.send_client_advertise(&relay_struc)) {
      std::cerr << KRED "ERROR: Problem with sending advertise packet to client\n" KWHT;
      return 1;
    }

    return 0;
  }
  /*---------------------------- Captured packet is request ----------------------------*/
  else if (relay_struc.client_captured_packet_type == REQUEST_MSG_TYPE) {
    /* Sending request packet to server */
    if (packet_handler.send_server_request(&relay_struc)) {
      std::cerr << KRED "ERROR: Problem with sending request packet to server\n" KWHT;
      return 1;
    }
    /* Receiving reply packet from server */
    if (packet_handler.receive_server_reply(&relay_struc)) {
      std::cerr << KRED "ERROR: Problem with receiving reply packet from server\n" KWHT;
      return 1;
    }
    /* Sending reply packet to server */
    if (packet_handler.send_client_reply(&relay_struc)) {
      std::cerr << KRED "ERROR: Problem with sending reply packet to client\n" KWHT;
      return 1;
    }
  }
  else {
      std::cerr << KRED "ERROR: Problem with captured packet type\n" KWHT;
      return 1;
  }

  
  /* Printing output to stdout */
  if (relay_struc.parse_struc.d_flag == true) 
  {
    logger.print_debug(relay_struc);
  }

  /* Printing output to syslog */
  if (relay_struc.parse_struc.l_flag == true) 
  {
    logger.open_syslog();
    logger.print_syslog(relay_struc);
    logger.close_syslog();
  }

  free(relay_struc.rec_client_solic_pack);
  free(relay_struc.rec_server_advertise_pack);
  free(relay_struc.rec_client_request_pack);
  free(relay_struc.rec_server_reply_pack);
  
  return 0;
}
