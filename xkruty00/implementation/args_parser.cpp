/******************************************************************************
 * Project:   3BIT ISA, Project, DHCPv6 relay                                 *
 *            Faculty of Information Technology                               *
 *            Brno University of Technology                                   *
 * File:      args_parser.cpp                                                 *
 * Date:      18.11.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

/***** Local modules *****/
#include "../headers/args_parser.h"
#include "../headers/parse_struc.h"
#include "../headers/colors.h"

/***** Standard libraries *****/
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <cstdlib>

/***** Network libraries *****/
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

/***** Method parses server input *****/
int ArgsParser::parse_server_input(ParseStruc *parse_struc) {
  const char *ip6str = parse_struc->server_id.c_str();

  struct sockaddr_storage result;

  struct addrinfo *res = NULL;
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICSERV;

  int rc = getaddrinfo(ip6str, NULL, &hints, &res);
  if (rc != 0)
  {
      fprintf(stderr, KRED "ERROR: Cannot parse host '%s': %s (%d)\n" KWHT, ip6str, gai_strerror(rc), rc);
      return 1;
  }

  if (res == NULL)
  {
      // Failure to resolve 'ip6str'
      fprintf(stderr, KRED "ERROR: No host found for '%s'\n" KWHT, ip6str);
      return 1;
  }

  memcpy(&result, res->ai_addr, res->ai_addrlen);

  freeaddrinfo(res);

  struct sockaddr_in6 * sa6 = (struct sockaddr_in6 *) &result;
  struct in6_addr * in6 = &sa6->sin6_addr;

  /* Copy ipv6 */
  char ipv6_server_address[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, in6->s6_addr, ipv6_server_address, INET6_ADDRSTRLEN);

  /* Save parsed server ipv6 addr */
  parse_struc->server_id = ipv6_server_address;
  return 0;
}


int ArgsParser::parse_args_posix(int argc, char *argv[], ParseStruc *parse_struc) {
    int c;
    opterr = 0;
    int s_counter = 0;
    int i_counter = 0;
    int d_counter = 0;
    int l_counter = 0;
    int opts_counter = 1;
    std::string i_id;
    std::string s_id;

    while((c = getopt (argc, argv, "s:i:dl") ) != -1 ) {
        switch(c) {
            case 's':
                if(!strcmp(optarg, "-s") || !strcmp(optarg, "-i") || !strcmp(optarg, "-d") || !strcmp(optarg, "-l")) {
                  std::cerr << KRED "ERROR: Option '-s' is required with argument\n" KWHT;            
                  return 1;
                }
                
                parse_struc->s_flag = true;
                s_id = optarg;
                parse_struc->server_id = s_id;
                
                s_counter++;
                opts_counter += 2;

                break;
            case 'i':
                if(!strcmp(optarg, "-s") || !strcmp(optarg, "-i") || !strcmp(optarg, "-d") || !strcmp(optarg, "-l")) {
                  std::cerr << KRED "ERROR: Option '-i' is required with argument\n" KWHT;            
                  return 1;
                }
                
                parse_struc->i_flag = true;
                i_id = optarg;
                parse_struc->interface_id = i_id;

                i_counter++;
                opts_counter += 2;

                break;
            case 'd':
                parse_struc->d_flag = true;
                d_counter++;
                opts_counter++;

                break;
            case 'l':
                parse_struc->l_flag = true;
                l_counter++;
                opts_counter++;

                break;
        }
    }

    if (!parse_struc->s_flag) {
      std::cerr << KRED "ERROR: Option '-s' is required with argument\n" KWHT;
      return 1;
    }
    if (s_counter > 1 || i_counter > 1 || d_counter > 1 || l_counter > 1 ) {
      std::cerr << KRED "ERROR: Option cannot be set multiple times\n" KWHT;
      return 1;
    }
    if (argc != opts_counter) {
      std::cerr << KRED "ERROR: Invalid argument\n" KWHT;
      return 1;
    }

    return 0;
};

