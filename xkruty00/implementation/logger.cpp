/******************************************************************************
 * Project:   3BIT ISA, Project, DHCPv6 relay                                 *
 *            Faculty of Information Technology                               *
 *            Brno University of Technology                                   *
 * File:      logger.cpp                                                      *
 * Date:      18.11.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

/***** Local modules *****/
#include "../headers/logger.h"
#include "../headers/relay_struc.h"

/***** Standard libraries *****/
#include <iostream>
#include <syslog.h>

/***** Network libraries *****/
#include <arpa/inet.h>

/***** Method prints debug informations *****/
int Logger::print_debug(RelayStruc relay_struc) {
  if (relay_struc.client_ip_prefix == 0) {
    std::cout << relay_struc.client_assigned_ipv6_addr << ",";
    std::cout << relay_struc.client_mac_addr << "\n";
  }
  else {
    std::cout << relay_struc.client_assigned_ipv6_addr_prefix << "/" << relay_struc.client_ip_prefix << ",";
    std::cout << relay_struc.client_mac_addr << "\n";
  }


  return 0;
};

/***** Method opens system log *****/
int Logger::open_syslog() {
  openlog("d6r", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
  
  return 0;
};

/***** Method prints to system log *****/
int Logger::print_syslog(RelayStruc relay_struc) {
  if (relay_struc.client_ip_prefix == 0) {
    syslog(LOG_NOTICE, "%s,%s\n", relay_struc.client_assigned_ipv6_addr,
                                  relay_struc.client_mac_addr);
  }
  else {
    syslog(LOG_NOTICE, "%s/%d,%s\n", relay_struc.client_assigned_ipv6_addr_prefix,
                                  relay_struc.client_ip_prefix,
                                  relay_struc.client_mac_addr);
  }

  return 0;
};

/***** Method closes system log *****/
int Logger::close_syslog() {
  closelog();
  
  return 0;
};
