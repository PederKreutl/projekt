/******************************************************************************
 * Project:   3BIT ISA, Project, DHCPv6 relay                                 *
 *            Faculty of Information Technology                               *
 *            Brno University of Technology                                   *
 * File:      logger.h                                                        *
 * Date:      18.11.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

#ifndef _LOGGER_H_
#define _LOGGER_H_

#include "relay_struc.h"

class Logger
{
public:
  /**
   * Method prints debug informations
   */
  int print_debug(RelayStruc relay_struc);
  
  /**
   * Method opens system log
   */
  int open_syslog();
  
  /**
   * Method prints to system log
   */
  int print_syslog(RelayStruc relay_struc);
  
  /**
   * Method closes system log
   */
  int close_syslog();
};

#endif /* _LOGGER_H_ */
