/******************************************************************************
 * Project:   3BIT ISA, Project, DHCPv6 relay                                 *
 *            Faculty of Information Technology                               *
 *            Brno University of Technology                                   *
 * File:      parse_struc.h                                                   *
 * Date:      18.11.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

#ifndef _PARSE_STRUC_H_
#define _PARSE_STRUC_H_

#include <string>

typedef struct parse_struc {
  bool s_flag = false;
  bool d_flag = false;
  bool l_flag = false;
  bool i_flag = false;
  
  std::string server_id = "";
  std::string interface_id = "";
} ParseStruc;

#endif /* _PARSE_STRUC_H_ */
