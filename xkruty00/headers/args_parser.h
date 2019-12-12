/******************************************************************************
 * Project:   3BIT ISA, Project, DHCPv6 relay                                 *
 *            Faculty of Information Technology                               *
 *            Brno University of Technology                                   *
 * File:      args_parser.h                                                   *
 * Date:      18.11.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

#ifndef _ARGS_PARSER_H_
#define _ARGS_PARSER_H_

#include "parse_struc.h"

class ArgsParser
{
public:
  
  /**
   * Method parses program arguments
   */
  int parse_args_posix(int argc, char *argv[], ParseStruc *parse_struc);
  
  /**
   * Method parses server id
   */
  int parse_server_input(ParseStruc *parse_struc);
};

#endif /* _ARGS_PARSER_H_ */
