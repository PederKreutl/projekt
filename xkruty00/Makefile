################################################################################
# Project:   2BIT ISA, Project, , DHCPv6 relay                                 #
#            Faculty of Information Technology                                 #
#            Brno University of Technology                                     #
# File:      Makefile                                                          #
# Date:      21.04.2019                                                        #
# Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                         #
################################################################################

CC=g++
CC_FLAGS= -std=c++11 -Wall -g 
OUTPUT= d6r
OF= args_parser.o logger.o packet_handler.o

output: main.cpp $(OF)
	$(CC) $(CC_FLAGS) main.cpp $(OF) -o $(OUTPUT) -lpcap
	rm $(OF)

args_parser.o: implementation/args_parser.cpp headers/args_parser.h headers/relay_struc.h headers/colors.h
	$(CC) $(CC_FLAGS) -c implementation/args_parser.cpp -o args_parser.o

logger.o: implementation/logger.cpp headers/logger.h headers/relay_struc.h headers/colors.h
	$(CC) $(CC_FLAGS) -c implementation/logger.cpp -o logger.o

packet_handler.o: implementation/packet_handler.cpp headers/packet_handler.h headers/colors.h
	$(CC) $(CC_FLAGS) -c implementation/packet_handler.cpp -o packet_handler.o

run:
	sudo ./d6r -s 2001:67c:1220:80c::93e5:dd2

clean:
	rm d6r