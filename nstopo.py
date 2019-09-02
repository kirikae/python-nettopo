#!/usr/bin/env python

import socket
import argparse
from getpass import getpass
from collections import namedtuple
from neo4j import GraphDatabase


neo4jusername = input("Neo4j username: ")
neo4jpassword = getpass("Neo4j password: ")
uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=(neo4jusername, neo4jpassword))

Hosts = []
Sources = {}

parser = argparse.ArgumentParser(
    description = "Parse Netstat output files and import them into Neo4j Graph Database"
    )
parser.add_argument('--files', '-f', nargs='+', help='Pass the File or Files to analyse')

args = parser.parse_args()

for arg in vars(args):
    filenamess = getattr(args, arg)

def main():
    Connection = namedtuple('Connection', ['proto', 'recvq', 'sendq', 'localaddr', 'localport', 'remoteaddr', 'remoteport', 'state', 'pid', 'program'])
    all_conections = []

    for File in filenames:
        print("Reading in file: ",File)
        with open(File, 'r') as f:
            for line in f:
                current_line = line.split()
                if current_line[0] == "tcp":
                    (proto, recvq, sendq, local, remote, state, pidprog) = current_line
                elif current_line[0] == "udp":
                    if current_line[5] == "ESTABLISHED":
                        (proto, recvq, sendq, local, remote, state, pidprog) = current_line
                    else:
                        state = ""
                        (proto, recvq, sendq, local, remote, pidprog) = current_line
                else:
                    continue
                if pidprog == '-':
                    (pid, program) = ("UNKNOWN", "UNKNOWN")
                else:
                    (pid, program) = pidprog.split('/')

                (localaddr, localport) = local.split(':')[:2]
                (remoteaddr, remoteport) = remote.split(':')[:2]

                current_connection = Connection(proto, recvq, sendq, localaddr, localport, remoteaddr, remoteport, state, pid, program)
        print("Finished with :", File)

    alladdrs = set()
    localconns = set()
    remoteconns = set()
    allprograms = set()
    Host = namedtuple('Host', ['hostname', 'ipaddr'])
    all_hosts = []
    all_programs = []

    for conn in all_connections:
        alladdrs.add(conn.localaddr)
        alladdrs.add(conn.remoteaddr)
        localconns.add(conn.localaddr)
        remotecons.add(conn.remoteaddr)
        allprograms.add(conn.program)

    for host in alladdrs:
        try:
            name = socket.gethostbyaddr(host)[0]
        except:
            name = "UNKNOWN"
        add_host = "CREATE (A:COMPUTER {IP: \"" + host + "\", FQDN: \"" + name + "\"})"

        with driver.session() as session:
            session.run(add_host)
            session.close()

    for program in allprograms:
        add_program = "CREATE (A:PROGRAM {Name: \"" + program + "\"})"

        with driver.session() as session:
            session.run(add_program)
            session.close()


    for conn in all_connections:
        if conn.localaddr not in Sources.keys():
            Sources[conn.localaddr] = []
        if conn.remoteaddr not in Sources[conn.localaddr]:
            add_app_relationship = "MATCH (A:COMPUTER {IP: \"" + conn.localaddr + "\"}),(B:PROGRAM {Name: \"" + conn.program + "\"}),(C:COMPUTER {IP: \"" + conn.remoteaddr + "\"}) CREATE (A)-[:RUNS]->(B)"
            add_hosts_relationship = "MATCH (A:COMPUTER {IP: \"" + conn.localaddr + "\"}),(B:PROGRAM {Name: \"" + conn.program + "\"}),(C:COMPUTER {IP: \"" + conn.remoteaddr + "\"}) CREATE (B)-[:CONNECTS_TO {Local_Port: \"" + conn.localport + "\", Remote_Port: \"" + con.remoteport + "\", Protocol: \"" + conn.proto + "\", State: \"" + conn.state + "\"}]->(C)"

            with driver.session() as session:
                session.run(add_app_relationship)
                session.run(add_host_relationship)
                Sources[conn.localaddr].append(conn.remoteaddr)
                session.close()


if __name__ = '__main__':
    main()
