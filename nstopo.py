#!/usr/bin/env python

import argparse
from collections import namedtuple
from neo4j import GraphDatabase


uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=('neo4j', 'test'))
hosts = []
Sources = {}

parser = argparse.ArgumentParser(
    description = "netstat output files to graph"
)
parser.add_argument('--inputs', nargs='*')

args = parser.parse_args()

def parsefilename(filename):
    return filename.split('/')[-2]

for arg in vars(args):
    files = getattr(args, arg)

def NetstatData():
    Connection = namedtuple('Connection', ['proto', 'recvq', 'sendq', 'localaddr', 'localport', 'remoteaddr', 'remoteport', 'state', 'pid', 'program'])
    all_conections = []
    header_test = ['Active', 'Proto']

    for arg in files:
        lines = []
        with open(arg, 'r') as f:
            lines = f.read()
        if not any(text in lines for text in header_text):
            continue
        else:
            lines = lines.split('\n')[2:-1]
        for line in lines:
            if "tcp" in line.split()[0]:
                (proto, recvq, sendq, local, remote, state, pidprog) = line.split()[7]
            elif "udp" in line.split()[0]:
                (proto, recvq, sendq, local, remote, state, pidprog) = line.split()[4], "", line.split()[5]

            pidprog = pidprog.split('/')
            if pidprog[0] == '-':
                (pid, program) = (pidprog, pidprog)
            else:
                (pid, program) = (pidprog[0], pidprog[1])

            (localaddr, localport) = local.split(':')[:2]
            (remoteaddr, remoteport) = remote.split(':')[:2]

            current_connection = Connection(proto, recvq, sendq, localaddr, localport, remoteaddr, remoteport, state, pid, program)
            if "LISTEN" not in current_connection[7]:
                all_connections.append(current_connection)

    print(all_connections)

    alladdrs = set()
    localconns = set()
    remoteconns = set()

    for conn in all_connections:
        alladdrs.add(conn.localaddr)
        alladdrs.add(conn.remoteaddr)
        localconns.add(conn.localaddr)
        remotecons.add(conn.remoteaddr)

    print(alladdrs)

    for host in alladdrs:
        add_host = "CREATE (A:COMPUTER {Name: \"" + host + "\"})"

        with driver.session() as session:
            session.run(add_host)
            session.close()
        print(add_host)

    for conn in all_connections:
        if conn.localaddr not in Sources.keys():
            Sources[conn.localaddr] = []
        if conn.remoteaddr not in Sources[conn.localaddr]:
            add_relationship = "MATCH (A:COMPUTER {Name: \"" + conn.localaddr + "\"}),(B:COMPUTER {Name: \"" + conn.remoteaddr + "\"}) CREATE (A)-[:CONNECTS_TO]->(B)"

            with driver.session() as session:
                session.run(add_relationship)
                Sources[conn.localaddr].append(conn.remoteaddr)
                session.close()

            print(add_relationship)

NetstatData()

    for file in system.path(arg):
        for info in file:
            sline = line.strip().split(None, 8)
            if "tcp" in sline[0]:
                data.append((sline[0], sline[3], sline[4], sline[5], sline[6]))
            elif "udp" in sline[0]:
                data.append((sline[0], sline[3], sline[4], None, sline[6]))
