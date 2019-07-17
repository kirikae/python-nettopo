#!/usr/bin/env python

from neo4j import GraphDatabase
import argparse
import re
import time


uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=("neo4j", "test"))

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

for arg in files:
    netstatlines = []
    with open(arg, 'r') as f:
        netstatlines = f.read()

    # Strip headings from netstat output
    netstatlines = netstatlines.split('\n')[2:-1]
    for l in netstatlines:
        if "tcp" in l.split()[0]:
            (proto, recvq, sendq, local, remote, state, pid) = l.split()[:7]
        elif "udp" in l.split()[0]:
            (proto, recvq, sendq, local, remote, state, pid) = l.split()[:4], None, l.split()[6]

        pid = pid.split('/')
        if pid[0] == '-':
            (pid, prog) = (pid, pid)
        else:
            (pid, prog) = (pid[0], pid[1])
        # print(state, prog)
        (src, srcport) = local.split(':')[:2]
        (dst, dstport) = remote.split(':')[:2]

        nodeprop = {
            'filename': arg,
            'name': parsefilename(arg)
        }
        edgeprop = {
            'port': dstport,
            'state': state,
            'prog': prog
        }

        if src not in Sources.keys():
            Sources[src] = []
        if dst not in Sources[src]:
            query = "MATCH (A:COMPUTER {Name: \"" + src + "\"}), (B:COMPUTER {Name: \"" + dst + "\"}) CREATE (A)-[:Connects_to]->(B)"

        with driver.session() as session:
            session.run(query)
            Sources[src].append(dst)
            session.close()

        time.sleep(0.1)

        print(query)
