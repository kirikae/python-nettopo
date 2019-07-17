#!/usr/bin/python3

import argparse
import re
import time
from neo4j import GraphDatabase

uri = bolt://localhost:7687
driver = GraphDatabase.driver(uri, auth=("neo4j", "password"))

Sources = {}

parser = argparse.ArgumentParser(
    description = "netstat output files to graph"
)
parser.add_argument('--inputs', nargs='*')

args = parser.parse_args()

def parsefilename(filename):
    return filename.split('/')[-2]

for arg in files:
    netstatlines = []
    with open(arg, 'r') as f:
        netstatlines = f.read()

    # Strip headings from netstat output
    netstatlines = netstatlines.split('\n')[2:-1]
    for l in netstatlines:
        (proto, recvq, sendq, local, remote, state, pid) = l.split()[:7]
        if "LISTEN" in state:
            continue

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
            query = "MATCH (A:COMPUTER {Name \"" + src + "\"}), (B:COPMPUTER {Name: \"" + dst + "\"}) CREATE (A)-[:COMPUTER]->(B)"

        with driver.session() as session:
            session.run(query)
            Sources[src].append(dst)
            session.close()

        time.sleep(1)

        print(query)
