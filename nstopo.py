#!/usr/bin/env python

import argparse
import networkx as nx
import namedtuple from collections


def NetstatData():
    Connection = namedtuple('Connection', [('source', 'source_port', 'destination', 'destination_port', 'state', 'program'])])
    all_conections = []

    for file in system.path(arg):
        for info in file:
            sline = line.strip().split(None, 8)
            if "tcp" in sline[0]:
                data.append((sline[0], sline[3], sline[4], sline[5], sline[6]))
            elif "udp" in sline[0]:
                data.append((sline[0], sline[3], sline[4], None, sline[6]))
