#!/usr/bin/env python

import socket
import argparse
from getpass import getpass
from collections import namedtuple
from neo4j import GraphDatabase

##########################
# Create namedtuples used
# ------------------------
Connection = namedtuple('Connection', ['proto', 'recvq', 'sendq', 'localaddr', 'localport', 'remoteaddr', 'remoteport', 'state', 'pid', 'program'])
Host = namedtuple('Host', ['hostname', 'ipaddr'])

##########################
# Constants
# ------------------------
URI = "bolt://localhost:7687"


##########################
# Parse Arguments
# ------------------------
parser = argparse.ArgumentParser(
    description = "Parse Netstat output files and import them into Neo4j Graph Database"
    )
parser.add_argument('--files', '-f', nargs='+', help='Pass the File or Files to analyse')
args = parser.parse_args()
for arg in vars(args):
    filenames = getattr(args, arg)

# Create driver for neo4j:
# TODO: Allow these to be parsed in from args or ENV
neo4jusername = input("Neo4j username: ")
neo4jpassword = getpass("Neo4j password: ")
driver = GraphDatabase.driver(URI, auth=(neo4jusername, neo4jpassword))

class N4JQueue(set):
    def __init__(self, driver: GraphDatabase.driver, buffer_size: int = 10000):
        self._driver = driver
        self._buffer_size = buffer_size

    def submit(self):
        with self._driver.session() as session:
            for item in self:
                try:
                    session.run(item)
                    self.remove(item)
                except Exception as e:
                    print("Issue with submitting or removing item: {}".format(e))

    def add(self, element) -> None:
        super().add(element= element)

        if len(self) >= self._buffer_size:
            self.submit()

class CachedDNSLookup:
    """
    This class provides a simple dictionary backed cache for hostname lookups.
    """
    def __init__(self):
        self._cache= {}

    def get_host_by_address(self, addr):
        if addr not in self._cache.keys():
            self._cache[addr] = socket.gethostbyaddr(addr)[0]
        return self._cache[addr]

def ProgressBar(value, endvalue, bar_length = 50):
    """
    Show a progress bar for an iteration
    Use something like:
    ProgressBar(index, len(item)-1)
    """
    percent = float(value) / endvalue
    arrow = '-' * int(round(percent * bar_length)-1) + '>'
    spaces = ' ' * (bar_length - len(arrow))

    # TODO: Change this to display at least 2 decimal places
    print("\rPercent: [{0}] {1}%".format(arrow + spaces, int(round(percent * 100))))

def main():
    """
    The main entry point!
    :return: None
    """

    all_connections = []
    sources = {}

    dns_lookup = CachedDNSLookup()

    n4j_queue = N4JQueue(driver, buffer_size=10000)

    # First, we read this into an array, parsing as we go.
    for file in filenames:
        print("Reading in file: ",file)
        with open(file, 'r') as f:
            for line in f:
                current_line = line.split()
                print(current_line)
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
                all_connections.append(current_connection)

        print("Finished with :", file)

    # Create working Sets
    all_addresses = set()
    local_connection = set()
    remote_connections = set()
    all_programs = set()

    for conn in all_connections:
        all_addresses.add(conn.localaddr)
        all_addresses.add(conn.remoteaddr)
        local_connection.add(conn.localaddr)
        remote_connections.add(conn.remoteaddr)
        all_programs.add(conn.program)

    print("Connections loaded.")

    for host in all_addresses:
        try:
            name = dns_lookup.get_host_by_address(host)
        except:
            name = "UNKNOWN"

        add_host_str = 'CREATE (A:COMPUTER {IP: "{}", FQDN: "{}"})'.format(host, name)
        n4j_queue.add(add_host_str)
    print("Hosts loaded.")

    for program in all_programs:
        add_program = 'CREATE (A:PROGRAM {Name: "{}"})'.format(program)
        n4j_queue.add(add_program)
    print("Programs loaded.")

    for conn in all_connections:
    for index, conn in enumerate(all_connections):
        if conn.localaddr not in sources.keys():
            sources[conn.localaddr] = []
        if conn.remoteaddr not in sources[conn.localaddr]:
            add_app_relationship =  f'MATCH (A:COMPUTER {{IP: "{conn.localaddr}"}}),'\
                                    f'(B:PROGRAM {{Name: "{conn.program}"}}),'\
                                    f'(C:COMPUTER {{IP: "{conn.remoteaddr}"}}) CREATE (A)-[:RUNS]->(B)'

            add_host_relationship = f'MATCH (A:COMPUTER {{IP: "{conn.localaddr}"}}),'\
                                    f'(B:PROGRAM {{Name: "{conn.program}"}}),'\
                                    f'(C:COMPUTER {{IP: "{conn.remoteaddr}"}}) '\
                                    f'CREATE (B)-[:CONNECTS_TO {{Local_Port: "{conn.localport}", '\
                                    f'Remote_Port: "{conn.remoteport}", '\
                                    f'Protocol: "{conn.proto}", '\
                                    f'State: "{conn.state}"}}]->(C)'

            n4j_queue.add(add_app_relationship)
            n4j_queue.add(add_host_relationship)

            sources[conn.localaddr].append(conn.remoteaddr)

    ProgressBar(index, len(all_connections)-1)
    print("Relationships have been made.")

    # Write remaining contents of the buffer.
    n4j_queue.submit()

if __name__ == '__main__':
    main()
