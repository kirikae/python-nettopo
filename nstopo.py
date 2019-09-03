#!/usr/bin/env python

import socket
import argparse
import os

from getpass import getpass
from collections import namedtuple
from neo4j import GraphDatabase

from collections import  Counter


import logging

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)



##########################
# Create namedtuples used
# ------------------------
Connection = namedtuple('Connection', ['proto', 'recvq', 'sendq', 'localaddr', 'localport', 'remoteaddr', 'remoteport', 'state', 'pid', 'program'])
Host = namedtuple('Host', ['hostname', 'ipaddr'])

##########################
# Constants
# ------------------------
ENABLE_DNS = False


URI = "bolt://localhost:7687"
# overwrite if a host is specified
if "NEO4J_HOST" in os.environ.keys():
    logging.info("Using NEO4J hostname from ENV")
    URI = os.environ.get("NEO4J_HOST")



##########################
# Parse Arguments
# ------------------------
parser = argparse.ArgumentParser(
    description = "Parse Netstat output files and import them into Neo4j Graph Database"
    )
parser.add_argument('--files', '-f', nargs='+', help='Pass the File or Files to analyse')
parser.add_argument('--n4j-user', '-u', help='neo4j User Name', default=os.environ.get("NEO4J_USER"))
parser.add_argument('--n4j-pass', '-p', help='neo4j Password', default=os.environ.get("NEO4J_PASS"))
args = parser.parse_args()

if args.files is None or len(args.files) == 0:
    raise Exception("No input files specified.")

if args.n4j_user is None:
    neo4jusername = input("Neo4j username: ")
else:
    neo4jusername = args.n4j_user

if args.n4j_pass is None:
    neo4jpassword = getpass("Neo4j password: ")
else:
    neo4jpassword = args.n4j_pass

filenames = args.files

# Check some silly assumptions.
assert len(filenames) > 0
assert neo4jusername is not None and neo4jusername != ""
assert neo4jpassword is not None and neo4jpassword != ""

# Create driver for neo4j:
driver = GraphDatabase.driver(URI, auth=(neo4jusername, neo4jpassword))

class N4JQueue(set):
    """
    This class provides a small amount of smarts on top of a basic set in Python.
    Once the nominated buffer size is reached, the entire contents of the set
    are placed into the database using the specified driver.

    """
    def __init__(self, driver: GraphDatabase.driver, buffer_size: int = 10000):
        self._driver = driver
        self._buffer_size = buffer_size

    def submit(self):
        """
        Submits the entire contents of self to the database, removing items that were correctly submitted.
        :return:
        """
        done_items = set()
        with self._driver.session() as session:
            for item in self:
                try:
                    session.run(item)
                    done_items.add(item)
                except Exception as e:
                    logging.exception(e)

            for item in done_items:
                self.remove(item)

    def add(self, element) -> None:
        super().add(element)

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
            logging.info(f"Looking up DNS for: {addr}.")
            self._cache[addr] = socket.gethostbyaddr(addr)[0]
        return self._cache[addr]

def escape_strings(in_string) -> str:
    replaced_str = in_string.replace(".", "_").replace(":","|")
    return f"A_{replaced_str}"

def main():
    """
    The main entry point!
    :return: None
    """

    all_connections = []
    sources = {}

    dns_lookup = CachedDNSLookup()

    n4j_queue = N4JQueue(driver, buffer_size=10000)

    # Clear the current DB
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")

    # First, we read this into an array, parsing as we go.
    for file in filenames:
        logging.info(f"Reading in file: {file}")
        with open(file, 'r') as f:
            for line in f:
                current_line = line.split()
                logging.debug(current_line)
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

        logging.info(f"Finished with: {file}. {len(all_connections)} now loaded.")

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

    logging.info(f"Connections loaded. {len(all_addresses)} addresses, "\
                 f"{len(local_connection)} local connections, "\
                 f"{len(local_connection)} remote connections, "\
                 f"{len(all_programs)} programs.")

    for host in all_addresses:
        try:
            if ENABLE_DNS:
                name = dns_lookup.get_host_by_address(host)
            else:
                name = host
        except socket.herror:
            name = host
        except Exception as e:
            logging.error(f"Error looking up DNS for {host}.")
            logging.exception(e)
            raise e

        add_host_str = f'CREATE ({escape_strings(host)}:COMPUTER {{IP: "{host}", FQDN: "{name}"}})'
        n4j_queue.add(add_host_str)

    n4j_queue.submit()
    logging.info("Hosts loaded.")

    for program in all_programs:
        add_program = f'CREATE (A:PROGRAM {{Name: "{program}"}})'
        n4j_queue.add(add_program)

    n4j_queue.submit()
    logging.info("Programs loaded.")

    app_relationship_counter = Counter()

    for conn in all_connections:
        if conn.localaddr not in sources.keys():
            sources[conn.localaddr] = []
        if conn.remoteaddr not in sources[conn.localaddr]:
            app_relationship_counter[(conn.localaddr, conn.program)] += 1

            add_host_relationship = f'MATCH (A:COMPUTER {{IP: "{conn.localaddr}"}}),'\
                                    f'(B:PROGRAM {{Name: "{conn.program}"}}),'\
                                    f'(C:COMPUTER {{IP: "{conn.remoteaddr}"}}) '\
                                    f'CREATE (B)-[:CONNECTS_TO {{Local_Port: "{conn.localport}", '\
                                    f'Remote_Port: "{conn.remoteport}", '\
                                    f'Protocol: "{conn.proto}", '\
                                    f'State: "{conn.state}"}}]->(C)'

            n4j_queue.add(add_host_relationship)


            sources[conn.localaddr].append(conn.remoteaddr)
    logging.info("Connections loaded.")

    # Now we build the app relationships using total counts of number of times encountered.
    for conn_tuple in app_relationship_counter.keys():
        (conn_localaddr, conn_program) = conn_tuple
        conn_count = app_relationship_counter[conn_tuple]

        add_app_relationship =  f'MATCH (A:COMPUTER {{IP: "{conn_localaddr}"}}),'\
                                f'(B:PROGRAM {{Name: "{conn_program}"}})'\
                                f'CREATE (A)-[:RUNS {{Count: "{conn_count}"}}]->(B) '

        n4j_queue.add(add_app_relationship)

    # Write remaining contents of the buffer.
    n4j_queue.submit()

if __name__ == '__main__':
    main()
