#!/usr/bin/env python

from copy import copy
from neo4j import GraphDatabase

uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=("neo4j", "test"))

hosts = []
with open("dns_resolved.list", 'r') as dnsList:
    for line in dnsList:
        host = {}
        host["address"] = line.split(" ")[0]
        host["name"] = line.split(" ")[1].strip()
        hosts.append(host)

for host in hosts:
    query = "CREATE (A:COMPUTER {Name: \"" + host["address"] + "\", Hostname: \"" + host["name"] + "\"})"
    print(query)

    with driver.session() as session:
        session.run(query)
