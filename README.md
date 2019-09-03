# python-nettopo
Network topology via Neo4j Graph Platform from `netstat` output.

## Requirements

* neo4j
* python3 
* netstat output. Either a single large file, or multiple files.
  The script has been tested with output generated via `sudo netstat -plaunt >> $(hostname -s).netstat` as the source.

The default assumption is that neo4j is available at `bolt://localhost:7687`. If this needs to be changed it can be overwritten by setting the environment variable `NEO4J_HOST=bolt://127.0.01:7687`. Likewise, default behaviour is to prompt for neo4j username and password, these can also be specified as environment variables (`NEO4J_USER` `NEO4J_PASS`) or command line arguments (`--n4j-user`/`-u` and  `--n4j-pass`/`-p`.

## Usage

`./nstopo.py --n4j-user USERNAME --n4j-pass PASSWORD -f ${HOSTNAME}.netstat`

or

`./nstopo.py -f /path/to/data/*.netstat`
Where the * becomes a list of filenames from, say, multiple different hosts.


## Contributing

Contributions are welcome. Please submit a Pull Request with any modifications / improvements.

## Author

Ben C-S
