# python-nettopo
Network topology from netstat output

## Requirements

* neo4j
* python3 
* netstat output. Either a single large file, or multiple files.
  The script has been tested with output generated via `sudo netstat -plaunt >> $(hostname -s).netstat` as the source.

## Usage

`./nstopo.py -f ${HOSTNAME}.netstat`

or

`./nstopo.py -f /path/to/data/*.netstat`
Where the * becomes a list of filenames from, say, multiple different hosts.


## Contributing

Contributions are welcome. Please submit a Pull Request with any modifications / improvements.

## Author

Ben C-S
