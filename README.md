# dns_pcap_extractor
Python script that extract dns traffic data from pcap file and can export to csv file

It relies on the pcapy library

## Invocation
python dns_pcap_extractor.py -h
usage: dns_pcap_extractor.py [-h] [--infile INFILE] [--outfile OUTFILE]
                             [--logfile LOGFILE] [--progress [PROGRESS]]
                             [--loglevel LOGLEVEL] [--summary]

optional arguments:
  -h, --help            show this help message and exit
  --infile INFILE       specifies the name of the input pcap file
  --outfile OUTFILE     specifies the name of the output csv file
  --logfile LOGFILE.    specifies the name of the log file
  --progress [PROGRESS] display a progress indicator every PROGRESS lines read
  --loglevel LOGLEVEL   specifies the log level (INFO, DEBUG)
  --summary             display a summary of the data analyzed




