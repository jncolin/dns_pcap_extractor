# dns_pcap_extractor
Python script that extract dns traffic data from pcap file and can export to csv file. It relies on the pcapy library

It takes as input a pcap file and writes its output to a csv file. 
Only DNS queries or responses are taken into account, all other packets are discarded.
So far, no packet defragmentation takes place

If a logfile name is specified, output is sent to the file, otherwise, it's sent to the console.

When processing large files, it is useful to follow the progress. The script can display a short message every set of X packets read

A summary of the data analysed can optionally be displayed at the end of the process.

## Invocation
```
python dns_pcap_extractor.py -h
usage: dns_pcap_extractor.py [-h] [--infile INFILE] [--outfile OUTFILE]
                             [--logfile LOGFILE] [--progress [PROGRESS]]
                             [--loglevel LOGLEVEL] [--summary]

optional arguments:
  -h, --help            show this help message and exit
  --infile INFILE       specifies the name of the input pcap file
  --outfile OUTFILE     specifies the name of the output csv file
  --logfile LOGFILE     specifies the name of the log file
  --progress [PROGRESS] display a progress indicator every PROGRESS lines read
  --loglevel LOGLEVEL   specifies the log level (INFO, DEBUG)
  --summary             display a summary of the data analyzed
```




