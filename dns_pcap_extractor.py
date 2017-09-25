
"""
Copyright 2017 Jean-Noel Colin

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

import argparse
import csv
import logging
import pcapy as pcapy
import socket
import struct
import sys
import time
from struct import unpack
import re

from dns_message import DNSHeader, DNSQuestion, DNSRR, DNSMessage, dns_rr_types, dns_query_classes, field_names, \
    dns_opcodes, dns_response_codes
from pcap_data import ip_protos, ETH_HEADER_LENGTH, IP_HEADER_LENGTH, TCP_HEADER_LENGTH, UDP_HEADER_LENGTH


class ParseException(Exception):
    pass

logger = logging.getLogger('pcapreader')
logger_data = logging.getLogger('pcapreader_data')

def mac2str (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0] ,a[1] , a[2], a[3], a[4] , a[5])
    return b

# reads a qname at the beginning of the buffer
# returns the qname and the position of the next byte to be read

def get_qname(buffer):
    pos=0
    l=buffer[pos]
    labels=[]
    while l > 0:
        labels.append(buffer[pos+1:pos+1+l].decode())
        pos+=l+1
        l=buffer[pos]
    return '.'.join(labels), pos+1

"""
retrieves a name from the buffer. Since the name may be subject to compression, if a length byte starts with 0x11,
next byte is an offset in the DNS payload where the rest of the name should be extracted
"""

def get_rr_name(buffer):
    pos=0
    labels=[]
    try:
        l = buffer[pos]
        while l > 0:
            if (l >> 6) == 3:
                # using compression scheme: let's resolve the pointer
                offset=unpack('!H',buffer[pos:pos+2])
                offset=offset[0] ^ 0xC000 # remove the first 2 bits
                # get qname at offset
                return '.'.join(labels), pos+2,offset
            else:
                labels.append(buffer[pos+1:pos+1+l].decode())
                pos+=l+1
            l=buffer[pos]
    except:
        raise(ParseException('pos: {} buffer: {}'.format(pos,buffer)))
    return '.'.join(labels), pos+1,0


def get_compressed_name(dns_payload,start,length=0,proto='udp'):
    """
    this method extracts a (potentially) compressed name from the DNS payload
    a compressed name can be present either in the name of a RR or in the RDATA of the RR
    in the case of name, there is no length indication
    in the case of rdata, the rdlength field gives the expected length
    :param dns_payload: the full DNS payload (in case of tcp, with the extra 2 bytes in front
    :param start: start position of the name to extract
    :param length: length of the data to process (only for rdata, used to detect incomplete record)
    :param protocol: udp or tcp: used to add the 2 bytes in the pointer arithmetics
    :return:
    """
    data, pos, ptr = get_rr_name(dns_payload[start:])
    while ptr > 0:
        # name compression scheme is used, I have to get the rest of the qname at the offset
        if proto == 'tcp':
            # remove two bytes because pointer gives the offset from the Identifier field in the DNS header
            # in tcp DNS messages, this field follows an extra 2 bytes field
            ptr -= 2
        data_end, pos2, ptr = get_rr_name(dns_payload[ptr:])

        if len(data) > 0:
            data = '.'.join((data, data_end))
        else:
            data = data_end
    return data,pos




def parse_rr_rdata(rr_type, dns_payload, start, length,proto='udp'):
    """
    parses the RDATA portion of a RR record, starting at position start of dns_payload, with an expected length of length
    :param rr_type: type of RR to read
    :param dns_payload: full dns_payload
    :param start: start of the RR rdata in the payload
    :param length: length of the RR data in the payload
    :return:
    """
    buffer=dns_payload[start:start+length]
    if len(buffer)<length:
        raise ParseException('insufficient data in rdata. expected {} got {}'.format(length,len(buffer)))
    if rr_type == 1:     # A
        if length==4:
            ip=unpack('BBBB',buffer)
            return '{}.{}.{}.{}'.format(ip[0],ip[1],ip[2],ip[3])
    elif rr_type == 2:   # NS
        return get_compressed_name(dns_payload,start,length,proto=proto)
    elif rr_type == 5:   # CNAME
        return get_compressed_name(dns_payload,start,length,proto=proto)
    elif rr_type == 6:   # SOA
        return buffer
    elif rr_type == 12:  # PTR
        return get_compressed_name(dns_payload,start,length,proto=proto)
    elif rr_type == 13:  # HINFO
        return buffer
    elif rr_type == 14:  # MINFO
        return buffer
    elif rr_type == 15:  # MX
        return buffer
    elif rr_type == 16:  # TXT
        return buffer
    elif rr_type == 28:  # AAAA
        if length==16:
            ip=unpack('BBBBBBBBBBBBBBBB',buffer)
            return '{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}'.\
                format(ip[0],ip[1],ip[2],ip[3],ip[4],ip[5],ip[6],ip[7],ip[8],
                       ip[9],ip[10],ip[11],ip[12],ip[13],ip[14],ip[15])
        else:
            logger.error('error in AAAA length: {}'.format(length))
        return buffer
    else:
        return 'unsupported RR type'


# extracts a dns question data starting at offset in the data buffer
# returns the question and the position of the next byte to read

def parse_dns_question(data,offset):
    buffer=data[offset:]
    qname, pos = get_qname(buffer)
    qtype = unpack('!H', buffer[pos:pos + 2])
    qclass = unpack('!H', buffer[pos + 2:pos + 4])
    question = DNSQuestion(qname, qtype[0], qclass[0])
    return question, offset+pos

def parse_dns_rr(dns_payload,offset,proto='udp'):
    buffer=dns_payload[offset:]
    name,pos=get_compressed_name(dns_payload,offset,proto=proto)
    try:
        params=unpack('!HHIH',buffer[pos:pos+10])
    except struct.error as e:
        raise(ParseException(e))
    rr_type=params[0]
    rr_class = params[1]
    rr_ttl = params[2]
    rr_rdlength = params[3]
    rr_rdata=parse_rr_rdata(rr_type, dns_payload, offset + pos + 10, rr_rdlength)
    rr=DNSRR(name,rr_type, rr_class, rr_ttl, rr_rdlength, rr_rdata)
    return rr,offset+pos+10+rr_rdlength

def parse_dns_message(dns_payload,proto='udp'):
    """
    parses a DNS message
    :param dns_payload: the DNS message payload extracted from the ethernet frame; it starts at the DNS data
    with ethernet, IP and UDP/TCP headers removed
    :return:
    """
    # identification 2B, parameters 2x1B, counts: 4x2B
    #
    if proto=='tcp':
        #https://www.ietf.org/rfc/rfc1035.txt
        dns_query_length=unpack('!H',dns_payload[:2])[0]
        dns_hdr_fields = unpack('!HBBHHHH', dns_payload[2:14])
    else:
        dns_hdr_fields = unpack('!HBBHHHH', dns_payload[:12])
    dns_header=DNSHeader(dns_hdr_fields[0], dns_hdr_fields[1]>>7, (dns_hdr_fields[1]>>3) & 0xF, (dns_hdr_fields[1]>>2) & 0x1,
                         (dns_hdr_fields[1] >> 1) & 0x1, (dns_hdr_fields[1]) & 0x1, (dns_hdr_fields[2]>>7) & 0x1,
                         dns_hdr_fields[2] & 0xf, dns_hdr_fields[3], dns_hdr_fields[4], dns_hdr_fields[5], dns_hdr_fields[6])
    dns_message=DNSMessage()
    dns_message.header=dns_header
    logger_data.debug('DNS header: ' + str(dns_header))
    # parse questions
    """
    Messages sent over TCP connections use server port 53 (decimal).  The
    message is prefixed with a two byte length field which gives the message
    length, excluding the two byte length field.  This length field allows
    the low-level processing to assemble a complete message before beginning
    to parse it.
    """
    if proto=='tcp':
        offset=14  # because DNS header is 14B long for TCP queries (extra Length field)
    else:
        offset=12  # because DNS header is 12B long for UDP queries

    for i in range(dns_header.question_entry_count):
        if offset < len(dns_payload):
            question, offset=parse_dns_question(dns_payload, offset)
            dns_message.questions.append(question)
            logger_data.debug('Question {}: {}'.format(i,question))
            offset+=4 # add the QTYPE and QCLASS fields
        else:
            raise(ParseException('insufficient data in questions section at offset {}'.format(offset)))
    for i in range(dns_header.answer_rr_count):
        if offset < len(dns_payload):
            rr, offset=parse_dns_rr(dns_payload, offset,proto=proto)
            logger_data.debug('Answer {}: {}'.format(i,rr))
            dns_message.answer_rrs.append(rr)
        else:
            raise(ParseException('insufficient data in answers section at offset {}'.format(offset)))
    for i in range(dns_header.authority_rr_count):
        if offset < len(dns_payload):
            rr, offset=parse_dns_rr(dns_payload, offset,proto=proto)
            dns_message.ns_rrs.append(rr)
            logger_data.debug('Authority {}: {}'.format(i,rr))
        else:
            raise(ParseException('insufficient data in authorities section at offset {}'.format(offset)))
    for i in range(dns_header.additional_rr_count):
        if offset < len(dns_payload):
            rr, offset=parse_dns_rr(dns_payload, offset,proto=proto)
            dns_message.additional_rrs.append(rr)
            logger_data.debug('Additional {}: {}'.format(i,rr))
        else:
            raise(ParseException('insufficient data in additional section at offset {}'.format(offset)))
    return dns_message


def parse_tcp_packet(raw_ethernet_frame,extra_headers,total_length):
    """
    parses a TCP packet
    :param raw_ethernet_frame: raw TCP packet starting with IP header
    :return:
    """

    tcp_header = raw_ethernet_frame[ETH_HEADER_LENGTH+IP_HEADER_LENGTH+extra_headers:ETH_HEADER_LENGTH+IP_HEADER_LENGTH+TCP_HEADER_LENGTH+extra_headers]
    tcph = unpack('!HHIIBBHHH', tcp_header) # sport (2B) dport (2B) seqnum (4B) acknum (4B) offset (4b) reserved (4b)
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    data_offset = doff_reserved >> 4

    if data_offset*4+IP_HEADER_LENGTH==total_length:
        raise(ParseException('not a DNS packet. Empty tcp packet'))

    # in a TCP DNS Query, there is an extra Length field before the identifier in the DNS Header
    # see https://www.ietf.org/rfc/rfc1035.txt
    """
    Messages sent over TCP connections use server port 53 (decimal).  The
    message is prefixed with a two byte length field which gives the message
    length, excluding the two byte length field.  This length field allows
    the low-level processing to assemble a complete message before beginning
    to parse it.
    """
    h_size = ETH_HEADER_LENGTH+IP_HEADER_LENGTH+extra_headers+(data_offset * 4)
    data = raw_ethernet_frame[h_size:]

    logger_data.debug('TCP Src port: {} Dst port: {} Data offset: {} Acknowledgement: {}'.format(source_port, dest_port, data_offset,acknowledgement))
    if source_port == 53 or dest_port == 53:
        return parse_dns_message(data,'tcp')
    else:
        raise(ParseException('not a DNS packet {}'))


def parse_udp_packet(raw_ethernet_frame,extra_headers):
    """
    parses a udp datagram
    :param raw_ethernet_frame: raw ethernet frame starting with IP Header
    :return:
    """
    udp_header = raw_ethernet_frame[ETH_HEADER_LENGTH+IP_HEADER_LENGTH+extra_headers:ETH_HEADER_LENGTH+IP_HEADER_LENGTH+UDP_HEADER_LENGTH+extra_headers]
    udph = unpack('!HHHH', udp_header)
    source_port = udph[0]
    dest_port = udph[1]
    length = udph[2]
    checksum = udph[3]
    headers_size = ETH_HEADER_LENGTH+IP_HEADER_LENGTH+UDP_HEADER_LENGTH+extra_headers
    data_size = len(raw_ethernet_frame) - headers_size
    data = raw_ethernet_frame[headers_size:]
    logger_data.debug('UDP Src port: {} Dst port: {} Length: {}'.format(source_port, dest_port, length))
    if source_port == 53 or dest_port == 53:
        return parse_dns_message(data)
    else:
        raise(ParseException('not a DNS packet {}'))

def parse_raw_packet(frame):
    """
    parses packet captured from a pcap source; packet is assumed to be an ethernet frame
    :param frame: the raw packet
    :return:
    """
    eth_header = frame[:ETH_HEADER_LENGTH]
    eth = unpack('!6s6sH', eth_header)  # 6s = 6 bytes, H = 2 bytes
    eth_protocol = socket.ntohs(eth[2])
    logger_data.debug('ETH Src MAC: {} Dst MAC: {} Protocol: {} Len: {}'.format(mac2str(eth[1]), mac2str(eth[0]), str(eth_protocol), len(frame)))
    extra_headers=0
    if eth_protocol == 8:     # Ethernet
        pass
    elif eth_protocol == 129: # 802.1Q
        extra_headers=4
    else:
        raise(ParseException('not a eth packet {}'.format(eth_protocol)))

    # Parse IP header
    ip_header = frame[ETH_HEADER_LENGTH+extra_headers:ETH_HEADER_LENGTH+IP_HEADER_LENGTH+extra_headers]
    ip_version=ip_header[0] >> 4
    if ip_version == 4:
        iph = unpack('!BBHHHBBH4s4s', ip_header)   # B=1B, H=2B, s=1B
        version_ihl = iph[0]         # version is in the 4 leftmost bits
        version = version_ihl >> 4   # select 4 leftmost bits
        ihl = version_ihl & 0xF      # select 4 rightmost bits
        iph_length = ihl * 4
        total_length=iph[2]
        identification=iph[3]
        fragment=iph[4]
        fragment_df= 1 if ((fragment >> 13) & 0x2) > 0 else 0
        fragment_mf=1 if ((fragment >> 13) & 0x1) > 0 else 0
        fragment_offset=fragment & 0x1FFF # set first 3 bits to 0
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        logger_data.debug('IPv4: Identification: {} Version: {} IP Header length: {} Total length: {} TTL: {} Protocol: {} ({}) Src IP: {} Dst IP: {} do not fragment: {} fragmented: {} Fragment offset: {}'.
                     format(identification, version, ihl, total_length, ttl, protocol, ip_protos.get(protocol,'unknown'), s_addr, d_addr,fragment_df,fragment_mf,fragment_offset))
        if protocol == 6: # TCP
            return parse_tcp_packet(frame,extra_headers,total_length)
        elif protocol == 17: #UDP
            return parse_udp_packet(frame,extra_headers)
        else:
            raise(ParseException('unknown protocol: {}'.format(ip_protos.get(protocol,'unknown'))))

def read_pcap_file(in_filename, out_filename, summary_report=False, progress_every=0):
    count=errors=0
    num_queries=num_answers=0
    query_names=set()
    query_types=dict()
    query_classes=dict()
    response_record_counts=[dict(),dict(),dict(),dict()]
    response_ttl=dict()
    domain_components=dict()
    opcodes=dict()
    response_codes=dict()

    csv_file=open(out_filename, 'w',newline='')
    csv_writer = csv.DictWriter(csv_file,fieldnames=field_names)
    csv_writer.writeheader()

    start = time.time()
    pcap_file=pcapy.open_offline(in_filename)
    (header, payload) = pcap_file.next()
    while header is not None:
        count+=1
        if progress_every > 0:
            if count % progress_every==0:
                logger.info(count)
        try:
            dns_message=parse_raw_packet(payload)
            if dns_message.header.qr_flag==0:
                num_queries+=1
                # I don't really care about queries, so I only count them
            elif dns_message.header.qr_flag==1:
                num_answers+=1
                opcodes[dns_message.header.opcode]=opcodes.get(dns_message.header.opcode,0)+1
                response_codes[dns_message.header.rcode]=response_codes.get(dns_message.header.rcode,0)+1
                d=response_record_counts[0]
                d[dns_message.header.question_entry_count]=d.get(dns_message.header.question_entry_count,0)+1
                d=response_record_counts[1]
                d[dns_message.header.answer_rr_count]=d.get(dns_message.header.answer_rr_count,0)+1
                d=response_record_counts[2]
                d[dns_message.header.authority_rr_count]=d.get(dns_message.header.authority_rr_count,0)+1
                d=response_record_counts[3]
                d[dns_message.header.additional_rr_count]=d.get(dns_message.header.additional_rr_count,0)+1
                for i in range(0,dns_message.header.question_entry_count):
                    query_names.add(dns_message.questions[i].qname)
                    query_types[dns_message.questions[i].qtype] = query_types.get(dns_message.questions[i].qtype,0)+1
                    query_classes[dns_message.questions[i].qclass] = query_classes.get(dns_message.questions[i].qclass,0)+1
                for i in range(0,dns_message.header.answer_rr_count):
                    response_ttl[dns_message.answer_rrs[i].ttl] = query_types.get(dns_message.answer_rrs[i].ttl,0)+1
                csv_writer.writerow(dns_message.as_dict())
        except ParseException as e:
            logger.debug('ParseException error at line {}: {}'.format(count,e))
            #traceback.print_exc()
            errors+=1
        except struct.error as e:
            logger.debug('struct.error at line {}: {}'.format(count,e))
            #traceback.print_exc()
            errors+=1
        except:
            logger.debug('error at line {}: {}'.format(count, sys.exc_info()[1]))
            errors+=1
            #traceback.print_exc()
        (header,payload)=pcap_file.next()

    end = time.time()
    csv_file.close()
    logger.info('Read {} records in {:.3f}s. {} errors'.format(count, end - start, errors))

    if summary_report:
        logger.info('Queries/Responses: {}/{}'.format(num_queries,num_answers))
        logger.info('Opcodes')
        for k,v in opcodes.items():
            logger.info('opcode: {} count: {}'.format(dns_opcodes.get(k,'unknown'),v))
        logger.info('Response codes')
        for k,v in response_codes.items():
            logger.info('response code: {} count: {}'.format(dns_response_codes.get(k,'unknown'),v))
        logger.info('query types')
        for k,v in query_types.items():
            logger.info('query type: {} count: {}'.format(dns_rr_types.get(k,'unknown'),v))
        for k,v in query_classes.items():
            logger.info('query class: {} count: {}'.format(dns_query_classes.get(k,'unknown'),v))

        sorted_list = sorted(response_record_counts[0].items(), key=lambda x: x[0])
        for k,v in sorted_list:
            logger.info('response question count: {} count: {}'.format(k,v))
        sorted_list = sorted(response_record_counts[1].items(), key=lambda x: x[0])
        for k,v in sorted_list:
            logger.info('response answer count: {} count: {}'.format(k,v))
        sorted_list = sorted(response_record_counts[2].items(), key=lambda x: x[0])
        for k,v in sorted_list:
            logger.info('response authority count: {} count: {}'.format(k,v))
        sorted_list = sorted(response_record_counts[3].items(), key=lambda x: x[0])
        for k,v in sorted_list:
            logger.info('response additional count: {} count: {}'.format(k,v))

        # sorted_list = sorted(response_ttl.items(), key=lambda x: x[0])
        # for k,v in sorted_list:
        #     logger.info('answer ttl: {} count: {}'.format(k,v))

        logger.info('#unique domains in queries: {}'.format(len(query_names)))
        for d in query_names:
            n=len(d.split('.'))
            domain_components[n]=domain_components.get(n,0)+1

        sorted_list = sorted(domain_components.items(), key=lambda x: x[0])
        for k,v in sorted_list:
            logger.info('number of domain components: {} count: {}'.format(k,v))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='PCAP dns reader')
    parser.add_argument('--infile', required=False)
    parser.add_argument('--outfile', required=False)
    parser.add_argument('--logfile', required=False)
    parser.add_argument('--progress', nargs='?', type=int, const=1000, required=False)
    parser.add_argument('--loglevel', default='INFO')
    parser.add_argument('--summary', action='store_true', default=False)
    args = parser.parse_args()

    if args.progress is None:
        progress_every=0
    else:
        progress_every=args.progress

    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % args.loglevel)

    logging.basicConfig(level=numeric_level)
    logger.setLevel(numeric_level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    if args.logfile is None:
        hdlr = logging.StreamHandler()
    else:
        hdlr = logging.FileHandler(args.logfile)
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)



    if args.infile is None:
        i_filename='data/dns-traffic.20140409.pcap'
    else:
        i_filename=args.infile
    if args.outfile is None:
        p = re.compile(r'.pcap$')
        o_filename=p.sub('.csv',i_filename)
    else:
        o_filename=args.outfile
    logger.info('Reading file {}'.format(i_filename))
    logger.info('Writing file {}'.format(o_filename))

    logger_data.disabled=True

    read_pcap_file(i_filename,o_filename, args.summary, progress_every)
