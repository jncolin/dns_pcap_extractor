
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

dns_qr_codes={
    0:'Query',
    1: 'Response'
}

dns_opcodes={
    0: 'Standard query',
    1: 'Inverse query',
    2: 'Server Status Request'
}

dns_response_codes={
    0: 'No error',
    1: 'Format error',
    2: 'Server failure',
    3: 'Non existent domain',
    4: 'Query type not implemented',
    5: 'Query refused'
}

dns_rr_types={
    1: 'A',
    2: 'NS',
    3: 'MD',
    4: 'MF',
    5: 'CNAME',
    6: 'SOA',
    7: 'MB',
    8: 'MG',
    9: 'MR',
    10: 'NULL',
    11: 'WKS',
    12: 'PTR',
    13: 'HINFO',
    14: 'MINFO',
    15: 'MX',
    16: 'TXT',
    17: 'RP',
    18: 'AFSDB',
    19: 'X25',
    20: 'ISDN',
    21: 'RT',
    22: 'NSAP',
    23: 'NSAP-PTR',
    24: 'SIG',
    25: 'KEY',
    26: 'PX',
    27: 'GPOS',
    28: 'AAAA',
    29: 'LOC',
    30: 'NXT',
    31: 'EID',
    32: 'NIMLOC',
    33: 'SRV',
    34: 'ATMA',
    35: 'NAPTR',
    36: 'KX',
    37: 'CERT',
    38: 'A6',
    39: 'DNAME',
    40: 'SINK',
    41: 'OPT',
    42: 'APL',
    43: 'DS',
    44: 'SSHFP',
    45: 'IPSECKEY',
    46: 'RRSIG',
    47: 'NSEC',
    48: 'DNSKEY',
    49: 'DHCID',
    50: 'NSEC3',
    51: 'NSEC3PARAM',
    52: 'TLSA',
    53: 'SMIMEA',
    54: 'Unassigned',
    55: 'HIP',
    56: 'NINFO',
    57: 'RKEY',
    58: 'TALINK',
    59: 'CDS',
    60: 'CDNSKEY',
    61: 'OPENPGPKEY',
    62: 'CSYNC',
    99: 'SPF',
    100: 'UINFO',
    101: 'UID',
    102: 'GID',
    103: 'UNSPEC',
    104: 'NID',
    105: 'L32',
    106: 'L64',
    107: 'LP',
    108: 'EUI48',
    109: 'EUI64',
    249: 'TKEY',
    250: 'TSIG',
    251: 'IXFR',
    252: 'AXFR',
    253: 'MAILB',
    254: 'MAILA',
    255: '*',
    256: 'URI',
    257: 'CAA',
    258: 'AVC',
    32768: 'TA',
    32769: 'DLV',
    65535: 'Reserved',

}

dns_query_types={
    252: 'AXFR',
    253: 'MAILB',
    254: 'MAILA',
    255: '*'
}

dns_query_classes={
    1: 'IN',
    2: 'CSNET',
    3: 'CHAOS',
    4: 'Hesiod'
}

field_names = ['ts_sec','ts_usec','identifier', 'opcode', 'aa_flag', 'tc_flag', 'rd_flag', 'ra_flag', 'rcode', 'questions_count',
               'answers_count', 'authority_count', 'additional_count', 'q_name', 'q_type', 'q_class']


class DNSRR:
    def __init__(self):
        self.name=''
        self.rr_type=0
        self.rr_class=0
        self.ttl=0
        self.rdlength=0
        self.rdata=''

    def __init__(self, name, rr_type, rr_class, ttl, rdlength, rdata):
        self.name=name
        self.rr_type=rr_type
        self.rr_class=rr_class
        self.ttl=ttl
        self.rdlength=rdlength
        self.rdata=rdata

    def __str__(self):
        return 'name: {} rr_type: {} rr_class: {} ttl: {} rdlength: {} rdata: {}'.\
            format(self.name,dns_rr_types.get(self.rr_type,'unknown {}'.format(self.rr_type)),
                   dns_query_classes.get(self.rr_class, 'unknown {}'.format(self.rr_class)),
                   self.ttl, self.rdlength, self.rdata)


class DNSHeader:
    def __init__(self):
        self.identifier = self.qr_flag = self.opcode = self.aa_bit = self.tc_bit = self.rd_bit = self.ra_bit = self.rcode = 0
        self.question_entry_count = self.answer_rr_count = self.authority_rr_count = self.additional_rr_count = 0

    def __init__(self, identifier = 0, qr_flag = 0, opcode = 0, aa_bit = 0, tc_bit = 0,
                 rd_bit = 0, ra_bit = 0, rcode = 0, question_entry_count = 0,
                 answer_rr_count = 0, authority_rr_count = 0, additional_rr_count = 0):
        self.identifier = identifier
        self.qr_flag = qr_flag
        self.opcode = opcode
        self.aa_bit = aa_bit
        self.tc_bit = tc_bit
        self.rd_bit = rd_bit
        self.ra_bit = ra_bit
        self.rcode = rcode
        self.question_entry_count = question_entry_count
        self.answer_rr_count = answer_rr_count
        self.authority_rr_count = authority_rr_count
        self.additional_rr_count = additional_rr_count


    def __str__(self):
        return 'identifier: {} ({:x}) qr_flag: {} opcode: {} AA:TC:RD:RA {}:{}:{}:{} rcode: {} counts:{}:{}:{}:{}'.\
            format(self.identifier,
                   self.identifier,
                   self.qr_flag,
                   self.opcode,
                   self.aa_bit,
                   self.tc_bit,
                   self.rd_bit,
                   self.ra_bit,
                   self.rcode,
                   self.question_entry_count,
                   self.answer_rr_count,
                   self.authority_rr_count,
                   self.additional_rr_count)

class DNSQuestion:
    def __init__(self):
        self.qname=''
        self.qtype=0
        self.qclass=0

    def __init__(self, qname, qtype, qclass):
        self.qname=qname
        self.qtype=qtype
        self.qclass=qclass

    def __str__(self):
        return 'qname: {} qtype: {} qclass: {}'.format(self.qname,
                                                       dns_rr_types.get(self.qtype,'unknown {}'.format(self.qtype)),
                                                       dns_query_classes.get(self.qclass,'unknown {}'.format(self.qclass)))

class TimeStamp:
    def __init__(self):
        self.seconds=0
        self.microseconds=0

    def __init__(self, sec=0, usec=0):
        self.seconds=sec
        self.microseconds=usec

    def __str__(self):
        return '{}s{}usec'.format(self.ts.seconds,self.ts.microseconds)


class DNSMessage:
    def __init__(self):
        self.timestamp=None
        self.header=DNSHeader()
        self.questions=[]
        self.answer_rrs=[]
        self.ns_rrs=[]
        self.additional_rrs=[]

    def __str__(self):
        return '{}\n{}\n{}'.format(self.header,self.questions,self.answer_rrs)

    def as_dict(self):
        return {'ts_sec': self.timestamp.seconds,
                'ts_usec': self.timestamp.microseconds,
                'identifier': self.header.identifier,
                'opcode': self.header.opcode,
                'aa_flag': self.header.aa_bit,
                'tc_flag': self.header.tc_bit,
                'rd_flag': self.header.rd_bit,
                'ra_flag': self.header.ra_bit,
                'rcode': self.header.rcode,
                'questions_count': self.header.question_entry_count,
                'answers_count': self.header.answer_rr_count,
                'authority_count': self.header.authority_rr_count,
                'additional_count': self.header.additional_rr_count,
                'q_name': self.questions[0].qname,
                'q_type': dns_rr_types.get(self.questions[0].qtype,'unknown {}'.format(self.questions[0].qtype)),
                'q_class': dns_query_classes.get(self.questions[0].qclass, 'unknown {}'.format(self.questions[0].qclass))
                }