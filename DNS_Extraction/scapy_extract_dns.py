from __future__ import print_function
from __future__ import absolute_import

__code_version__ = 'v0.0.1'
__code_desc__ = """
program extracts dns information from a pcap file
    ex: python {name}
""".format(name=__file__)

# Standard Libraries
import os
import csv
import argparse

# Third-Party Libraries
from scapy.all import DNSQR, DNSRR
from scapy.utils import rdpcap

def resolve_basedirectory():
    return os.path.dirname(os.path.abspath(__file__))

def read_dns_record_enum():
    enum = {}
    base = resolve_basedirectory()
    filename = base + os.path.sep + 'resources' + os.path.sep + 'dns_query_types.csv'
    with open(filename, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            key = int(row['id'])
            enum[key] = row['record']
    return enum

def dedup(arg):
    cst = set(arg)
    return list(cst)

def load_pcap(pcap):
    # @todo: possibly generate a packet list using sniff
    # sniff(offline=pcap,prn=method_filter_HTTP,store=0)

    # read pcap into memory
    packet_list = rdpcap(pcap)
    count = len(packet_list)
    print("[*]: Reading %d packets" % count)

    # get human readable types
    dns_type_enum = read_dns_record_enum()

    # extract information
    dns_queries = []
    dns_responses = []
    for packet in packet_list:
        if packet.haslayer(DNSRR):
            dnsr = packet[DNSRR]
            rrname = dnsr.rrname.decode('UTF-8')
            rdata = dnsr.rdata
            rrtype = dns_type_enum[dnsr.rclass]
            ttl = dnsr.ttl
            dns_queries.append( (rrname, rrtype) )
            dns_responses.append( (rrname, rrtype, ttl, rdata) )
        elif packet.haslayer(DNSQR):
            dnsr = packet[DNSQR]
            query = dnsr.qname.decode('UTF-8')
            query_type = dns_type_enum[dnsr.qtype]
            dns_queries.append( (query, query_type) )

    return dns_queries, dns_responses

def print_results(title, resultset):
    print(title)
    for item in resultset:
        print(item)

def handleArgs():
    #region BuildArgParser
    parser = argparse.ArgumentParser(description=__code_desc__)
    parser.add_argument('-V','--version', action='version', version='%(prog)s '+__code_version__)
    parser.add_argument('-v','--verbose', action='count', default=0, help="Print verbose output to the console. Multiple v's increase verbosity")
    parser.add_argument('--debug', action='store_true', help="Toggle debugging output to the console.")
    parser.add_argument('pcap', help='a packet capture to parse')
    return parser.parse_args()
    #endregion

def main():
    args = handleArgs()
    dnsq, dnsr = load_pcap(args.pcap)
    dnsq = dedup(dnsq)
    dnsr = dedup(dnsr)
    print_results('DNS Queries', dnsq)
    print_results('DNS Responses', dnsr)

if __name__=="__main__":
    main()
