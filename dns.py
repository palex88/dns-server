#!usr/bin/env/python

#######################################################################################################################
# File:           dns.py
# Author:         Alex Thompson
# Github:         palex88
# Date Created:   2018-02-16
# Date Modified:  2018-02-20
# Python Version: 3.6
#
# Purpose:        This is a basic DNS server that uses a dummy zone file to deliver an IP address when querying my
#                 github.io page, 'palex88.github.io'.
#
# Sources:        DNS RFC: https://www.ietf.org/rfc/rfc1035.txt
#                 HowCode DNS Server tutorial: https://github.com/howCodeORG/howDNS
#######################################################################################################################

import socket
import json
import glob

PORT = 53
IP = '127.0.0.1'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP, PORT))


def load_zones():
    '''
    Reads from files the to match IP addresses with domain names, and then returns a dictionary of
    domain names and their IP addresses.

    :return:
    '''
    json_zone = {}
    zone_files = glob.glob('zones/*.zone')

    for zone in zone_files:
        with open(zone) as zone_data:
            data = json.load(zone_data)
            zone_name = data["$origin"]
            json_zone[zone_name] = data

    return json_zone


ZONE_DATA = load_zones()


def get_flags(flags):
    '''
    Takes in a list of flags present in a DNS quesry, and returns them as bytes.

    :param flags:
    :return:
    '''
    byte1 = bytes(flags[:1])

    qr = '1'

    op_code = ''
    for bit in range(1, 5):
        op_code += str(ord(byte1) & (1 << bit))
    aa = '1'

    tc = '0'

    rd = '0'

    ra = '0'

    z = '000'

    r_code = '0000'

    return int(qr + op_code + aa + tc + rd, 2).to_bytes(1, byteorder='big') + \
           int(ra + z + r_code, 2).to_bytes(1, byteorder='big')


def get_question_domain(data):
    '''
    Converts the parts of the domain from bytes to chars.

    :param data:
    :return:
    '''
    state = 0
    expected_len = 0
    domain_string = ''
    domain_parts = []
    x = 0
    y = 0
    for byte in data:
        if state == 1:
            if byte != 0:
                domain_string += chr(byte)
            x += 1
            if x == expected_len:
                domain_parts.append(domain_string)
                domain_string = ''
                state = 0
                x = 0
            if byte == 0:
                domain_parts.append(domain_string)
                break
        else:
            state = 1
            expected_len = byte
        y += 1

    question_type = data[y:y+2]

    return domain_parts, question_type


def get_zone(domain):
    '''
    Gets the domain name data from the zones files.

    :param domain:
    :return:
    '''
    global ZONE_DATA

    zone_name = '.'.join(domain)
    return ZONE_DATA[zone_name]


def get_recs(data):
    '''
    Gets the record requests from the DNS request and changes them to bytes.

    :param data:
    :return:
    '''
    domain, question_type = get_question_domain(data)
    qt = ''

    if question_type == b'\x00\x01':
        qt = 'a'

    zone = get_zone(domain)

    return zone[qt], qt, domain


def build_question(domain_name, rec_type):
    '''
    Builds the DNS request questions that can then be parsed for the response.

    :param domain_name:
    :param rec_type:
    :return:
    '''
    q_bytes = b''

    for part in domain_name:
        length = len(part)
        q_bytes += bytes([length])

        for char in part:
            q_bytes += ord(char).to_bytes(1, byteorder='big')

    if rec_type == 'a':
        q_bytes += (1).to_bytes(2, byteorder='big')

    q_bytes += (1).to_bytes(2, byteorder='big')

    return q_bytes


def rec_to_bytes(rec_type, rec_ttl, rec_value):
    '''
    Changes the record repsonses to bytes.

    :param rec_type:
    :param rec_ttl:
    :param rec_value:
    :return:
    '''
    r_bytes = b'\xc0\x0c'

    if rec_type == 'a':
        r_bytes = r_bytes + bytes([0]) + bytes([1])

    r_bytes = r_bytes + bytes([0]) + bytes([1])

    r_bytes += int(rec_ttl).to_bytes(4, byteorder='big')

    if rec_type == 'a':
        r_bytes = r_bytes + bytes([0]) + bytes([4])

        for part in rec_value.split('.'):
            r_bytes += bytes([int(part)])

    return r_bytes


def build_repsonse(data):
    '''
    Builds the response that is sent back after a request is made.

    :param data:
    :return:
    '''
    # Transaction ID
    transaction_id = data[:2]

    # Get flags
    flags = get_flags(data[2:4])

    # Question count
    qd_count = b'\x00\x01'

    # Answer count
    an_count = len(get_recs(data[12:])[0]).to_bytes(2, byteorder='big')

    # Namesserver count
    ns_count = (0).to_bytes(2, byteorder='big')

    # Additional count
    ar_count = (0).to_bytes(2, byteorder='big')

    # Create DNS header
    dns_header = transaction_id + flags + qd_count + an_count + ns_count + ar_count

    # Create DNS body
    dns_body = b''

    # Get answer for query
    records, rec_type, domain_name = get_recs(data[12:])

    dns_question = build_question(domain_name, rec_type)

    for record in records:
        dns_body += rec_to_bytes(rec_type, record["ttl"], record["value"])

    return dns_header + dns_question + dns_body


def run():
    '''
    Run the DNS server that listens for requests. Server is run on port 53 with IP 127.0.0.1.

    :return:
    '''
    while 1:
        data, addr = sock.recvfrom(512)
        r = build_repsonse(data)
        sock.sendto(r, addr)


if __name__ == '__main__':
    run()
