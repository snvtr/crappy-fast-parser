#!/usr/bin/python
# -*- coding: utf-8 -*-

######№############################################
# FAST Listener + crappy FAST parser for python 2 #
###################################################

import os
import sys
import time
import copy
import socket
import select
import xml.dom.minidom

from datetime import datetime
from struct import unpack
from collections import OrderedDict

def log_seq( log_fh, timestamp, seq, pkt_len, data ):
    log_fh.write(';'.join([timestamp, str(seq), str(pkt_len), str(data)] + '\n'))

def log_gap( gap_fh, feed_label, timestamp, seq, seq_diff ):
    gap_fh.write(';'.join([feed_label, str(timestamp), str(seq), str(seq_diff)] + '\n'))

def get_string(data):
    value = ''
    for i in range(0, len(data)):
        if ord(data[i]) < 128:
            value += data[i]
        else:
            value += chr(ord(data[i]) - 128)
            return value, data[i:]
    return '', data

def get_ByteVector(data):
    value = ''
    byte_vector_len = ord(data[0]) - 128
    for i in range(1, byte_vector_len):
        value += data[i]
    return value, data[byte_vector_len+1:]

def get_uInt(data):
    value = 0
    bits = []
    int_data = ''
    if ord(data[0]) == 128:
        return 0, data[1:]
    for i in range(0, len(data)):
        if ord(data[i]) < 128:
            int_data += data[i]
        else:
            int_data += chr(ord(data[i]) - 128)
            break
    for i in int_data[::-1]:
        digit = ord(i)
        for j in range(0,7): # only 7 lower bits from each byte!
            if digit&2**j > 0:
                bits.append(1)
            else:
                bits.append(0)
    for i in range(0, len(bits)):
        value += bits[i]*2**i
    return value, data[len(int_data):]

def get_SignedInt(data):
    value = 0
    bits = []
    int_data = ''
    if ord(data[0]) == 128:
        return 0, data[1:]
    for i in range(0, len(data)):
        if ord(data[i]) < 128:
            int_data += data[i]
        else:
            int_data += chr(ord(data[i]) - 128)
            break
    for i in int_data[::-1]:
        digit = ord(i)
        for j in range(0,7): # only 7 lower bits from each byte!
            if digit&2**j > 0:
                bits.append(1)
            else:
                bits.append(0)
    for i in range(0, len(bits)):
        value += bits[i]*2**i
    if(value & 0x80000000):
        value = -0x100000000 + value
        return value, data[len(int_data):]
    return 0, data[len(int_data):]

def get_decimal(data):
    value = 0
    int_mantissa = ''
    # first: mantissa
    for i in range(0, len(data)):
        if ord(data[i]) < 128:
            int_mantissa += data[i]
        else:
            int_mantissa += chr(ord(data[i]) - 128)
            break
    data = data[i:]
    int_data = ''
    # second: base
    for j in range(i, len(data)):
        if ord(data[j]) < 128:
            int_data += data[j]
        else:
            int_data += chr(ord(data[j]) - 128)
            break
    # :-) let's assume that int_mantissa is ALWAYS one byte since 10**63 or 10**-63 is quite enough:
    if ord(int_mantissa) > 63:
        int_mantissa = chr(ord(int_mantissa) - 64)
        minus = -1
    else:
        minus = 1
    # convert 7 bit bytes into one integer
    bits = []
    for i in int_data[::-1]:
        digit = ord(i)
        for k in range(0,7): # only 7 lower bits from each byte!
            if digit&2**k > 0:
                bits.append(1)
            else:
                bits.append(0)
    for i in range(0, len(bits)):
        value += bits[i]*2**i
    # finally:
    value = value*10**(ord(int_mantissa)*minus)
    return value, data[j:]

def get_sequence(tpl_id, data_rest, Config, id):
    ''' processes the sequence part of the msg '''
    # first, extract 268 - how many submessages
    # then loop it like parse_data()
    ret_value = []
    value, data_rest = get_uInt(data_rest) # field 268
    ret_value.append(value)
    print('[sequence] seq msg num:', value)
    for seq_id in Config[tpl_id][id].keys():
        if seq_id == 'type' or seq_id == 'name':
            continue
        elif 'constant' in Config[tpl_id][id][seq_id].keys():
            value = Config[tpl_id][id][seq_id]['constant']
        elif   Config[tpl_id][id][seq_id]['type'] == 'string': # ascii string
            value, data_rest = get_string(data_rest)
        elif Config[tpl_id][id][seq_id]['type'] == 'ByteVector': # unicode string
            value, data_rest = get_ByteVector(data_rest)
        elif Config[tpl_id][id][seq_id]['type'] == 'uInt32' or Config[tpl_id][id][seq_id]['type'] == 'length':
            value, data_rest = get_uInt(data_rest)
        elif Config[tpl_id][id][seq_id]['type'] == 'uInt64':
            value, data_rest = get_uInt(data_rest)
        elif Config[tpl_id][id][seq_id]['type'] == 'int32':
            value, data_rest = get_SignedInt(data_rest)
        elif Config[tpl_id][id][seq_id]['type'] == 'decimal':
            value, data_rest = get_decimal(data_rest)
        print('[sequence] id:', seq_id, 'name:', Config[tpl_id][id]['name'], 'value:', value)
        ret_value.append(value)
    return ret_value, data_rest

def parse_data( tpl_id, data, Config ):
    ''' parses fast data and returns a human readable string '''
    parsed_data = ''
    if tpl_id in Config.keys():
        data_rest = data
        for id in Config[tpl_id].keys():
            if 'constant' in Config[tpl_id][id].keys():
                value = Config[tpl_id][id]['constant']
            elif Config[tpl_id][id]['type'] == 'string':
                value, data_rest = get_string(data_rest)
            elif Config[tpl_id][id]['type'] == 'ByteVector':
                value, data_rest = get_ByteVector(data_rest)
            elif Config[tpl_id][id]['type'] == 'uInt32' or Config[tpl_id][id]['type'] == 'length':
                value, data_rest = get_uInt(data_rest)
            elif Config[tpl_id][id]['type'] == 'uInt64':
                value, data_rest = get_uInt(data_rest)
            elif Config[tpl_id][id]['type'] == 'int32':
                value, data_rest = get_uInt(data_rest)
            elif Config[tpl_id][id]['type'] == 'int64':
                value, data_rest = get_uInt(data_rest)
            elif Config[tpl_id][id]['type'] == 'decimal':
                value, data_rest = get_decimal(data_rest)
            elif Config[tpl_id][id]['type'] == 'sequence':
                # something is wrong here. Cannot figure out how the fields are filled in sequences.
                value = ''
                for c in data_rest:
                    value = value + '%02x ' % ord(c)
                data_rest = ''
                #value, data_rest = get_sequence(tpl_id, data_rest, Config, id)
            parsed_data += '%s=%s|' % (id, value)
    else:
        parsed_data = 'unknown template: %s' % tpl_id
    return parsed_data

def parse_config( file, udp, tcp ):
    ''' loads streams configuration. One stream per script, please '''
    DOMTree = xml.dom.minidom.parse(file)
    cfg = DOMTree.documentElement

    udp = []
    tcp = []
    if cfg.hasAttribute('environment'):
        connections = cfg.getElementsByTagName('connection')
        if connections:
            for connection in connections:
                row = {}
                row['feedName']  = connection.getAttribute('id').strip()
                row['feedLabel'] = connection.getElementsByTagName('type').item(0).getAttribute('feed-type').strip()
                row['protocol']  = connection.getElementsByTagName('protocol').item(0).firstChild.nodeValue

                if 'TCP' in row['protocol'].upper():
                    row['src-ip'] = ''
                    row['port']   = connection.getElementsByTagName('port').item(0).firstChild.nodeValue
                    # get first IP
                    row['ip']     = connection.getElementsByTagName('ip').item(0).firstChild.nodeValue
                    tcp.append( row )

                    row2 = copy.deepcopy(row)
                    # get second IP
                    row2['ip']    = connection.getElementsByTagName('ip').item(1).firstChild.nodeValue
                    tcp.append( row2 )
                    continue

                row['feedType'] = ''
                row['feedId']   = connection.getElementsByTagName('feed').item(0).getAttribute('id').strip()
                row['src-ip']   = connection.getElementsByTagName('feed').item(0).getElementsByTagName('src-ip').item(0).firstChild.nodeValue
                row['ip']       = connection.getElementsByTagName('feed').item(0).getElementsByTagName('ip').item(0).firstChild.nodeValue
                row['port']     = connection.getElementsByTagName('feed').item(0).getElementsByTagName('port').item(0).firstChild.nodeValue
                udp.append( row )

                row2 = copy.deepcopy( row )
                row2['feedType'] = ''
                row2['feedId']   = connection.getElementsByTagName('feed').item(1).getAttribute('id').strip()
                row2['src-ip']   = connection.getElementsByTagName('feed').item(1).getElementsByTagName('src-ip').item(0).firstChild.nodeValue
                row2['ip']       = connection.getElementsByTagName('feed').item(1).getElementsByTagName('ip').item(0).firstChild.nodeValue
                row2['port']     = connection.getElementsByTagName('feed').item(1).getElementsByTagName('port').item(0).firstChild.nodeValue
                udp.append( row2 )

        return udp, tcp
    else:
        print('UNKNOWN config')
        return [], []

def parse_template(xmlfile):
    ''' loads xml and returns a parsed templates config '''
    DOMTree = xml.dom.minidom.parse(xmlfile)
    Template = DOMTree.documentElement
    T = {}
    for i in Template.getElementsByTagName('template'):
        if i.hasAttribute('id'):
            T[i.getAttribute('id').encode('ascii','ignore')] = OrderedDict({'template': i})

    for t in T.keys():
        for i in T[t]['template'].childNodes:
            if i.nodeName == '#text':
                continue
            if i.nodeName == 'sequence':
                id = 'sequence'
            else:
                # FIX field ID
                id = i.getAttribute('id').encode('ascii', 'ignore')
            T[t][id] = OrderedDict()
            # FIX field type: uInt, Int, Decimal, string, ByteVector (UTF string)
            # Int/uInt may be nullable when optional
            T[t][id]['type'] = i.nodeName.encode('ascii', 'ignore')
            for j in i.childNodes:
                if j.nodeName == 'constant':
                    T[t][id]['constant'] = j.attributes.item(0).value.encode('ascii', 'ignore')
            if i.attributes:
                for j in range(0, i.attributes.length):
                    T[t][id][i.attributes.item(j).name.encode('ascii', 'ignore')] = i.attributes.item(j).value.encode('ascii', 'ignore')
            if i.nodeName == 'sequence':
                for j in i.childNodes:
                    if j.attributes:
                        seq_id = j.getAttribute('id').encode('ascii', 'ignore')
                        T[t][id][seq_id] = OrderedDict()
                        T[t][id][seq_id]['type'] = j.nodeName.encode('ascii', 'ignore')
                        for k in range(0, j.attributes.length):
                            T[t][id][seq_id][j.attributes.item(k).name.encode('ascii', 'ignore')] = j.attributes.item(k).value.encode('ascii', 'ignore')
        del T[t]['template']
    return T

def create_ssm_listener( src, grp, port ):
    imr = (socket.inet_pton(socket.AF_INET, grp) +
                 socket.inet_pton(socket.AF_INET, '0.0.0.0') +
                 socket.inet_pton(socket.AF_INET, src))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # Buffer size
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16777216 )
    # SSM option
    s.setsockopt(socket.SOL_IP, socket.IP_ADD_SOURCE_MEMBERSHIP, imr)
    # allows reuse address
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #allows reuse port (multiple listeners for one groupe simultaneously)
    if hasattr(socket, 'SO_REUSEPORT'):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind((grp, int(port)))
    return s

def clearScreen():
    print chr(27)+'[2J'+chr(27)+'[;H',

def main():
    os.chdir(os.path.dirname(os.path.realpath(sys.argv[0])))

    if len(sys.argv) == 1:
        print('')
        print('Usage: fast-data.py <configfilename> [--log]')
        print('')
        sys.exit(0)

    udp = []
    tcp = []
    Config = {}

    udp,tcp = parse_config( sys.argv[1], udp, tcp )
    Config  = parse_template( 'FIX50SP2-2017-Mar.xml' )

    sockets = []
    l_feeds = {}    #listened feeds

    if not hasattr(socket, 'IP_MULTICAST_TTL'):
        setattr(socket, 'IP_MULTICAST_TTL', 33)
    if not hasattr(socket, 'IP_ADD_SOURCE_MEMBERSHIP'):
        setattr(socket, 'IP_ADD_SOURCE_MEMBERSHIP', 39)

    # start listening
    curt = time.time()
    for feed in udp:
        print('Subscribing to :',feed['src-ip'], feed['ip'], int(feed['port']))
        s = create_ssm_listener( feed['src-ip'], feed['ip'], int(feed['port']) )
        sockets.append(s)
        l_port = int(feed['port'])
        l_feeds[l_port] = feed
        l_feeds[l_port]['pkts']     = 0
        l_feeds[l_port]['bytes']    = 0
        l_feeds[l_port]['lastseq']  = 0
        l_feeds[l_port]['lasttime'] = curt
        l_feeds[l_port]['loss']     = 0

    starttime = time.time()
    last_shown_time = 0
    empty = []
    fo = 0

    WRITE_LOG = False
    if len(sys.argv) > 2:
        if sys.argv[2] == '--log':
            WRITE_LOG = True
            for l_port in l_feeds:
                l_feeds[l_port]['logFile'] = open(l_feeds[l_port]['feedLabel']+'_'+l_feeds[l_port]['feedId']+'.log', 'wt')
            gap_f = open('gaps.log', 'wt')

    # main loop
    while True:
        readable, writable, exceptional = select.select(sockets, empty, empty)
        curt = time.time()

        for s in readable:
            feed_data = s.recvfrom(2048)
            feed_port = s.getsockname()[1]
            timestamp = datetime.now()

            if curt - starttime < 1:
                continue

            # get sequence
            seq = 0
            seq = unpack('<L', feed_data[0][0:4])[0]
            # seq logging:
            if WRITE_LOG:
                pmap = feed_data[0][4]
                # actually in my feed there are 0x10 or 0x13 in the first byte of the template value, feed_data[0][5]
                # but my template numbers are built as if there is 0x09. So it's hardcoded here. Needs to be clarified.
                template_id = str(unpack('>H',chr(9) + feed_data[0][6])[0])
                data = feed_data[0][7:]
                decoded_fast_msg = parse_data( template_id, data, Config )
                log_seq(l_feeds[feed_port]['logFile'],
                        str(timestamp),
                        seq,
                        len(feed_data[0]),
                        decoded_fast_msg)
            # sequence analysis
            if l_feeds[feed_port]['pkts'] == 0:
                l_feeds[feed_port]['lastseq'] = seq
            if seq > (l_feeds[feed_port]['lastseq']+1):
                l_feeds[feed_port]['loss'] += (seq-l_feeds[feed_port]['lastseq']-1)
                # gap logging:
                if WRITE_LOG:
                    log_gap(gap_f,
                            ' '.join([l_feeds[feed_port]['feedName'], \
                                      l_feeds[feed_port]['feedLabel'], \
                                      l_feeds[feed_port]['feedId']]), \
                                      timestamp, seq, seq - l_feeds[feed_port]['lastseq'])

            l_feeds[feed_port]['lastseq']  = seq
            l_feeds[feed_port]['pkts']    += 1
            l_feeds[feed_port]['bytes']   += len(feed_data[0])
            l_feeds[feed_port]['lasttime'] = time.time()


        if time.time()-last_shown_time > 0.2:
            clearScreen()
            print '%-15s|%-16s|%-50s|%7s|%10s|%7s|%10s' % ('Source','Group','Label','Packets','Bytes','Loss','SecondsAgo')
            for l in sorted(l_feeds.keys()):
                st = '%-16s|%-16s|%-50s|%7d|%10d|%7d|%10d\n' % (l_feeds[l]['src-ip'],l_feeds[l]['ip'],l_feeds[l]['feedName']+' '+l_feeds[l]['feedLabel']+l_feeds[l]['feedId'],l_feeds[l]['pkts'],l_feeds[l]['bytes'],l_feeds[l]['loss'],(curt-l_feeds[l]['lasttime']))
                print st,

            # renew counters at 05:00 every day
            if time.gmtime(last_shown_time).tm_hour==4 and time.gmtime(curt).tm_hour==5:
                for l in l_feeds.keys():
                    l_feeds[l]['pkts']     = 0
                    l_feeds[l]['bytes']    = 0
                    l_feeds[l]['lasttime'] = curt
                    l_feeds[l]['loss']     = 0

            last_shown_time = curt

    for s in sockets:
        s.close()

if __name__ == '__main__':
    main()
