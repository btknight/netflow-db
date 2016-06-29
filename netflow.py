#!/usr/bin/python3
#
# netflow.py
#
# Decodes netflow messages

from dumper import dump
import asyncio
import struct
import ipaddress
import datetime


NETFLOW_REC_V5 = {
    1: 'ipv4_src_addr',
    2: 'ipv4_dst_addr',
    3: 'ipv4_next_hop',
    4: 'input_snmp',
    5: 'output_snmp',
    6: 'in_pkts',
    7: 'in_bytes',
    8: 'first_switched',
    9: 'last_switched',
    10: 'l4_src_port',
    11: 'l4_dst_port',
    12: 'tcp_flags',
    13: 'protocol',
    14: 'src_tos',
    15: 'src_as',
    16: 'dst_as',
    17: 'src_mask',
    18: 'dst_mask',
}
NETFLOW_REC_V9 = {
    1: 'in_bytes',
    2: 'in_pkts',
    3: 'flows',
    4: 'protocol',
    5: 'src_tos',
    6: 'tcp_flags',
    7: 'l4_src_port',
    8: 'ipv4_src_addr',
    9: 'src_mask',
    10: 'input_snmp',
    11: 'l4_dst_port',
    12: 'ipv4_dst_addr',
    13: 'dst_mask',
    14: 'output_snmp',
    15: 'ipv4_next_hop',
    16: 'src_as',
    17: 'dst_as',
    18: 'bgp_ipv4_next_hop',
    19: 'mul_dst_pkts',
    20: 'mul_dst_bytes',
    21: 'last_switched',
    22: 'first_switched',
    23: 'out_bytes',
    24: 'out_pkts',
    25: 'min_pkt_lngth',
    26: 'max_pkt_lngth',
    27: 'ipv6_src_addr',
    28: 'ipv6_dst_addr',
    29: 'ipv6_src_mask',
    30: 'ipv6_dst_mask',
    31: 'ipv6_flow_label',
    32: 'icmp_type',
    33: 'mul_igmp_type',
    34: 'sampling_interval',
    35: 'sampling_algorithm',
    36: 'flow_active_timeout',
    37: 'flow_inactive_timeout',
    38: 'engine_type',
    39: 'engine_id',
    40: 'total_bytes_exp',
    41: 'total_pkts_exp',
    42: 'total_flows_exp',
    44: 'ipv4_src_prefix',
    45: 'ipv4_dst_prefix',
    46: 'mpls_top_label_type',
    47: 'mpls_top_label_ip_addr',
    48: 'flow_sampler_id',
    49: 'flow_sampler_mode',
    50: 'flow_sampler_random_interval',
    52: 'min_ttl',
    53: 'max_ttl',
    54: 'ipv4_ident',
    55: 'dst_tos',
    56: 'in_src_mac',
    57: 'out_dst_mac',
    58: 'src_vlan',
    59: 'dst_vlan',
    60: 'ip_protocol_version',
    61: 'direction',
    62: 'ipv6_next_hop',
    63: 'bpg_ipv6_next_hop',
    64: 'ipv6_option_headers',
    70: 'mpls_label_1',
    71: 'mpls_label_2',
    72: 'mpls_label_3',
    73: 'mpls_label_4',
    74: 'mpls_label_5',
    75: 'mpls_label_6',
    76: 'mpls_label_7',
    77: 'mpls_label_8',
    78: 'mpls_label_9',
    79: 'mpls_label_10',
    80: 'in_dst_mac',
    81: 'out_src_mac',
    82: 'if_name',
    83: 'if_desc',
    84: 'sampler_name',
    85: 'in_ permanent _bytes',
    86: 'in_ permanent _pkts',
    88: 'fragment_offset',
    89: 'forwarding status',
    90: 'mpls pal rd',
    91: 'mpls prefix len',
    92: 'src traffic index',
    93: 'dst traffic index',
    94: 'application description',
    95: 'application tag',
    96: 'application name',
    98: 'postipdiffservcodepoint',
    99: 'replication factor',
    100: 'deprecated',
    102: 'layer2packetsectionoffset',
    103: 'layer2packetsectionsize',
    104: 'layer2packetsectiondata',
}
STRUCT_LEN = {
    2: "H",
    4: "I",
    8: "Q"
}


def unpack(data):
    ln = len(data)
    if ln == 0:
        raise Exception("data is length 0")
    fmt = 'B'
    if ln in STRUCT_LEN:
        fmt = STRUCT_LEN[ln]
    retval = struct.unpack('>%s' % fmt, data)
    if len(retval) == 1:
        retval = retval[0]
    return retval


class NetflowRecord(object):
    def __init__(self):
        self.data = {}
        self['version'] = 0
        self['addr'] = None
        self['src_id'] = None
        self['time_offset'] = None

    def __getitem__(self, item):
        return self.data[item]

    def __setitem__(self, item, value):
        self.data[item] = value

    @staticmethod
    def decode(data, addr):
        return []


class NetflowRecordV5(NetflowRecord):
    next_seq = None
    time_offset = {}
    template = {
        (1, 0, 4),
        (2, 4, 8),
        (3, 8, 12),
        (4, 12, 14),
        (5, 14, 16),
        (6, 16, 20),
        (7, 20, 24),
        (8, 24, 28),
        (9, 28, 32),
        (10, 32, 34),
        (11, 34, 36),
        (12, 37, 38),
        (13, 38, 39),
        (14, 39, 40),
        (15, 40, 42),
        (16, 42, 44),
        (17, 44, 45),
        (18, 45, 46),
    }

    def __init__(self):
        super().__init__()
        self['version'] = 5

    @staticmethod
    def decode(data, addr):
        records = []
        pkt_data = {}
        version = unpack(data[0:2])
        if version != 5:
            return []
        rc_count = unpack(data[2:4])
        pkt_data['sysuptime'] = unpack(data[4:8])
        pkt_data['unix_date'] = unpack(data[8:12])
        seq = unpack(data[16:20])
        pkt_data['src_id'] = unpack(data[20:22])
        data = data[20:]
        if NetflowRecordV5.next_seq is not None and seq != NetflowRecordV5.next_seq:
            print("Lost Netflow packets detected: expected %d, got %d" % (NetflowRecordV5.next_seq, seq))
        NetflowRecordV5.next_seq = seq + rc_count
        NetflowRecordV5.time_offset[addr[0]] = pkt_data['unix_date'] - int(pkt_data['sysuptime'] / 1000)
        rc_found = 0
        while rc_found < rc_count:
            rc_data = data[:48]
            data = data[48:]
            new_rec = NetflowRecordV5.decode_record(rc_data, addr, pkt_data)
            records.append(new_rec)
            rc_found += 1
        return records

    @staticmethod
    def decode_record(data, addr, pkt_data):
        record = NetflowRecordV5()
        record['src_id'] = pkt_data['src_id']
        record['addr'] = addr
        record['time_offset'] = NetflowRecordV5.time_offset[addr[0]]
        for (a, i, j) in NetflowRecordV5.template:
            rec_name = NETFLOW_REC_V5[a]
            record[rec_name] = unpack(data[i:j])
        return record


class NetflowRecordV9(NetflowRecord):
    templates = {}
    seq = None
    time_offset = {}

    def __init__(self):
        super().__init__()
        self['version'] = 9

    @staticmethod
    def decode(data, addr):
        records = []
        pkt_data = {}
        version = unpack(data[0:2])
        if version != 9:
            return []
        fs_count = unpack(data[2:4])
        pkt_data['sysuptime'] = unpack(data[4:8])
        pkt_data['unix_date'] = unpack(data[8:12])
        seq = unpack(data[12:16])
        pkt_data['src_id'] = unpack(data[18:20])
        data = data[20:]
        if NetflowRecordV9.seq is not None and seq != NetflowRecordV9.seq + 1:
            print("Lost Netflow packets detected: expected %d, got %d" % (NetflowRecordV9.seq + 1, seq))
        NetflowRecordV9.seq = seq
        NetflowRecordV9.time_offset[addr[0]] = pkt_data['unix_date'] - int(pkt_data['sysuptime'] / 1000)
        fs_found = 0
        while fs_found < fs_count:
            template = unpack(data[0:2])
            len_fs = unpack(data[2:4])
            data_fs = data[4:len_fs]
            data = data[len_fs:]
            if template == 0:
                fs_found += NetflowRecordV9.decode_templates(data_fs, addr)
            else:
                if (addr[0] not in NetflowRecordV9.templates or
                        template not in NetflowRecordV9.templates[addr[0]]):
                    print("Template %s:%d not configured yet" % (addr[0], template))
                    return []
                new_recs = NetflowRecordV9.decode_records(data_fs, addr, pkt_data, template)
                records.extend(new_recs)
                fs_found += len(new_recs)
        return records

    @staticmethod
    def decode_templates(data, addr):
        fs_found = 0
        while len(data) > 0:
            template_id = unpack(data[0:2])
            field_ct = unpack(data[2:4])
            field_list = []
            data = data[4:]
            for i in range(0, field_ct):
                field_type = unpack(data[0:2])
                field_len = unpack(data[2:4])
                field_def = (field_type, field_len)
                field_list.append(field_def)
                data = data[4:]
            if addr[0] not in NetflowRecordV9.templates:
                NetflowRecordV9.templates[addr[0]] = {}
            NetflowRecordV9.templates[addr[0]][template_id] = tuple([(f[0], f[1]) for f in field_list])
            print("Template: rec'd %d from %s" % (template_id, addr[0]))
            fs_found += 1
        return fs_found

    @staticmethod
    def decode_records(data, addr, pkt_data, template):
        records = []
        template = NetflowRecordV9.templates[addr[0]][template]
        rec_len = 0
        for t_rec in template:
            rec_len += t_rec[1]
        while len(data) >= rec_len:
            record = NetflowRecordV9()
            record['src_id'] = pkt_data['src_id']
            record['addr'] = addr
            record['time_offset'] = NetflowRecordV9.time_offset[addr[0]]
            for t_rec in template:
                if t_rec[0] in NETFLOW_REC_V9:
                    field_name = NETFLOW_REC_V9[t_rec[0]]
                else:
                    field_name = str(t_rec[0])
                field_len = t_rec[1]
                value = unpack(data[:field_len])
                data = data[field_len:]
                record[field_name] = value
            records.append(record)
        return records


class NetflowProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        print("connected to Netflow socket")

    def datagram_received(self, data, addr):
        version = unpack(data[0:2])
        records = []
        if version == 9:
            records = NetflowRecordV9.decode(data, addr)
        elif version == 5:
            records = NetflowRecordV5.decode(data, addr)
            #try:
            #    records = NetflowRecordV9.decode(data, addr)
            #    print(dump(records))
            #except:
            #    pass
        else:
            print("Unsupported Netflow version %d from %s:%s" % (version, addr[0], addr[1]))
        if len(records) > 0:
            print(dump(records))


loop = asyncio.get_event_loop()
print("Starting UDP server")
listen = loop.create_datagram_endpoint(NetflowProtocol, local_addr=('0.0.0.0', 5000))
transport, protocol = loop.run_until_complete(listen)

try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

transport.close()
loop.close()

