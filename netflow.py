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


NETFLOW_V5 = {
    'ipv4_src_addr': 1,
    'ipv4_dst_addr': 2,
    'ipv4_next_hop': 3,
    'input_snmp': 4,
    'output_snmp': 5,
    'in_pkts': 6,
    'in_bytes': 7,
    'first_switched': 8,
    'last_switched': 9,
    'l4_src_port': 10,
    'l4_dst_port': 11,
    'tcp_flags': 12,
    'protocol': 13,
    'src_tos': 14,
    'src_as': 15,
    'dst_as': 16,
    'src_mask': 17,
    'dst_mask': 18,
}
NETFLOW_V9 = {
    'in_bytes': 1,
    'in_pkts': 2,
    'flows': 3,
    'protocol': 4,
    'src_tos': 5,
    'tcp_flags': 6,
    'l4_src_port': 7,
    'ipv4_src_addr': 8,
    'src_mask': 9,
    'input_snmp': 10,
    'l4_dst_port': 11,
    'ipv4_dst_addr': 12,
    'dst_mask': 13,
    'output_snmp': 14,
    'ipv4_next_hop': 15,
    'src_as': 16,
    'dst_as': 17,
    'bgp_ipv4_next_hop': 18,
    'mul_dst_pkts': 19,
    'mul_dst_bytes': 20,
    'last_switched': 21,
    'first_switched': 22,
    'out_bytes': 23,
    'out_pkts': 24,
    'min_pkt_lngth': 25,
    'max_pkt_lngth': 26,
    'ipv6_src_addr': 27,
    'ipv6_dst_addr': 28,
    'ipv6_src_mask': 29,
    'ipv6_dst_mask': 30,
    'ipv6_flow_label': 31,
    'icmp_type': 32,
    'mul_igmp_type': 33,
    'sampling_interval': 34,
    'sampling_algorithm': 35,
    'flow_active_timeout': 36,
    'flow_inactive_timeout': 37,
    'engine_type': 38,
    'engine_id': 39,
    'total_bytes_exp': 40,
    'total_pkts_exp': 41,
    'total_flows_exp': 42,
    'ipv4_src_prefix': 44,
    'ipv4_dst_prefix': 45,
    'mpls_top_label_type': 46,
    'mpls_top_label_ip_addr': 47,
    'flow_sampler_id': 48,
    'flow_sampler_mode': 49,
    'flow_sampler_random_interval': 50,
    'min_ttl': 52,
    'max_ttl': 53,
    'ipv4_ident': 54,
    'dst_tos': 55,
    'in_src_mac': 56,
    'out_dst_mac': 57,
    'src_vlan': 58,
    'dst_vlan': 59,
    'ip_protocol_version': 60,
    'direction': 61,
    'ipv6_next_hop': 62,
    'bgp_ipv6_next_hop': 63,
    'ipv6_option_headers': 64,
    'mpls_label_1': 70,
    'mpls_label_2': 71,
    'mpls_label_3': 72,
    'mpls_label_4': 73,
    'mpls_label_5': 74,
    'mpls_label_6': 75,
    'mpls_label_7': 76,
    'mpls_label_8': 77,
    'mpls_label_9': 78,
    'mpls_label_10': 79,
    'in_dst_mac': 80,
    'out_src_mac': 81,
    'if_name': 82,
    'if_desc': 83,
    'sampler_name': 84,
    'in_permanent_bytes': 85,
    'in_permanent_pkts': 86,
    'fragment_offset': 88,
    'forwarding status': 89,
    'mpls_pal_rd': 90,
    'mpls_prefix_len': 91,
    'src_traffic_index': 92,
    'dst_traffic_index': 93,
    'application_description': 94,
    'application_tag': 95,
    'application_name': 96,
    'postipdiffservcodepoint': 98,
    'replication_factor': 99,
    'layer2packetsectionoffset': 102,
    'layer2packetsectionsize': 103,
    'layer2packetsectiondata': 104
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
        self.data = []
        self.version = 0
        self.addr = None
        self.src_id = None
        self.time_offset = None

    def __getitem__(self, item):
        return self.data[item]

    def __setitem__(self, item, value):
        self.data[item] = value

    @staticmethod
    def decode(data, addr):
        return []


class NetflowRecordV5(NetflowRecord):
    seq = None
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
        self.data = [None for x in range(0, 19)]
        self.version = 5

    def __getitem__(self, item):
        val = None
        if type(item) is int:
            val = item
        elif type(item) is str and item in NETFLOW_V5:
            val = NETFLOW_V5[item]
        else:
            return None
        return self.data[val]

    def __setitem__(self, item, value):
        val = None
        if type(item) is int:
            val = item
        elif type(item) is str and item in NETFLOW_V5:
            val = NETFLOW_V5[item]
        else:
            return None
        self.data[val] = value

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
        if NetflowRecordV5.seq is not None and seq != NetflowRecordV5.seq + rc_count:
            print("Lost Netflow packets detected: at %d, expected %d, got %d" % (NetflowRecordV5.seq, NetflowRecordV5.seq + rc_count, seq))
        NetflowRecordV5.seq = seq
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
        record.src_id = pkt_data['src_id']
        record.addr = addr
        record.time_offset = NetflowRecordV5.time_offset[addr[0]]
        for (a, i, j) in NetflowRecordV5.template:
            record[a] = unpack(data[i:j])
        return record


class NetflowRecordV9(NetflowRecord):
    templates = {}
    seq = None
    time_offset = {}

    def __init__(self):
        self.data = [None for x in range(0, 128)]
        self.version = 9
        self.flow_set = None

    def __getitem__(self, item):
        val = None
        if type(item) is int:
            val = item
        elif type(item) is str and item in NETFLOW_V9:
            val = NETFLOW_V9[item]
        else:
            return None
        return self.data[val]

    def __setitem__(self, item, value):
        val = None
        if type(item) is int:
            val = item
        elif type(item) is str and item in NETFLOW_V9:
            val = NETFLOW_V9[item]
        else:
            return None
        self.data[val] = value

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
            flow_set = unpack(data[0:2])
            len_fs = unpack(data[2:4])
            data_fs = data[4:len_fs]
            data = data[len_fs:]
            if flow_set == 0:
                fs_found += NetflowRecordV9.decode_templates(data_fs, addr)
            else:
                if (addr[0] not in NetflowRecordV9.templates or
                        flow_set not in NetflowRecordV9.templates[addr[0]]):
                    print("Template %s:%d not configured yet" % (addr[0], flow_set))
                    return []
                new_recs = NetflowRecordV9.decode_records(data_fs, addr, pkt_data, flow_set)
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
    def decode_records(data, addr, pkt_data, flow_set):
        records = []
        template = NetflowRecordV9.templates[addr[0]][flow_set]
        rec_len = 0
        for t_rec in template:
            rec_len += t_rec[1]
        while len(data) >= rec_len:
            record = NetflowRecordV9()
            record.flow_set = flow_set
            record.src_id = pkt_data['src_id']
            record.addr = addr
            record.time_offset = NetflowRecordV9.time_offset[addr[0]]
            for t_rec in template:
                field_len = t_rec[1]
                value = unpack(data[:field_len])
                data = data[field_len:]
                record[t_rec[0]] = value
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

