#!/usr/bin/python3
#
# netflow.py
#
# Decodes netflow messages

from dumper import dump
import asyncio
import struct
import ipaddress


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


def unpack(data):
    return struct.unpack('!', data)

class NetflowRecord(object):
    def __init__(self):
        self.data = []
        self.addr = None

    def __getitem__(self, item):
        return self.data[item]

    def __setitem__(self, item, value):
        self.data[item] = value

    def decode_record(self, data, addr):
        pass


class NetflowRecordV9(NetflowRecord):
    templates = {}

    def __init__(self):
        self.data = [None for x in range(0, 128)]
        self.addr = None

    def __getattr__(self, item):
        if item not in NETFLOW_V9:
            raise KeyError("'%s' not found" % item)
        return self.data[NETFLOW_V9[item]]

    def __setattr__(self, item, value):
        if item not in NETFLOW_V9:
            raise KeyError("'%s' not found" % item)
        self.data[NETFLOW_V9[item]] = value

    @staticmethod
    def decode(self, data, addr):
        records = []
        version = unpack(data[0:2])
        if version != 9:
            return []
        fs_count = unpack(data[2:4])
        seq = unpack(data[12:16])
        src_id = unpack(data[18:20])
        data = data[20:]
        for i in range(0, fs_count):
            flow_set = unpack(data[0:2])
            len_fs = unpack(data[2:4]) + 4
            data_fs = data[4:len_fs]
            data = data[len_fs:]
            if flow_set == 0:
                NetflowRecordV9.decode_templates(data_fs, addr)
            else:
                if (addr[0] not in NetflowRecordV9.templates or
                        flow_set not in NetflowRecordV9.templates[addr[0]]):
                    print("Template %s:%d not configured yet" % (addr[0], flow_set))
                    return []
                new_recs = NetflowRecordV9.decode_records(data_fs, addr, flow_set)
                records.extend(new_recs)
        return records

    @staticmethod
    def decode_templates(data, addr):
        while len(data) > 0:
            template_id = unpack(data[0:2])
            field_ct = unpack(data[2:4])
            field_list = []
            data = data[4:]
            for i in range(0, field_ct):
                field_def = tuple(unpack(data[0:2]), unpack(data[2:4]))
                field_list.append(field_def)
                data = data[4:]
            if addr[0] not in NetflowRecordV9.templates:
                NetflowRecordV9.templates[addr[0]] = {}
            NetflowRecordV9.templates[addr[0]][template_id] = (tuple(f[0], f[1]) for f in field_list)

    @staticmethod
    def decode_records(data, addr, flow_set):
        records = []
        template = NetflowRecordV9.templates[addr[0]][flow_set]
        rec_len = 0
        for t_rec in template:
            rec_len += t_rec[1]
        while len(data) >= rec_len:
            record = NetflowRecordV9()
            record.addr = addr
            for t_rec in template:
                field_len = t_rec[1]
                value = data[:field_len]
                data = data[field_len:]
                record[t_rec[0]] = value
        return records


class NetflowProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        print("connected to Netflow socket")

    def datagram_received(self, data, addr):
        version = unpack(data[0:2])
        records = []
        if version == 9:
            try:
                records = NetflowRecordV9.decode(data)
                print(dump(records))
            except:
                pass
        else:
            print("Unsupported Netflow version %d" % version)


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

