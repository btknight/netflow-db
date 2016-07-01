#!/usr/bin/python3
#
# netflow.py
#
# Decodes netflow messages and stores them in a database
import argparse
import asyncio
import queue
import threading
import struct
import ipaddress
import time
import mysql.connector
import os
#from daemonize import Daemonize
import logging
import signal


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
    102: 'layer2packetsectionoffset',
    103: 'layer2packetsectionsize',
    104: 'layer2packetsectiondata',
}
STRUCT_LEN = {
    1: "B",
    2: "H",
    4: "I",
    8: "Q"
}
ALL_FIELDS = ['version', 'reporter', 'src_id', 'time_offset'] + [r for r in NETFLOW_REC_V9.values()]

verbose = 1

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
        self['reporter'] = None
        self['src_id'] = None
        self['time_offset'] = None

    def __getitem__(self, item):
        return self.data[item]

    def __setitem__(self, item, value):
        self.data[item] = value

    def __iter__(self):
        return self.data.__iter__()

    def keys(self):
        return self.data.keys()

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
        data = data[24:]
        if NetflowRecordV5.next_seq is not None and seq != NetflowRecordV5.next_seq:
            log_msg("NFv5 %s lost Netflow packets detected: expected %d, got %d" % (addr[0],
                    NetflowRecordV5.next_seq, seq), msg_verb=2)
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
        record['reporter'] = int(ipaddress.IPv4Address(addr[0]))
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
            log_msg("NFv9 %s lost Netflow packets detected: expected %d, got %d" % (addr[0],
                    NetflowRecordV9.seq + 1, seq), msg_verb=2)
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
                    log_msg("Template %s:%d not configured yet" % (addr[0], template), msg_verb=2)
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
            log_msg("Template: rec'd %d from %s" % (template_id, addr[0]), msg_verb=2)
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
            record['reporter'] = int(ipaddress.IPv4Address(addr[0]))
            record['time_offset'] = NetflowRecordV9.time_offset[addr[0]]
            for t_rec in template:
                if t_rec[0] in NETFLOW_REC_V9:
                    field_name = NETFLOW_REC_V9[t_rec[0]]
                else:
                    field_name = str(t_rec[0])
                field_len = t_rec[1]
                value = None
                if field_len in STRUCT_LEN:
                    value = unpack(data[:field_len])
                else:
                    value = data[:field_len]
                data = data[field_len:]
                record[field_name] = value
            records.append(record)
        return records


class NetflowProtocol(asyncio.DatagramProtocol):
    db_q = queue.Queue()

    def connection_made(self, transport):
        log_msg("connected to Netflow socket", msg_verb=3)

    def datagram_received(self, data, addr):
        global db_q
        version = unpack(data[0:2])
        records = []
        if version == 9:
            records = NetflowRecordV9.decode(data, addr)
        elif version == 5:
            records = NetflowRecordV5.decode(data, addr)
        else:
            log_msg("Unsupported Netflow version %d from %s:%s" % (version, addr[0], addr[1]), facility=logging.warning)
        if len(records) > 0:
            log_msg("adding %d records to queue" % len(records), msg_verb=3)
        for r in records:
            NetflowProtocol.db_q.put(r)


class DB(threading.Thread):
    def __init__(self, conn_args, queue, shutdown_event):
        self.conn_args = conn_args
        self.queue = queue
        self.shutdown_event = shutdown_event
        super().__init__()
        self.conn = None
        self.connect()
        log_msg("Connected to SQL server %s" % self.conn_args['host'])

    def run(self):
        while not self.shutdown_event.is_set():
            try:
                self.connect()
                self.main_loop()
            except Exception as e:
                log_msg("SQL connection error, attempting reconnect: %s" % str(e), facility=logging.warning)

    def main_loop(self):
        while not self.shutdown_event.is_set():
            while not self.queue.empty() and not self.shutdown_event.is_set():
                c = self.conn.cursor()
                self.output_record(self.queue.get(), c)
                self.conn.commit()
                c.close()
                self.queue.task_done()
            time.sleep(1)
        self.disconnect()

    def output_record(self, record, c):
        column_list = [r for r in ALL_FIELDS if r in record]
        output_list = [str(record[r]) for r in column_list]
        placeholder_list = ["%s" for r in column_list]
        query = "INSERT INTO netflow (" + ", ".join(column_list) + ") VALUES (" + ", ".join(placeholder_list) + ");"
        c.execute(query, output_list)

    def connect(self):
        if self.conn is None or not self.conn.is_connected():
            self.conn = mysql.connector.connect(**self.conn_args)
            self.create_tables()

    def create_tables(self):
        if self.conn is not None:
            query = "show tables;"
            c = self.conn.cursor()
            c.execute(query)
            tables = {r[0] for r in c}
            c.close()
            if 'netflow' not in tables:
                c = self.conn.cursor()
                query = """
                CREATE TABLE netflow (
                    id INT NOT NULL AUTO_INCREMENT
                    , version TINYINT NOT NULL
                    , reporter INT UNSIGNED NOT NULL
                    , src_id SMALLINT UNSIGNED NOT NULL
                    , time_offset INT UNSIGNED NOT NULL
                    , in_bytes BIGINT UNSIGNED
                    , input_snmp INT UNSIGNED
                    , layer2packetsectionoffset INT UNSIGNED
                    , layer2packetsectionsize INT UNSIGNED
                    , layer2packetsectiondata INT UNSIGNED
                    , l4_dst_port SMALLINT UNSIGNED
                    , ipv4_dst_addr INT UNSIGNED
                    , dst_mask TINYINT UNSIGNED
                    , output_snmp INT UNSIGNED
                    , ipv4_next_hop INT UNSIGNED
                    , src_as INT UNSIGNED
                    , dst_as INT UNSIGNED
                    , bgp_ipv4_next_hop INT UNSIGNED
                    , mul_dst_pkts INT UNSIGNED
                    , in_pkts BIGINT UNSIGNED
                    , mul_dst_bytes INT UNSIGNED
                    , last_switched INT UNSIGNED
                    , first_switched INT UNSIGNED
                    , out_bytes INT UNSIGNED
                    , out_pkts INT UNSIGNED
                    , min_pkt_lngth SMALLINT UNSIGNED
                    , max_pkt_lngth SMALLINT UNSIGNED
                    , ipv6_src_addr VARBINARY(16)
                    , ipv6_dst_addr VARBINARY(16)
                    , ipv6_src_mask TINYINT UNSIGNED
                    , flows BIGINT UNSIGNED
                    , ipv6_dst_mask TINYINT UNSIGNED
                    , ipv6_flow_label INT UNSIGNED
                    , icmp_type SMALLINT UNSIGNED
                    , mul_igmp_type TINYINT UNSIGNED
                    , sampling_interval INT UNSIGNED
                    , sampling_algorithm TINYINT UNSIGNED
                    , flow_active_timeout SMALLINT UNSIGNED
                    , flow_inactive_timeout SMALLINT UNSIGNED
                    , engine_type TINYINT UNSIGNED
                    , engine_id TINYINT UNSIGNED
                    , protocol TINYINT UNSIGNED
                    , total_bytes_exp BIGINT UNSIGNED
                    , total_pkts_exp BIGINT UNSIGNED
                    , total_flows_exp BIGINT UNSIGNED
                    , ipv4_src_prefix INT UNSIGNED
                    , ipv4_dst_prefix INT UNSIGNED
                    , mpls_top_label_type TINYINT UNSIGNED
                    , mpls_top_label_ip_addr INT UNSIGNED
                    , flow_sampler_id TINYINT UNSIGNED
                    , flow_sampler_mode TINYINT UNSIGNED
                    , src_tos TINYINT UNSIGNED
                    , flow_sampler_random_interval INT UNSIGNED
                    , min_ttl TINYINT UNSIGNED
                    , max_ttl TINYINT UNSIGNED
                    , ipv4_ident SMALLINT UNSIGNED
                    , dst_tos TINYINT UNSIGNED
                    , in_src_mac BIGINT UNSIGNED
                    , out_dst_mac BIGINT UNSIGNED
                    , src_vlan SMALLINT UNSIGNED
                    , dst_vlan SMALLINT UNSIGNED
                    , tcp_flags TINYINT UNSIGNED
                    , ip_protocol_version TINYINT UNSIGNED
                    , direction TINYINT UNSIGNED
                    , ipv6_next_hop BINARY(16)
                    , bgp_ipv6_next_hop BINARY(16)
                    , ipv6_option_headers INT UNSIGNED
                    , l4_src_port SMALLINT UNSIGNED
                    , mpls_label_1 INT UNSIGNED
                    , mpls_label_2 INT UNSIGNED
                    , mpls_label_3 INT UNSIGNED
                    , mpls_label_4 INT UNSIGNED
                    , mpls_label_5 INT UNSIGNED
                    , mpls_label_6 INT UNSIGNED
                    , mpls_label_7 INT UNSIGNED
                    , mpls_label_8 INT UNSIGNED
                    , mpls_label_9 INT UNSIGNED
                    , mpls_label_10 INT UNSIGNED
                    , ipv4_src_addr INT UNSIGNED
                    , in_dst_mac BIGINT UNSIGNED
                    , out_src_mac BIGINT UNSIGNED
                    , if_name VARBINARY(80)
                    , if_desc VARBINARY(256)
                    , sampler_name VARBINARY(256)
                    , in_permanent_bytes BIGINT UNSIGNED
                    , in_permanent_pkts BIGINT UNSIGNED
                    , fragment_offset SMALLINT UNSIGNED
                    , forwarding_status TINYINT UNSIGNED
                    , src_mask TINYINT UNSIGNED
                    , mpls_pal_rd BIGINT UNSIGNED
                    , mpls_prefix_len TINYINT UNSIGNED
                    , src_traffic_index INT UNSIGNED
                    , dst_traffic_index INT UNSIGNED
                    , application_description VARBINARY(256)
                    , application_tag VARBINARY(256)
                    , application_name VARBINARY(256)
                    , postipdiffservcodepoint TINYINT UNSIGNED
                    , replication_factor INT UNSIGNED
                    , PRIMARY KEY (id)
                    );
                """
                c.execute(query)
                self.conn.commit()
                c.close()
            if 'netflow_v' not in tables:
                c = self.conn.cursor()
                query = """
                    create view netflow_v
                    AS
                    select
                    N.*
                    , INET_NTOA(N.reporter) as reporter_a
                    , INET_NTOA(N.ipv4_src_addr) as ipv4_src_addr_a
                    , INET_NTOA(N.ipv4_dst_addr) as ipv4_dst_addr_a
                    , INET_NTOA(N.ipv4_next_hop) as ipv4_next_hop_a
                    , INET_NTOA(N.bgp_ipv4_next_hop) as bgp_ipv4_next_hop_a
                    , INET_NTOA(N.ipv4_src_prefix) as ipv4_src_prefix_a
                    , INET_NTOA(N.ipv4_dst_prefix) as ipv4_dst_prefix_a
                    , N.src_tos >> 2 as src_dscp
                    , N.dst_tos >> 2 as dst_dscp
                    , from_unixtime(N.first_switched div 1000 + N.time_offset) as first_switched_d
                    , from_unixtime(N.last_switched div 1000 + N.time_offset) as last_switched_d
                    , (N.tcp_flags & 1) AS tcp_flags_fin
                    , (N.tcp_flags & 2) >> 1 AS tcp_flags_syn
                    , (N.tcp_flags & 4) >> 2 AS tcp_flags_rst
                    , (N.tcp_flags & 8) >> 3 AS tcp_flags_psh
                    , (N.tcp_flags & 16) >> 4 AS tcp_flags_ack
                    , (N.tcp_flags & 32) >> 5 AS tcp_flags_urg
                    from netflow as N;
                """
                c.execute(query)
                self.conn.commit()
                c.close()

    def disconnect(self):
        if self.conn is not None:
            self.conn.disconnect()
            self.conn = None


def log_msg(msg, msg_verb=1, facility=logging.info):
    global verbose
    if msg is not None:
        if facility == logging.info and msg_verb <= verbose:
            print(msg)
        facility(msg)


def main(args):
    local_addr = '0.0.0.0'
    loop = asyncio.get_event_loop()
    if os.name == 'posix':
        loop.add_signal_handler(signal.SIGTERM, loop.stop)
    listen = loop.create_datagram_endpoint(NetflowProtocol, local_addr=(local_addr, args.port))
    transport, protocol = loop.run_until_complete(listen)
    log_msg("Started Netflow listener on %s:%d" % (local_addr, args.port))

    db = None
    db_connect = {
        'user': args.dbuser,
        'password': args.dbpassword,
        'host': args.dbhost,
        'database': args.dbname
    }
    db_shutdown = threading.Event()
    try:
        db = DB(conn_args=db_connect, queue=NetflowProtocol.db_q, shutdown_event=db_shutdown)
    except mysql.connector.Error as e:
        log_msg("could not connect to mysql database: %s" % str(e), facility=logging.error)
        if db_connect['password'] is None:
            log_msg("did you forget to specify a database password?", facility=logging.error)
        exit(-1)
    db.start()

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    log_msg("Shutting down", facility=logging.error)
    transport.close()
    loop.close()
    db_shutdown.set()
    db.join(10)

if __name__ == '__main__':
    if os.name == 'nt':
        default_pidfile = r'%TEMP%\netflow.pid'
    elif os.name == 'posix':
        default_pidfile = r'/tmp/netflow.pid'
    else:
        default_pidfile = None
    ap = argparse.ArgumentParser(description="Copy Netflow data to a MySQL database.")
    ap.add_argument('--daemonize', '-d', action='store_true', help="run in background")
    ap.add_argument('--pidfile', type=str, default=default_pidfile, help="location of pid file")
    ap.add_argument('--dbuser', '-U', default="netflow", help="database user")
    ap.add_argument('--dbpassword', '-P', help="database password")
    ap.add_argument('--dbhost', '-H', default="127.0.0.1", help="database host")
    ap.add_argument('--dbname', '-D', default="netflow", help="database name")
    ap.add_argument('port', type=int, help="Netflow UDP listener port")
    ap.add_argument('--verbose', '-v', action='count', default=1, help="Verbosity of console messages")
    ap.add_argument('--quiet', '-q', action='store_true',
                    help="Suppress console messages (only warnings and errors will be shown")

    args = ap.parse_args()

    if args.port < 1 or args.port > 65535:
        ap.exit(-1, "error: port must be 1-65535")

    verbose = args.verbose
    if args.quiet:
        verbose = 0

    #if args.daemonize:
    #    if args.pidfile is None:
    #        raise Exception("Attempted to run as daemon, but pid file was not provided, and cannot determine default location for pidfile")

    #    d = Daemonize(app="netflow", pid=args.pidfile, action=main, args=args)
    #    d.start()
    #    logging.info("netflow started in background")
    #else:
    #    main(args)
    main(args)
