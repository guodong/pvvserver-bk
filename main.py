import socket
import json
import sys
import netifaces
import time

BUF_SIZE = 4096
PORT = 9999


class Node:
    def __init__(self):
        ifs = netifaces.interfaces()
        self.name = ifs[1].split('-')[0][1:]
        with open('topo.json', 'r') as f:
            data = f.read()
            topo = json.loads(data)
            self.topo = topo

            for node in topo['nodes']:
                if node['name'] == self.name:
                    self.rules = node['rules']
                    self.build_space()
                    # print self.rules

    def get_node_by_ip(self, ip):
        for node in self.topo['nodes']:
            if node['ip'] == ip:
                return node
        return None

    def start_server(self):
        ip_port = ('0.0.0.0', PORT)
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(ip_port)
        while True:
            data, client = server.recvfrom(BUF_SIZE)
            print 'starttime: %d' % int(time.time() * 1000000)
            print('recv: ', len(data), client[0], data)
            msg = json.loads(data)
            result = self.cal_pm(msg['space'], self.get_node_by_ip(client[0])['name'])
            if result is not None:
                msg_to_send = {
                    'protocol': 'p1',
                    'property': 'reachable',
                    'space': result
                }
                self.flood(json.dumps(msg_to_send), client[0])
            print 'endtime: %d' % int(time.time() * 1000000)

    def get_node_by_name(self, name):
        for node in self.topo['nodes']:
            if node['name'] == name:
                return node
        return None

    def get_neighbor_ips(self):
        ips = []
        for link in self.topo['links']:
            if link['src'] == self.name:
                ips.append(self.get_node_by_name(link['dst'])['ip'])
            elif link['dst'] == self.name:
                ips.append(self.get_node_by_name(link['src'])['ip'])

        return ips

    def flood(self, msg, except_ip = None):
        neighbor_ips = self.get_neighbor_ips()
        if except_ip is not None:
            neighbor_ips.remove(except_ip)

        for neighbor in neighbor_ips:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.sendto(msg, (neighbor, PORT))

    def gen_bits(self, size):
        bits = ''
        for i in range(0, size):
            bits += '*'
        return bits

    # build space bits from rules. eg. nw_src=2,nw_dst=3 => ...**10**...**11**...
    def build_space(self):
        header_map = {
            "dl_dst": (0, 48),
            "dl_src": (1, 48),
            "dl_type": (2, 16),
            "ip_version": (3, 4),
            "ihl": (4, 4),
            "diffserv": (5, 8),
            "total_length": (6, 16),
            "identification": (7, 16),
            "flags": (8, 3),
            "frag": (9, 13),
            "ttl": (10, 8),
            "protocol": (11, 8),
            "checksum": (12, 16),
            "nw_src": (13, 32),
            "nw_dst": (14, 32),
            "tcp_src": (15, 16),
            "tcp_dst": (16, 16),
            "tcp_length": (17, 16),
            "tcp_checksum": (18, 16)
        }
        for rule in self.rules:
            headers = [
                self.gen_bits(48),  # dl_dst
                self.gen_bits(48),  # dl_src
                self.gen_bits(16),  # dl_type
                self.gen_bits(4),  # ip_version
                self.gen_bits(4),  # ihl
                self.gen_bits(8),  # diffserv
                self.gen_bits(16),  # total_length
                self.gen_bits(16),  # identification
                self.gen_bits(3),  # flags
                self.gen_bits(13),  # frag
                self.gen_bits(8),  # ttl
                self.gen_bits(8),  # protocol
                self.gen_bits(16),  # checksum
                self.gen_bits(32),  # nw_src
                self.gen_bits(32),  # nw_dst
                self.gen_bits(16),  # tcp_src
                self.gen_bits(16),  # tcp_dst
                self.gen_bits(16),  # tcp_length
                self.gen_bits(16)  # tcp_checksum
            ]
            for match in rule['matches']:
                index = header_map[match['field']][0]
                headers[index] = self.intersect(headers[index], match['value'])

            rule['space'] = ''.join(headers)

    @staticmethod
    def intersect(space1, space2):
        result_space = ''
        for i in range(0, len(space1)):
            if space1[i] == space2[i]:
                result_space += space1[i]
            elif ord(space1[i]) + ord(space2[i]) == 97:  # 1 0 or 0 1
                return None
            elif space1[i] == '*':
                result_space += space2[i]
            else:
                result_space += space1[i]

        return result_space

    def cal_pm(self, space, nexthop):
        forward_space = None
        for rule in self.rules:
            if rule['actions']['nexthop'] == nexthop:
                forward_space = self.intersect(rule['space'], space)
                break

        print forward_space
        return forward_space

    def get_space(self, nexthop):
        for rule in self.rules:
            if rule['actions']['nexthop'] == nexthop:
                return rule['space']

        return None

    def init(self):
        print 'starttime: %d' % int(time.time() * 1000000)
        headers = [
            self.gen_bits(48),  # dl_dst
            self.gen_bits(48),  # dl_src
            self.gen_bits(16),  # dl_type
            self.gen_bits(4),  # ip_version
            self.gen_bits(4),  # ihl
            self.gen_bits(8),  # diffserv
            self.gen_bits(16),  # total_length
            self.gen_bits(16),  # identification
            self.gen_bits(3),  # flags
            self.gen_bits(13),  # frag
            self.gen_bits(8),  # ttl
            self.gen_bits(8),  # protocol
            self.gen_bits(16),  # checksum
            self.gen_bits(32),  # nw_src
            self.gen_bits(32),  # nw_dst
            self.gen_bits(16),  # tcp_src
            self.gen_bits(16),  # tcp_dst
            self.gen_bits(16),  # tcp_length
            self.gen_bits(16)  # tcp_checksum
        ]
        msg = {
            'protocol': 'p1',
            'property': 'reachable',
            'space': ''.join(headers)
        }
        self.flood(json.dumps(msg))
        print 'endtime: %d' % int(time.time() * 1000000)


if __name__ == '__main__':
    node = Node()
    if len(sys.argv) > 1:
        node.init()
    else:
        node.start_server()