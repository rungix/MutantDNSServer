import socket
from twisted.internet import reactor, defer
from twisted.names import client, dns, error, server
from twisted.internet.address import IPv4Address

import colorama 
colorama.init(autoreset=True)

import pygeoip
import json
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__file__)

import re
import os
import argparse


def print_red(msg):
    print(colorama.Fore.RED + msg)

def print_blue(msg):
    print(colorama.Fore.BLUE+ msg)

def print_green(msg):
    print(colorama.Fore.GREEN+ msg)

null_record = {
    'city': None,
    'region_code': None,
    'country_name': None,
    'postal_code': None,
    'country_code': None,
    'country_code3': None,
    'continent': None,
    'metro_code': None,
    'area_code': None,
    'time_zone': None,
    'dma_code': None,
    'latitude': None,
    'longitude': None,
}

as_re = re.compile(r'AS(?P<num>\d+)(?: (?P<name>.+))?')
default_format_string = '"%ip", "%cn", "%lat","%lon","%as_num","%as_name"'


class GeoIP():
    def __init__(self, data_dir="./geoip_data/"):
        self.geo_city = pygeoip.GeoIP(os.path.join(data_dir, 'GeoLiteCity.dat'))
        self.geo_asn = pygeoip.GeoIP(os.path.join(data_dir,
        'GeoIPASNum.dat'))

    def __ip_valid(self, ip):
        ip = ip.strip()
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            return ip
        else:
            return None
    
    def ip_2_city(self, ip):
        ip = self.__ip_valid(ip)
        if ip:
            ip_data = self.geo_city.record_by_addr(ip)
            if ip_data == None:
                ip_data = null_record

            ip_asn = self.geo_asn.asn_by_addr(ip)
            if ip_asn != None:
                (as_num, as_name) = as_re.match(ip_asn).groups()
            else:
                (as_num, as_name) = (0, 'None') 

        ip_data['ip'] = ip
        ip_data['as_num'] = as_num
        ip_data['as_name'] = as_name        
        return ip_data
        



class DynamicDNSServerFactory(server.DNSServerFactory):

    def handleQuery(self, message, protocol, address):
        if protocol.transport.socket.type == socket.SOCK_STREAM:
            self.peer_address = protocol.transport.getPeer()
        elif protocol.transport.socketType == socket.SOCK_DGRAM:
            self.peer_address = IPv4Address('UDP', *address)
        else:
            print_red("Unexpected socket type %r" % protocol.transport.socket.type)

        logger.debug("Got message from : %r" % self.peer_address)

        # Make peer_address available to resolvers that support that attribute
        for resolver in self.resolver.resolvers:
            if hasattr(resolver, 'peer_address'):
                resolver.peer_address = self.peer_address

        return server.DNSServerFactory.handleQuery(self, message, protocol, address)

class DynamicResolver(object):
    """
    A resolver which calculates the answers to certain queries based on the
    query type and name.
    """
    _pattern = (b'origin', b'www', b'ns1', b'ns2')
    _ns_pattern = (b'ns1', b'ns2')

    # _network = b'172.0.2'


    def __init__(self, ip_json, ns_ip):
        self._peer_address = None
        self._geoip = GeoIP()
        self._IPs = json.loads(open(ip_json).read())
        self._ns_ip = ns_ip

    @property
    def peer_address(self):
        return self._peer_address

    @peer_address.setter
    def peer_address(self, value):
        self._peer_address = value

    def _dynamicResponseRequired(self, query):
        """
        Check the query to determine if a dynamic response is required.
        """
        if query.type == dns.A:
            labels = query.name.name.split(b'.')
            if labels[0].lower().startswith(self._pattern):
                return True

        return False


    def _doDynamicResponse(self, query):
        """
        Calculate the response to a query.
        """
        reply_ip = self._ns_ip
        query_ip = self._geoip.ip_2_city(self.peer_address.host)
        print(json.dumps(query_ip, indent=4, sort_keys=True))

        print_blue("Receiving >>>>>> ....")
        print_green(str(query_ip))
        print_blue("Replying with <<<<<< ....")

        labels = query.name.name.split(b'.')
        if labels[0].lower().startswith(self._ns_pattern):
            print_red('NS: ' + str(reply_ip))
        else:
            for ip in self._IPs:
                if query_ip['country_name'] != ip['country_name']:
                    reply_ip = ip['ip']
                    self._IPs.remove(ip)                    
                    break

        print_red(reply_ip)
        name = query.name.name
#        labels = name.split(b'.')
#        parts = labels[0].split(self._pattern)
#        lastOctet = bytes(parts[1])
        answer = dns.RRHeader(
            name=name,
            payload=dns.Record_A(address=reply_ip))
#  payload=dns.Record_A(address=b'%s.%s' % (self._network, lastOctet)))
        answers = [answer]
        authority = []
        additional = []
        return answers, authority, additional



    def query(self, query, timeout=None):
        """
        Check if the query should be answered dynamically, otherwise dispatch to
        the fallback resolver.
        """
        logger.info("\n\n----------------------------")
        logger.info("DynamicResolver.query(): {} ask {}, type {}".format(self.peer_address, query.name.name, query.type))
 
        if self._dynamicResponseRequired(query):
            return defer.succeed(self._doDynamicResponse(query))
        else:
            return defer.fail(error.DomainError())

        
class ClientAddressDNSDatagramProtocol(dns.DNSDatagramProtocol):
    def datagramReceived(self, datagram, addr):
        logger.debug("Datagram {} from {}".format(datagram, addr))
        return dns.DNSDatagramProtocol.datagramReceived(self, datagram, addr)





def main(args):
    """
    Run the server.
    """

    factory = DynamicDNSServerFactory(
        clients=[DynamicResolver(args.ip_json, args.ns_ip)], verbose=1
    )

    protocol = ClientAddressDNSDatagramProtocol(controller=factory)

    reactor.listenUDP(53, protocol)
    reactor.listenTCP(53, factory)

    reactor.run()



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A DNS Server for replying IPs dynamically')
    parser.add_argument('-j', '--json', help='IP info in JSON format.', required='True', dest='ip_json')
    parser.add_argument('-n', '--ns', help='Name Server\'s IP', required='True', dest='ns_ip')
    args = parser.parse_args()
    print(args)
    raise SystemExit(main(args))
