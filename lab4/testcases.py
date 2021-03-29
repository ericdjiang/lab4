#!/usr/bin/python2

"""
Start up a Simple topology for CS144
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.util import quietRun
from mininet.moduledeps import pathCheck
import time
from sys import exit
import os.path
import json
from subprocess import Popen, STDOUT, PIPE
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('-t', metavar='test', type=int, default=None, help='test cases')
parser.add_argument('-d', metavar='debug', type=int, default=0, help='debug')
args = parser.parse_args()

IPBASE = '10.3.0.0/16'
ROOTIP = '10.3.0.100/16'
IPCONFIG_FILE = './IP_CONFIG'
IP_SETTING={}

class CS144Topo( Topo ):
    "CS 144 Lab 3 Topology"
    
    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )
        server1 = self.addHost( 'server1' )
        server2 = self.addHost( 'server2' )
        router = self.addSwitch( 'sw0' , protocols = ["OpenFlow10"])
        client = self.addHost('client')
        for h in server1, server2, client:
            self.addLink( h, router )


class CS144Controller( Controller ):
    "Controller for CS144 Multiple IP Bridge"

    def __init__( self, name, inNamespace=False, command='controller',
                 cargs='-v ptcp:%d', cdir=None, ip="127.0.0.1",
                 port=6633, **params ):
        """command: controller command name
           cargs: controller command arguments
           cdir: director to cd to before running controller
           ip: IP address for controller
           port: port for controller to listen at
           params: other params passed to Node.__init__()"""
        Controller.__init__( self, name, ip=ip, port=port, **params)

    def start( self ):
        """Start <controller> <args> on controller.
            Log to /tmp/cN.log"""
        pathCheck( self.command )
        cout = '/tmp/' + self.name + '.log'
        if self.cdir is not None:
            self.cmd( 'cd ' + self.cdir )
        self.cmd( self.command, self.cargs % self.port, '>&', cout, '&' )

    def stop( self ):
        "Stop controller."
        self.cmd( 'kill %' + self.command )
        self.terminate()


def startsshd( host ):
    "Start sshd on host"
    stopsshd()
    info( '*** Starting sshd\n' )
    name, intf, ip = host.name, host.defaultIntf(), host.IP()
    banner = '/tmp/%s.banner' % name
    host.cmd( 'echo "Welcome to %s at %s" >  %s' % ( name, ip, banner ) )
    host.cmd( '/usr/sbin/sshd -o "Banner %s"' % banner, '-o "UseDNS no"' )
    info( '***', host.name, 'is running sshd on', intf, 'at', ip, '\n' )


def stopsshd():
    "Stop *all* sshd processes with a custom banner"
    info( '*** Shutting down stale sshd/Banner processes ',
          quietRun( "pkill -9 -f Banner" ), '\n' )


def starthttp( host ):
    "Start simple Python web server on hosts"
    info( '*** Starting SimpleHTTPServer on host', host, '\n' )
    host.cmd( 'cd ./http_%s/; nohup python2.7 ./webserver.py &' % (host.name) )


def stophttp():
    "Stop simple Python web servers"
    info( '*** Shutting down stale SimpleHTTPServers', 
          quietRun( "pkill -9 -f SimpleHTTPServer" ), '\n' )    
    info( '*** Shutting down stale webservers', 
          quietRun( "pkill -9 -f webserver.py" ), '\n' )    
    
def set_default_route(host):
    info('*** setting default gateway of host %s\n' % host.name)
    if(host.name == 'server1'):
        routerip = IP_SETTING['sw0-eth1']
    elif(host.name == 'server2'):
        routerip = IP_SETTING['sw0-eth2']
    elif(host.name == 'client'):
        routerip = IP_SETTING['sw0-eth3']
    print host.name, routerip
    host.cmd('route add %s/32 dev %s-eth0' % (routerip, host.name))
    host.cmd('route add default gw %s dev %s-eth0' % (routerip, host.name))
    ips = IP_SETTING[host.name].split(".") 
    host.cmd('route del -net %s.0.0.0/8 dev %s-eth0' % (ips[0], host.name))

def get_ip_setting():
    try:
        with open(IPCONFIG_FILE, 'r') as f:
            for line in f:
                if( len(line.split()) == 0):
                  break
                name, ip = line.split()
                print name, ip
                IP_SETTING[name] = ip
            info( '*** Successfully loaded ip settings for hosts\n %s\n' % IP_SETTING)
    except EnvironmentError:
        exit("Couldn't load config file for ip addresses, check whether %s exists" % IPCONFIG_FILE)


def send_command_and_check(node, node_name, command, expected_result):
    info(">>>>>>>>>>>>>>>>Sending command: %s %s<<<<<<<<<<<<<<<\n" % (node_name.lower(), command))
    return_info = node.cmd(command)
    info(return_info+"\n")
    return_info = return_info.lower()
    if expected_result in return_info:
        return True
    else:
        return False

def check_traceroute(node, node_name, ip, hop):
    info(">>>>>>>>>>>>>>>>Sending command: %s traceroute %s<<<<<<<<<<<<<<<\n" % (node_name.lower(), ip))
    return_info = node.cmd("traceroute %s" % ip)
    info(return_info+"\n")

    return_info = str.strip(return_info)
    listx = return_info.split("\n")
    count = 0
    for i in range(1, len(listx)):
        item = str.strip(listx[i]).split(" ")
        if item[0].isdigit():
            count = max(count, int(item[0]))
    if count == hop:
        return True
    else:
        return False
        
def output_info(information):
    info("-------------%s-------------\n" % information)

def check_correctness(passed, testcase, testcases_scores, records):
    max_score = testcases_scores[testcase-1]
    if passed:
        score = max_score
        output_info("Test Case %d: Passed (%d/%d)" % (testcase, score, max_score))
        records[testcase-1] = 1
    else:
        score = 0
        output_info("Test Case %d: Failed (0/%d)" % (testcase, max_score))
        records[testcase-1] = 0
    return score

def run_tests(net):
    ip_lists = {
        '10.0.1.100': 'client',
        '10.0.1.1': 'eth3',
        '192.168.2.1': 'eth1',
        '192.168.2.2': 'server1',
        '172.64.3.10': 'server2',
        '172.64.3.1': 'eth2'
    }
    infile = open("./HWINFOS_TEMP", "r")
    hwinfos = json.loads(infile.read())
    infile.close()

    records = [-1]*11
    testcases_scores = [5, 2, 2, 2, 2, 1, 1, 1, 3, 3, 3]

    client = [net.get('client'), '10.0.1.100']
    server1 = [net.get('server1'), '192.168.2.2']
    server2 = [net.get('server2'), '172.64.3.10']
    node_infos = [client, server1, server2]
    node_names = ['Client', 'Server1', 'Server2']

    if args.d == 1:
        client[0].cmd("tshark -i client-eth0 -w ./pcap_files/client.pcap &")
        server2[0].cmd("tshark -i server2-eth0 -w ../pcap_files/server2.pcap &")
        server1[0].cmd("tshark -i server1-eth0 -w ../pcap_files/server1.pcap &")
    total_scores = 0

    if args.t is None:
        testcases = range(1, 12)
        max_score = 25
    else:
        testcases = [args.t]
        max_score = testcases_scores[args.t-1]
    
    # testcase 1 - arping
    testcase = 1
    if testcase in testcases:
        output_info("Test Case 1: ARP test Start")
        passed = True
        parameters = [
            [client[0], 'Client', '10.0.1.1', hwinfos['eth3']],
            [server2[0], 'Server2', '172.64.3.1', hwinfos['eth2']],
            [server1[0], 'Server1', '192.168.2.1', hwinfos['eth1']]
        ]
        for parameter in parameters:
            if not send_command_and_check(parameter[0], parameter[1], "arping -c 3 %s" % parameter[2], parameter[3]):
                passed = False
                break
        total_scores += check_correctness(passed, testcase, testcases_scores, records)

    for testcase in (2, 3, 4):
        if testcase in testcases:
            node_info = node_infos[testcase-2]
            node_name = node_names[testcase-2]
            output_info("Test Case %d: %s pings all interfaces of router Start" % (testcase, node_name))
            passed = True

            node_ip = node_info[1]
            node = node_info[0]
            for ip in ip_lists:
                if 'eth' not in ip_lists[ip]:
                    continue
                if not send_command_and_check(node, node_name, "ping -c 3 -t 64 %s" % ip, "3 received"):
                    passed = False
                    break
            
            total_scores += check_correctness(passed, testcase, testcases_scores, records)

    testcase = 5
    if testcase in testcases:
        output_info("Test Case %d: Port Unreachable" % testcase)
        node_info = node_infos[0]
        node_name = node_names[0]
        node_ip = node_info[1]
        node = node_info[0]
        passed = True

        for ip in ip_lists:
            if 'eth' not in ip_lists[ip]:
                continue
            if not send_command_and_check(node, node_name, "wget -T 10 --tries=3 http://%s" % ip, "connection refused"):
                passed = False
                break
        total_scores += check_correctness(passed, testcase, testcases_scores, records)
    
    testcase = 6
    if testcase in testcases:
        ips = ['192.168.2.2', '172.64.3.10']
        output_info("Test Case %d: Time to live exceeded" % testcase)
        passed = True

        for ip in ips:
            if not send_command_and_check(node, node_name, "ping -c 3 -t 1 %s" % ip, "time to live exceeded"):
                passed = False
                break
        total_scores += check_correctness(passed, testcase, testcases_scores, records)

    testcase = 7
    if testcase in testcases:
        output_info("Test Case %d: Destination Net Unreachable" % testcase)
        wrong_ips = ['10.0.1.2', '192.168.2.3', '172.64.3.9']
        passed = True

        for ip in wrong_ips:
            if not send_command_and_check(node, node_name, "ping -c 3 -t 64 %s" % ip, "destination net unreachable"):
                passed = False
                break
        total_scores += check_correctness(passed, testcase, testcases_scores, records)

    testcase = 8
    if testcase in testcases:
        output_info("Test Case %d: Handle TTL correctly" % testcase)
        passed = True

        for ip in ip_lists:
            if 'eth' not in ip_lists[ip]:
                continue
            if not send_command_and_check(node, node_name, "ping -c 3 -t 1 %s" % ip, "3 received"):
                passed = False
                break
        total_scores += check_correctness(passed, testcase, testcases_scores, records)
    
    testcase = 9
    if testcase in testcases:
        output_info("Test Case %d: Ping All Hosts" % testcase)
        passed = True
        for i in range(len(node_infos)):
            node_info = node_infos[i]
            node_name = node_names[i]
            node_ip = node_info[1]
            node = node_info[0]
            node_ip = node_info[1]
            node = node_info[0]
            for ip in ip_lists:
                if 'eth' in ip_lists[ip] or ip == node_ip:
                    continue
                if not send_command_and_check(node, node_name, "ping -c 3 -t 64 %s" % ip, "3 received"):
                    passed = False
                    break
            if not passed:
                break
        total_scores += check_correctness(passed, testcase, testcases_scores, records)

    testcase = 10
    if testcase in testcases:
        output_info("Test Case %d: Wget the Web Server" % testcase)
        node_info = node_infos[0]
        node_name = node_names[0]
        node_ip = node_info[1]
        node = node_info[0]
        passed = True

        for ip in ip_lists:
            if 'server' not in ip_lists[ip]:
                continue
            if not send_command_and_check(node, node_name, "wget -T 10 --tries=3 http://%s" % ip, "saved"):
                passed = False
                break
        total_scores += check_correctness(passed, testcase, testcases_scores, records)

    testcase = 11
    if testcase in testcases:
        output_info("Test Case %d: Traceroute all the interfaces" % testcase)
        passed = True
        for i in range(len(node_infos)):
            node_info = node_infos[i]
            node_name = node_names[i]
            node_ip = node_info[1]
            node = node_info[0]
            node_ip = node_info[1]
            node = node_info[0]
            for ip in ip_lists:
                if ip == node_ip:
                    continue
                if 'eth' in ip_lists[ip]:
                    hop = 1
                else:
                    hop = 2
                if not check_traceroute(node, node_name, ip, hop):
                    passed = False
                    break
            if not passed:
                break
        total_scores += check_correctness(passed, testcase, testcases_scores, records)

    output_info("All Test Cases Finished")
    output_info("Total Score: %d/%s" % (total_scores, max_score))
    for i in range(len(records)):
        if records[i] != -1:
            if records[i] == 1:
                passed = "PASSED"
            else:
                passed = "FAILED"
            info("Test Case:%d %s\n" % (i+1, passed))

    output = open("lab4_results.json", "w")
    res = {
        "score": total_scores,
        "stdout_visibility": "visible",
    }
    output.write(json.dumps(res))
    os.system("rm -rf index.html*")
    output.close()

    if args.d == 1:
        os.system("chmod 777 ./pcap_files/*")

def cs144net():
    stophttp()
    "Create a simple network for cs144"
    get_ip_setting()
    topo = CS144Topo()
    info( '*** Creating network\n' )
    net = Mininet( topo=topo, controller=RemoteController, ipBase=IPBASE )
    net.start()
    server1, server2, client, router = net.get( 'server1', 'server2', 'client', 'sw0')
    s1intf = server1.defaultIntf()
    s1intf.setIP('%s/8' % IP_SETTING['server1'])
    s2intf = server2.defaultIntf()
    s2intf.setIP('%s/8' % IP_SETTING['server2'])
    clintf = client.defaultIntf()
    clintf.setIP('%s/8' % IP_SETTING['client'])
    for host in server1, server2, client:
        set_default_route(host)
    starthttp( server1 )
    starthttp( server2 )

    time.sleep(10)
    run_tests(net)
    stophttp()
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    cs144net()
