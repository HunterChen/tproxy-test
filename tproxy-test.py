#!/usr/bin/python
import os, sys, socket, traceback, time

# global params
proxy_ip4 = '10.30.1.128'
proxy_port = 50080
target_ip4 = '5.6.7.8'
target_port = 80
zero_ip4 = '0.0.0.0'

#
proxy_ip6 = 'dead:1::2'
target_ip6 = 'dead:2::1'
zero_ip6 = '::'


def connect_agent():
    from Agent import TestAgentStub
    if os.system("rsync -a Agent root@%s:" % proxy_ip4) != 0:
        raise Exception, "Error syncing agent"
    return TestAgentStub.TestAgentStub("ssh root@%s Agent/test-agent.py" % (proxy_ip4,), 'tproxy')


# IPv4


tproxy_rule_only_ipv4_sockets = (
# sockets that are irrelevant to our redirection, their existance should not
# cause any connections to be established
 (
  # irrelevant, because of port number
  (zero_ip4, 5678, True), (proxy_ip4, 5678),
  # redirect should override even those listeners that are bound explicitly
  (zero_ip4, 80, True), (proxy_ip4, 80), (target_ip4, 80), 
  (target_ip4, 50080, True)
 ), 
# sockets that should match, in reverse-preference order, e.g. the
# connection should always establish to the last one
 ((zero_ip4, 50080, True), (proxy_ip4, 50080))
)

tproxy_plus_socket_rules_ipv4_sockets = (
# sockets that are irrelevant to our redirection, their existance should not
# cause any connections to be established
 (
  # irrelevant, because of port number
  (zero_ip4, 5678, True), (proxy_ip4, 5678),
  # redirect should override even those listeners that are bound explicitly
  (zero_ip4, 80, True), (proxy_ip4, 80),
  (target_ip4, 50080, True)
 ), 
# sockets that should match, in reverse-preference order, e.g. the
# connection should always establish to the last one
 (
  # because of the socket match, we get a connection on the target address
  # this is when the proxy opens a dynamic listener
  (target_ip4, 80, True), 
  (zero_ip4, 50080, True), (proxy_ip4, 50080)
 )
)

# ipv6

tproxy_rule_only_ipv6_sockets = (
# sockets that are irrelevant to our redirection, their existance should not
# cause any connections to be established
 (
  # irrelevant, because of port number
  (zero_ip6, 5678, True), (proxy_ip6, 5678),
  # redirect should override even those listeners that are bound explicitly
  (zero_ip6, 80, True), (proxy_ip6, 80), (target_ip6, 80), 
  (target_ip6, 50080, True)
 ), 
# sockets that should match, in reverse-preference order, e.g. the
# connection should always establish to the last one
 ((zero_ip6, 50080, True), (proxy_ip6, 50080))
)

tproxy_plus_socket_rules_ipv6_sockets = (
# sockets that are irrelevant to our redirection, their existance should not
# cause any connections to be established
 (
  # irrelevant, because of port number
  (zero_ip6, 5678, True), (proxy_ip6, 5678),
  # redirect should override even those listeners that are bound explicitly
  (zero_ip6, 80, True), (proxy_ip6, 80),
  (target_ip6, 50080, True)
 ), 
# sockets that should match, in reverse-preference order, e.g. the
# connection should always establish to the last one
 (
  # because of the socket match, we get a connection on the target address
  # this is when the proxy opens a dynamic listener
  (target_ip6, 80, True), 
  (zero_ip6, 50080, True), (proxy_ip6, 50080)
 )
)

def debug(*args):
    global debug_flag
    
    if debug_flag:
        for arg in args:
            print arg,
        print

tproxy_sockets = {
  (socket.AF_INET, False): tproxy_rule_only_ipv4_sockets,
  (socket.AF_INET, True): tproxy_plus_socket_rules_ipv4_sockets,
  (socket.AF_INET6, False): tproxy_rule_only_ipv6_sockets, 
  (socket.AF_INET6, True): tproxy_plus_socket_rules_ipv6_sockets,
}

def load_iptables(a, family=socket.AF_INET, socket_type=socket.SOCK_STREAM, socket_rule=False, explicit_on_ip=False):

    header = """
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p icmpv6 -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -m mark --mark 1/1 -j ACCEPT
-A INPUT -j LOG --log-prefix "PF/INPUT: DROP "
-A INPUT -j DROP
-A FORWARD -j LOG --log-prefix "PF/FORWARD: DROP "
-A FORWARD -j DROP
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DIVERT - [0:0]
"""
    subst = {}
    
    if socket_type == socket.SOCK_STREAM:
        subst['proto'] = 'tcp'
    else:
        subst['proto'] = 'udp'
        
    subst['target_port'] = target_port
    subst['proxy_port'] = proxy_port
    if family == socket.AF_INET:
        subst['proxy_ip'] = proxy_ip4
    else:
        subst['proxy_ip'] = proxy_ip6
    rules = header
    if socket_rule:
        rules += """-A PREROUTING -m socket --transparent -j DIVERT\n"""

    if explicit_on_ip:
        rules += """
-A PREROUTING -p %(proto)s -m %(proto)s --dport %(target_port)d -j TPROXY --on-port %(proxy_port)d --on-ip %(proxy_ip)s --tproxy-mark 0x1/0x1""" % subst
    else:
        rules += """
-A PREROUTING -p %(proto)s -m %(proto)s --dport %(target_port)d -j TPROXY --on-port %(proxy_port)d --tproxy-mark 0x1/0x1""" % subst

    rules += """
-A DIVERT -j MARK --set-xmark 0x1/0x1
-A DIVERT -j ACCEPT 
COMMIT
""" % subst

    debug(rules)
    a.iptables_restore(family, rules)

def open_listener(a, family, socket_type, addr):
    s = a.socket(family, socket_type)
    s.bind(addr[0:2])
    if socket_type == socket.SOCK_STREAM:
        s.listen(255)
    
    return s


def run_sockets(a, family=socket.AF_INET, socket_type=socket.SOCK_STREAM, socket_rule=False, explicit_on_ip=False, sockets=()):

    skip_irrelevant = False
    load_iptables(a, family, socket_type, socket_rule, explicit_on_ip)
    
    open_sockets = []
    
    relevant = False
    success = True
    for addrs in sockets:
        for addr in addrs:
        
            debug("### Opening listener %s" % (addr,))
        
            l_sock = open_listener(a, family, socket_type, addr)
            open_sockets.append(l_sock)
            
            c_sock = socket.socket(family, socket_type)
            c_sock.settimeout(2)
            
            if family == socket.AF_INET:
                target_ip = target_ip4
            else:
                target_ip = target_ip6
            
            debug("### Connecting to %s" % ((target_ip, target_port),))
            try:
                if relevant or not skip_irrelevant:
                    c_sock.connect((target_ip, target_port))
                    if socket_type == socket.SOCK_DGRAM:
                        c_sock.send("almafa")
                    debug("### Connected to %s" % ((target_ip, target_port),))
                else:
                    debug("### Skipped connection to %s" % ((target_ip, target_port),))
                    c_sock = None
            except socket.error:
                # connection failed
                c_sock = None
                debug("### Connection failed to %s" % ((target_ip, target_port),))
            
            if relevant or not skip_irrelevant:
                debug("### Waiting for connection %s" % (addr,))
                (r, w, x) = a.select(open_sockets, [], [], timeout=2)
            else:
                (r, w, x) = ([], [], [])
                
            if socket_type == socket.SOCK_DGRAM and (len(r) + len(w) + len(x)) == 0:
                debug("### Datagram read failed on %s" % (addr,))
                c_sock = None
            
            if socket_type == socket.SOCK_STREAM and c_sock != None and (len(r) + len(w) + len(x)) != 1:
                print r, w, x
                print "FAIL: connected and select returned no connection?"
                success = False
            elif c_sock == None:
                # timed out
                if not relevant:
                    print "PASS: %s, didn't get a connection on irrelevant address" % (addr,)
                else:
                    print "FAIL: %s, didn't get a connection but we should have" % (addr,)
                    success = False
            else:
                if len(r) != 1:
                    print "FAIL: uhh, we got a connection on multiple fds?"
                    success = False
                else:
                    if not relevant:
                        print "FAIL: %s, we got a connection but we shouldn't have" % (addr,)
                        success = False
                    else:
                        if r[0] == l_sock:
                            print "PASS: %s, we got a connection as we deserved" % (addr,)
                            if socket_type == socket.SOCK_STREAM:
                                a_sock = l_sock.accept()
                        else:
                            print "FAIL: %s, we got the connection on the wrong listener" % (addr,)
                            success = False
            if len(addr) == 3:
                
                # we close the socket if it refers to the zero address as
                # otherwise we'd have a bind conflict, as the upcoming bind
                # address will contain a more specific version of this
                # listener
                l_sock = None
                open_sockets = open_sockets[:-1]
            r, w, x = ([], [], [])
        relevant = True
    return success

def run_testcases(a, all_sockets):
    
    global_success = True
    for family in (socket.AF_INET6, socket.AF_INET):
        for socket_type in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            for socket_rule in (False, True):
                for explicit_on_ip in (False, True):
                    if not run_sockets(a, family, socket_type, socket_rule, explicit_on_ip, all_sockets[(family, socket_rule)]):
                        global_success = False

    if global_success:
        print "PASS: everything is fine"
    else:
        print "FAIL: some tests failed"
    
# testcases
#   TPROXY rule only, no "socket" match
#      80 -> 50080 redirection rule
#           TCP listener on redirect-ip:50080, connection establishes
#           TCP listener on redirect-ip:80, connection does not establish
#           TCP listener on redirect-ip:80 & redirect-ip:50080, connection goes to the latter
#           TCP listener on 0.0.0.0:50080, connection establishes
#           TCP listener on 0.0.0.0:50080 & redirect-ip:50080, connection establishes to the latter
#           TCP listener on 0.0.0.0:80, connection does not establish
#           TCP listener on 0.0.0.0:80 & 0.0.0.0:50080, connection goes to the latter
#           TCP listener on target-ip:80, connection does not establish
#           TCP listener on target-ip:50080, connection does not establish

def main():
    global debug_flag
    
    debug_flag = False
    try:
        a = connect_agent()
        #print a.iptables_save(family=socket.AF_INET)
        run_testcases(a, tproxy_sockets)
        a.quit()
        return 0
    except Exception, e:
        traceback.print_exc()
        print e
        return 1
    
sys.exit(main())

