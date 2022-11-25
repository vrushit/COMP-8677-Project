#!/usr/bin/python

import kernel
import module
import netfilter
import netfilter_ipv4
import ip
import tcp
import udp
import if_ether
import inet

hook1 = netfilter.nf_hook_ops()
hook2 = netfilter.nf_hook_ops()


def blockUDP(skb, state):  # skb parameter is a socket buffer and it will contain the data for the packet being processed, state is a structure containing info about the current state of the network stack.
    # First we get the IP header and UDP header from the socket buffer.
    iph = ip_hdr(skb)
    udph = udp_hdr(skb)

    # then set the port to 53 and the IP address to 8.8.8.8. Then IP address is converted from dotted decimal to 32-bit binary.
    port = 53
    ip = "8.8.8.8"
    ip_addr = inet.in4_pton(ip, -1, (u8 * )&amp
                            ip_addr, '\0', NULL)

    # if its a udp packet, then check if dest & port match what is being blocked, we drop the packet
    if iph.protocol == IPPROTO_UDP:
        if iph.daddr == ip_addr and ntohs(udph.dest) == port:
            kernel.printk(KERN_WARNING "*** Dropping %pI4 (UDP), port %d\n", & amp
                          (iph.daddr), port)
            return NF_DROP
    # otherwise we accept it
    return NF_ACCEPT


def printInfo(skb, state):
    iph = ip_hdr(skb)

    # we set the hook variable to the name of the hook that is currently being processed.
    hook = None
    if state.hook == NF_INET_LOCAL_IN:
        hook = "LOCAL_IN"
    elif state.hook == NF_INET_LOCAL_OUT:
        hook = "LOCAL_OUT"
    elif state.hook == NF_INET_PRE_ROUTING:
        hook = "PRE_ROUTING"
    elif state.hook == NF_INET_POST_ROUTING:
        hook = "POST_ROUTING"
    elif state.hook == NF_INET_FORWARD:
        hook = "FORWARD"
    else:
        hook = "IMPOSSIBLE"

    # we set the protocol variable to the name of the protocol that is being used
    protocol = None
    if iph.protocol == IPPROTO_UDP:
        protocol = "UDP"
    elif iph.protocol == IPPROTO_TCP:
        protocol = "TCP"
    elif iph.protocol == IPPROTO_ICMP:
        protocol = "ICMP"
    else:
        protocol = "OTHER"

    # then print the hook and protocol variables. as well as the source and destination IP addresses.
    kernel.printk(KERN_INFO "*** %s\n", hook)
    kernel.printk(KERN_INFO " %pI4 -&gt; %pI4 (%s)\n", & amp
                  (iph.saddr), & amp
                  (iph.daddr), protocol)

    return NF_ACCEPT

# now we register the two hooks


def registerFilter():
    kernel.printk(KERN_INFO "Registering filters.\n")

    # print info about the packets that are being processed.
    hook1.hook = printInfo
    hook1.hooknum = NF_INET_LOCAL_OUT
    hook1.pf = PF_INET
    hook1.priority = NF_IP_PRI_FIRST
    netfilter.nf_register_net_hook(kernel.init_net, hook1)

    # block UDP traffic to a specific IP address and port.
    hook2.hook = blockUDP
    hook2.hooknum = NF_INET_POST_ROUTING
    hook2.pf = PF_INET
    hook2.priority = NF_IP_PRI_FIRST
    netfilter.nf_register_net_hook(kernel.init_net, hook2)

    return 0

# remove the two hooks


def removeFilter():
    kernel.printk(KERN_INFO "The filters are being removed.\n")
    netfilter.nf_unregister_net_hook(kernel.init_net, hook1)
    netfilter.nf_unregister_net_hook(kernel.init_net, hook2)


# The module_init() and module_exit() functions are used to tell the kernel when to load and unload the module.
# The MODULE_LICENSE() macro is used to set the license for the module.
module.module_init(registerFilter)
module.module_exit(removeFilter)
module.MODULE_LICENSE("GPL")
