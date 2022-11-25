#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>

// LKM that drops any UDP packet (except for UDP packets that are destined to port 53 — DNS), and accepts any TCP packet. Any other packet will be dropped.

static struct nf_hook_ops first_hook, second_hook; // third_hook, fourth_hook, fifth_hook; // define 2 fork structures

unsigned int blockUDP(struct sk_buff *skb,
                      const struct nf_hook_state *state) // packets are stored in the address pointed by skb
{
   struct iphdr *iph;
   struct udphdr *udph;

   u16 port = 53;           // dns
   char ip[16] = "9.9.9.9"; // quad9 dns server, we can also use google's 8.8.8.8
   u32 ip_addr;

   if (!skb)
      return NF_ACCEPT;

   iph = ip_hdr(skb);
   // Convert the IPv4 address from dotted decimal to 32-bit binary
   in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);

   if (iph->protocol == IPPROTO_UDP)
   {
      udph = udp_hdr(skb);
      if (iph->daddr == ip_addr && ntohs(udph->dest) == port) // if its a match we drop the packet
      {
         printk(KERN_WARNING "*** Dropping %pI4 (UDP), port %d\n", &(iph->daddr), port);
         return NF_DROP;
      }
   }
   return NF_ACCEPT; // otherwise we accept it
}

unsigned int printInfo(struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
   struct iphdr *iph;
   char *hook;
   char *protocol;

   switch (state->hook)
   {
   case NF_INET_LOCAL_IN:
      hook = "LOCAL_IN";
      break;
   case NF_INET_LOCAL_OUT:
      hook = "LOCAL_OUT";
      break;
   case NF_INET_PRE_ROUTING:
      hook = "PRE_ROUTING";
      break;
   case NF_INET_POST_ROUTING:
      hook = "POST_ROUTING";
      break;
   case NF_INET_FORWARD:
      hook = "FORWARD";
      break;
   default:
      hook = "IMPOSSIBLE";
      break;
   }
   printk(KERN_INFO "*** %s\n", hook); // Print out the hook info

   iph = ip_hdr(skb);
   switch (iph->protocol)
   {
   case IPPROTO_UDP:
      protocol = "UDP";
      break;
   case IPPROTO_TCP:
      protocol = "TCP";
      break;
   case IPPROTO_ICMP:
      protocol = "ICMP";
      break;
   default:
      protocol = "OTHER";
      break;
   }
   // Print out the IP addresses and protocol
   printk(KERN_INFO "    %pI4  --> %pI4 (%s)\n",
          &(iph->saddr), &(iph->daddr), protocol); // source address, destination address and protocol will be printed out in the kernel buffer

   return NF_ACCEPT;
}

int registerFilter(void) // module entrance
{
   printk(KERN_INFO "Registering filters.\n"); // register the hook

   /* //NF_INET_PRE_ROUTING
    first_hook.hook = printInfo; // get the print info
    first_hook.hooknum = NF_INET_PRE_ROUTING;
    first_hook.pf = PF_INET;
    first_hook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &first_hook);

    //NF_INET_LOCAL_IN
    second_hook.hook = printInfo; // get the print info
    second_hook.hooknum = NF_INET_LOCAL_IN;
    second_hook.pf = PF_INET;
    second_hook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &second_hook);

    //NF_INET_FORWARD
    third_hook.hook = printInfo; // get the print info
    third_hook.hooknum = NF_INET_FORWARD ;
    third_hook.pf = PF_INET;
    third_hook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &third_hook);

    //NF_INET_LOCAL_OUT
    fourth_hook.hook = printInfo; // get the print info
    fourth_hook.hooknum = NF_INET_LOCAL_OUT;
    fourth_hook.pf = PF_INET;
    fourth_hook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &fourth_hook);

    //NF_INET_POST_ROUTING
    fifth_hook.hook = printInfo; // get the print info
    fifth_hook.hooknum = NF_INET_POST_ROUTING;
    fifth_hook.pf = PF_INET;
    fifth_hook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &fifth_hook);

    return 0; */

   first_hook.hook = printInfo; // get the print info
   first_hook.hooknum = NF_INET_LOCAL_OUT;
   first_hook.pf = PF_INET;
   first_hook.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &first_hook);

   second_hook.hook = blockUDP;
   second_hook.hooknum = NF_INET_POST_ROUTING; // first four lines initializes the fork
   second_hook.pf = PF_INET;
   second_hook.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &second_hook);

   return 0;
}

void removeFilter(void) // module exit
{
   printk(KERN_INFO "The filters are being removed.\n");
   nf_unregister_net_hook(&init_net, &first_hook);
   nf_unregister_net_hook(&init_net, &second_hook);
   // nf_unregister_net_hook(&init_net, &third_hook);
   // nf_unregister_net_hook(&init_net, &fourth_hook);
   // nf_unregister_net_hook(&init_net, &fifth_hook);
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
