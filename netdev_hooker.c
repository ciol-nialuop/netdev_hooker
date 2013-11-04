#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/ip.h>

static char *interface;
module_param(interface, charp, S_IRUGO);

static struct net_device_ops *local_netdev_ops;
static struct net_device_ops *hooked_netdev_ops;
static struct net_device *hooked_netdev;

 /* xmit_filters */
static void mac_filter(struct sk_buff *skb)
{
	char *mac_header = skb_mac_header(skb);

	if (mac_header < skb->head)
		return;

	if (mac_header + ETH_HLEN > skb->data)
		return;
}

/* TODO IPV6 */
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
	
static void network_filter(struct sk_buff *skb)
{
	char *network_header = skb_network_header(skb);
	struct iphdr *iph = (struct iphdr *)network_header;

	if (network_header < skb->head)
		return;

	printk(KERN_DEBUG "Packet src = %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
	printk(KERN_DEBUG "Packet dst = %d.%d.%d.%d\n\n", NIPQUAD(iph->daddr));
}

static netdev_tx_t
local_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	mac_filter(skb);
	network_filter(skb);
	return hooked_netdev_ops->ndo_start_xmit(skb, ndev);
}

static struct net_device * retrieve_netdev(const char *name)
{
	struct net_device *ndev;

	read_lock(&dev_base_lock);
	ndev = first_net_device(&init_net);
	while (ndev) {
		if (!strcmp(name, ndev->name))
			break;
		ndev = next_net_device(ndev);
	}
	read_unlock(&dev_base_lock);

	return ndev;
}

static int hook_netdev(struct net_device *ndev)
{
	/* TODO: locking */
	if (ndev->netdev_ops) {
		local_netdev_ops = kmalloc(sizeof(struct net_device_ops), GFP_KERNEL);
		if (local_netdev_ops) {
			hooked_netdev = ndev;
			memcpy(local_netdev_ops, ndev->netdev_ops, sizeof(struct net_device_ops));
			hooked_netdev_ops = ndev->netdev_ops;
			local_netdev_ops->ndo_start_xmit = local_start_xmit;
			ndev->netdev_ops = local_netdev_ops;
		} else {
			return -ENOMEM;
		}
	}

	return 0;
}

static int unhook_netdev(struct net_device *ndev)
{
	/* TODO: locking */
	if (ndev->netdev_ops && hooked_netdev_ops) {
		local_netdev_ops = kmalloc(sizeof(struct net_device_ops), GFP_KERNEL);
		ndev->netdev_ops = hooked_netdev_ops;
		kfree(local_netdev_ops);
	}

	return 0;
}

static int __init netdev_hooker_load(void)
{
	struct net_device *ndev;

	if (interface) {
		ndev = retrieve_netdev(interface);
		if (ndev)
			hook_netdev(ndev);
	}

	return 0;
}
module_init(netdev_hooker_load);

static void __exit netdev_hooker_exit(void)
{
	unhook_netdev(hooked_netdev);
}
module_exit(netdev_hooker_exit);
