# Configure Kernel Parameters

> **Note**
> Parameters will be automatically configured if `global.auto_config_kernel_parameter` is `true`.

If you set up dae as a router or other intermediate device and bind it to LAN interfaces, you need to adjust some Linux kernel parameters to make everything work fine. By default, the latest Linux distributions have IP Forwarding `disabled`. In the case where we need to up a Linux router/gateway or a VPN server or simply a plain dial-in server, then we need to enable forwarding. Moreover, in order to keep our gateway position and keep correct downstream route table, we should disable `send-redirects`. Do the followings to adjust Linux kernel parameters:

For every LAN interfaces you want to proxy:

```shell
export lan_ifname=docker0

sudo tee /etc/sysctl.d/60-dae-lan-$lan_ifname.conf << EOF
net.ipv4.conf.$lan_ifname.forwarding = 1
net.ipv6.conf.$lan_ifname.forwarding = 1
net.ipv4.conf.$lan_ifname.send_redirects = 0
EOF
sudo sysctl --system
```

`send_redirects` is read as the OR of `conf/all/send_redirects` and
`conf/<interface>/send_redirects`, so the per-interface entry above changes
nothing on its own: `conf/all/send_redirects` defaults to `1`, and the kernel
keeps offering downstream clients a direct route to the upstream router, which
bypasses dae. Disable the global node as well:

```shell
printf 'net.ipv4.conf.all.send_redirects = 0\n' | sudo tee /etc/sysctl.d/60-dae-send-redirects.conf
sudo sysctl --system
```

The reverse is also true: `conf/all/send_redirects = 0` is not enough on its own
either, because an interface whose own node is still `1` keeps sending redirects.
They stop only where both nodes are `0`, which is the case for the LAN interfaces
dae actually configures. Interfaces dae leaves alone - WAN, for example - keep
their own node at the default `1` and go on sending them.

It is also recommended to enable IPv4 and IPv6 forward to avoid weird situations:

```shell
echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/60-ip-forward.conf
echo "net.ipv6.conf.all.forwarding = 1" | sudo tee /etc/sysctl.d/60-ip-forward.conf
sudo sysctl --system
```

Please modify `docker0` to your LAN interface.

For your WAN interfaces that accept RA:

```shell
export wan_ifname=eth0

if [ "$(cat /proc/sys/net/ipv6/conf/$wan_ifname/accept_ra)" == "1" ]; then
    sudo tee /etc/sysctl.d/60-dae-wan-$wan_ifname.conf << EOF
net.ipv6.conf.$wan_ifname.accept_ra = 2
EOF
    sudo sysctl --system
fi
```

Please modify `eth0` to your WAN interface.

Setting accept_ra to 2 if it is 1 because `net.ipv6.conf.all.forwarding = 1` will suppress it. See <https://sysctl-explorer.net/net/ipv6/accept_ra/> for more information.
