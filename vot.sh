EXPOSING
THEINVISIBLE
PROJECT
FILMS
RESOURCES
GUIDES
Search
Go
Cs vot en v01 000 onions small
vot.sh


#!/bin/bash

##################################################################
# OpenVPN over Tor (VoT)
#
# requirements: 
#   - must be run as root ("sudo VoT.sh", "gksu VoT.sh" or in root term)
#   - openvpn config file must be named "vot.ovpn" and reside in /home/amnesia/Persistent/vpn
#   - openvpn must be configured to use TCP (vs. std. UDP) 
#   - openvpn must be configured to use tun (vs. tap)
#   - must use IPv4 networking because we disable IPv6 to prevent leaking
#   - to use VPN start software using "sudo -u vpnuser MySoftware"
##################################################################

# check necessary rights
if [ ! `id -u` = 0 ] ; then
        echo "This script needs to be run using 'sudo SCRIPT' or in 'root terminal'"
  read -n1 -r -p "Press any key to exit..." key
  exit 1
fi

# check for tcp config in vot.ovpn
if [[ ! $(cat /home/amnesia/Persistent/vpn/vot.ovpn | grep "proto tcp") ]]
then
        echo "OpenVPN needs to be configured using "proto tcp" to work in Tails"
  read -n1 -r -p "Press any key to exit..." key
  exit 1
fi

# check that no "socks-proxy" directive is in vot.ovpn
if [[ $(cat /home/amnesia/Persistent/vpn/vot.ovpn | grep "socks-proxy") ]]
then
        echo "This script does not allow to have "socks-proxy" in vot.ovpn because it will be added by this scrpt"
  read -n1 -r -p "Press any key to exit..." key
  exit 1
fi


# disable IPv6 - is exploited to circumvent default IPv4-route to reveal users real IP address
grep "net.ipv6.conf.all.disable_ipv6 = 1" /etc/sysctl.conf  >/dev/null || echo net.ipv6.conf.all.disable_ipv6 = 1 >> /etc/sysctl.conf 
sysctl -p >/dev/null

# add user vpnuser for running VPNed software
grep "vpnuser" /etc/passwd  >/dev/null || useradd -m -s /bin/bash -U vpnuser 2>&1  >/dev/null
xhost +local:vpnuser >/dev/null       # Was: `xhost +si:localuser:vpnuser >/dev/null` 

# install net-tools if necessary
if [ ! -f /bin/netstat ]
then
        apt-get install -y net-tools
fi

# populate vars
unset phys_if
unset phys_IP
unset phys_gw
phys_if=`netstat -r | grep default | awk '{print $8}'`
phys_IP=`ifconfig $phys_if | grep "inet " | cut -d: -f2 | awk '{print $2}'`
phys_gw=`netstat -r | grep default | awk '{print $2}'`

# install openvpn if not yet installed
if [ ! -f /usr/sbin/openvpn ]
then
  echo
  echo
  echo "    **********************  OpenVPN install  **********************"
  echo
  apt-cache search openvpn 2>/dev/nul | grep "openvpn - virtual private network daemon" || apt-get update
  apt-get install -y libpkcs11-helper1 openvpn 
fi

# configure ferm.conf to allow access to 9053/tcp for users root and openvpn, (re)route Tor traffic trough phys. interface and allow vpnuser to access tun0
if [[ ! $(cat /etc/ferm/ferm.conf | grep "outerface tun0 mod owner uid-owner vpnuser") ]]
then
  cp /etc/ferm/ferm.conf /etc/ferm/bak.ferm.conf
  awk '/TransPort/{print "                # White-list access to Tor socks port for OpenVPN" RS "                daddr 127.0.0.1 proto tcp dport 9053 {" RS "                    mod owner uid-owner root ACCEPT;" RS "                    mod owner uid-owner openvpn ACCEPT;" RS "                }" RS RS $0;next}1' /etc/ferm/ferm.conf >/tmp/ferm.conf && mv /tmp/ferm.conf /etc/ferm
  awk '/Local network connections should not go through Tor but DNS shall be/{print "            # vpnuser is allowed to connect to any TCP or UDP port via tun0" RS "            # to be able to use OpenVPN connections" RS "            outerface tun0 mod owner uid-owner vpnuser {" RS "                proto tcp ACCEPT;" RS "                proto udp ACCEPT;" RS "            }" RS RS $0;next}1' /etc/ferm/ferm.conf >/tmp/ferm.conf && mv /tmp/ferm.conf /etc/ferm
  awk '/                daddr 127.0.0.1 proto udp dport \(53 5353\) {/{print $0 RS "                    mod owner uid-owner vpnuser ACCEPT;"; next}1' /etc/ferm/ferm.conf >/tmp/ferm.conf && mv /tmp/ferm.conf /etc/ferm
  awk '/^        chain POSTROUTING/{del=2;print;print "            policy ACCEPT;" RS RS "            # SNAT Tor packets to physical interfaces IP" RS "            outerface '$phys_if' mod mark mark 42 SNAT to-source '$phys_IP';" RS "        }" RS RS "        chain OUTPUT {";next} {if(!del)print} /^        chain OUTPUT /{del=0}' /etc/ferm/ferm.conf >/tmp/ferm.conf && mv /tmp/ferm.conf /etc/ferm
  awk '/^            daddr 127.0.0.1 proto udp dport 53 REDIRECT to-ports 5353;/{del=2;print;print "        }" RS "    }" RS RS "    table mangle {" RS "        chain OUTPUT {" RS "            # mark Tor-packets for re-routing through physical interface" RS "            mod owner uid-owner debian-tor MARK set-mark 42;" RS "        }" RS "    }" RS "}" RS RS "# IPv6:" ;next} {if(!del)print} /^# IPv6/{del=0}' /etc/ferm/ferm.conf >/tmp/ferm.conf && mv /tmp/ferm.conf /etc/ferm
fi

# add group and user "openvpn" to be used by OpenVPN when dropping privileges
grep "openvpn" /etc/passwd  >/dev/null || useradd -M -s /bin/false -U openvpn

# delete ferm cache
rm -f /var/cache/ferm/*
# reload ferm
echo
echo
echo "    **********************  reloading firewall to apply rules for VPN  **********************"
echo
/etc/init.d/ferm reload

# add SocksPort 9053 for OpenVPN to torrc
## SocksPort for OpenVPN
if [[ ! $(cat /etc/tor/torrc | grep "SocksPort for OpenVPN") ]]
then
  cp /etc/tor/torrc /etc/tor/bak.torrc
  awk '/SocksPort 127.0.0.1:9150 IsolateSOCKSAuth KeepAliveIsolateSOCKSAuth/{print $0 RS "## SocksPort for OpenVPN" RS "SocksPort 127.0.0.1:9053 PreferSOCKSNoAuth";next}1' /etc/tor/torrc >/tmp/torrc && mv /tmp/torrc /etc/tor
  chown debian-tor:debian-tor /etc/tor/torrc
  chmod 644 /etc/tor/torrc
fi

## reroute Tor traffic through physical interface
if [[ ! $(ip rule show | grep "fwmark 0x2a lookup 42") ]]
then
  # Route marked packets via physical interface
  ip rule add fwmark 42 table 42
  ip route add default via $phys_gw dev $phys_if table 42
fi

# restart Tor
echo
echo
echo "    **********************  restarting Tor  **********************"
echo
restart-tor

# clean vot.ovpn from DOS line breaks if necessary
if `grep -r $'\r' /home/amnesia/Persistent/vpn/vot.ovpn >/dev/null`
then
  unset votcfgperm
  votcfgperm=`stat -c%a /home/amnesia/Persistent/vpn/vot.ovpn`
  tr -d $'\r' < /home/amnesia/Persistent/vpn/vot.ovpn >/tmp/vot.ovpn && mv /tmp/vot.ovpn /home/amnesia/Persistent/vpn/
  chmod "$votcfgperm" /home/amnesia/Persistent/vpn/vot.ovpn
  unset votcfgperm
fi

# add socks proxy option to OpenVPN config and save it to /etc/openvpn/
awk '/^remote /{print $0 RS "socks-proxy 127.0.0.1 9053";next}1' /home/amnesia/Persistent/vpn/vot.ovpn > /etc/openvpn/vot.ovpn
cp /home/amnesia/Persistent/vpn/vot-ca.pem /etc/openvpn/vot-ca.pem

# add parameter "up-delay" to vot.ovpn to avoid the SIGHUP/SIGUSR1 after establishing connection
grep "up-delay" /etc/openvpn/vot.ovpn >/dev/null || echo "up-delay" >> /etc/openvpn/vot.ovpn

# add parameters to vot.ovpn to better handle unstable Tor
grep "connect-retry-max" /etc/openvpn/vot.ovpn >/dev/null || echo "connect-retry-max 1" >> /etc/openvpn/vot.ovpn
# grep "connect-retry" /etc/openvpn/vot.ovpn >/dev/null || echo "connect-retry 20" >> /etc/openvpn/vot.ovpn
# grep "connect-timeout" /etc/openvpn/vot.ovpn >/dev/null || echo "connect-timeout 120" >> /etc/openvpn/vot.ovpn

# add settings to drop privileges by running as user/group "openvpn"
grep "user openvpn" /etc/openvpn/vot.ovpn >/dev/null || echo "user openvpn" >> /etc/openvpn/vot.ovpn
grep "group openvpn" /etc/openvpn/vot.ovpn >/dev/null || echo "group openvpn" >> /etc/openvpn/vot.ovpn

# OpenVPN debug output
# echo "verb 11" >> /etc/openvpn/vot.ovpn

# put OpenVPN in a chroot jail
mkdir -p /tmp/openvpn/jail/tmp
if [[ ! $(cat /etc/openvpn/vot.ovpn | grep "chroot ") ]]
then
  echo "chroot /tmp/openvpn/jail" >> /etc/openvpn/vot.ovpn
fi

# wait for Tor to be ready
echo
echo
echo "    **********************  waiting for Tor to be ready  **********************"
echo
while [[ ! `sudo -u amnesia torsocks curl --connect-timeout 3 --retry 5 https://tails.boum.org 2>/dev/null` ]]; do sleep 1; done

# start openvpn in foreground (so it's easier to kill or for interactive login)
echo
echo
echo "    **********************  starting OpenVPN  **********************"
echo
echo "    *****************************************************************************************"
echo "    * remember: to use the VPN connection you MUST start software as user \"vpnuser\", like *"
echo "    * \"sudo -u vpnuser MySoftware\" or \"gksu -u vpnuser MySoftware\"                      *"
echo "    *                                                                                       *"
echo "    * for software integrated in Tails be aware that it will be configured to use Tor proxy *"
echo "    * you'll need to reconfigure and/or user additional software                            *"
echo "    *****************************************************************************************"
echo
echo

# start openvpn in foreround (so you can see its proceedings and enter login credentials))
openvpn /etc/openvpn/vot.ovpn

# start openvpn in background (bc you have auto-login and hate that additional window ;))
# openvpn /etc/openvpn/vot.ovpn &

# clean up changes
echo
echo
echo "    **********************  cleaning up changes  **********************"
echo
rm /etc/openvpn/vot-ca.pem
rm /etc/openvpn/vot.ovpn
ip route del default table 42
ip rule del fwmark 42 table 42
ip route del 127.0.0.1 via $phys_gw dev $phys_if
mv /etc/tor/bak.torrc /etc/tor/torrc
mv /etc/ferm/bak.ferm.conf /etc/ferm/ferm.conf
rm -f /var/cache/ferm/*
/etc/init.d/ferm reload
xhost -local:vpnuser >/dev/null   
userdel openvpn
sudo userdel -r vpnuser 2>/dev/null

# restart Tor in case it became irritated by closing OpenVPN connection
echo
echo
echo "    **********************  restarting Tor after cleanup  **********************"
echo
restart-tor

# Recreate `/run/tor-has-bootstrapped` and refresh the tor status indicator
echo
echo
echo "    **********************  reconnecting to network(s)  **********************"
echo
sudo -u amnesia nmcli networking off
sleep 5
sudo -u amnesia nmcli networking on
Exposing the InvisiblebyTactical Technology Collectiveis licensed underCreative Commons- Read ourdata use policy and disclaimer-Talk to us
