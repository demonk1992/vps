#!/bin/bash
if [ "${EUID}" -ne 0 ]; then
  echo "You need to run this script as root"
  exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
  echo "OpenVZ is not supported"
  exit 1
fi
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
MYIP=$(wget -qO- icanhazip.com);
if [ -f "/etc/v2ray/domain" ]; then
echo "Script Already Installed"
exit 0
fi
# update upgrade
export DEBIAN_FRONTEND=noninteractive
apt-get update; apt-get -y dist-upgrade;
apt-get install -y dropbear ca-certificates apt-transport-https lsb-release screen unzip wget curl git netcat tcpd tor build-essential checkinstall zlib1g-dev libsctp-dev cmake make gcc zlib1g-dev libwrap0-dev certbot tor perl libperl-dev libgd3 libgd-dev libgeoip1 libgeoip-dev geoip-bin libxml2 libxml2-dev libxslt1.1 libxslt1-dev build-essential git tree libpcre3-dev socket libssl-dev libssl1.0 dh-autoreconf libssh-4 libssh-dev libconfig9 lolcat linux-image-5.10.0-0.bpo.4-amd64 dropbear
# Create and Configure rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
exit 0
END
chmod +x /etc/rc.local
# Create rc.d
mkdir /etc/rc.d
chmod +x /etc/rc.d
cat > /etc/rc.d/rc.local <<-END
#!/bin/sh -e
exit 0
END
chmod +x /etc/rc.d/rc.local
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
#  set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart
# dsable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
# Upgrade openssl
cd /usr/local/src/
wget https://www.openssl.org/source/openssl-1.1.1k.tar.gz
tar xzf openssl-1.1.1k.tar.gz
cd openssl-1.1.1k
sudo ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib && make && make test && make install
cd /etc/ld.so.conf.d/
cat > openssl-1.1.1k.conf << "EOF"
/usr/local/ssl/lib
EOF
sudo ldconfig -v
sudo mv /usr/bin/c_rehash /usr/bin/c_rehash.backup
sudo mv /usr/bin/openssl /usr/bin/openssl.backup
cat > /etc/environment << "EOF"
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/ssl/bin"
EOF
source /etc/environment
echo $PATH
which openssl
openssl version -a
# Upgrade Openssl+Quic
cd
git clone --depth 1 -b OpenSSL_1_1_1k+quic https://github.com/quictls/openssl
cd openssl
./config enable-tls1_3 --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib && make && make install_sw
sudo ldconfig -v
source /etc/environment
echo $PATH
which openssl
openssl version -a
# Install badvpn deb/ubun
cd
wget https://github.com/ambrop72/badvpn/archive/1.999.130.tar.gz && tar xzf 1.999.130.tar.gz
mkdir badvpn-build
cd badvpn-build
cmake ~/badvpn-1.999.130 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7000 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7000 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
# Allow Script Badvpn
chmod +x /usr/local/bin/badvpn-udpgw
# Start Badvpn
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7000 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
# Dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=222/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS=""/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
service ssh restart
service dropbear restart
# Upgrade Dropbear
cd
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2020.81.tar.bz2
bzip2 -cd dropbear-2020.81.tar.bz2 | tar xvf -
cd dropbear-2020.81
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear.old
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
cd && rm -rf dropbear-2020.81 && rm -rf dropbear-2020.81.tar.bz2
service dropbear restart
# set ipv4 forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
# menu
cd /usr/local/bin/
wget https://raw.githubusercontent.com/demonk1992/membagongkan/main/menu.zip && unzip menu.zip
chmod +x /usr/local/bin/*
cd
# Stunel
wget ftp://ftp.stunnel.org/stunnel/archive/5.x/stunnel-5.59.tar.gz
tar -xf stunnel-5.59.tar.gz
cd stunnel-5.59
groupadd -g 51 stunnel &&
useradd -c "stunnel Daemon" -d /var/lib/stunnel \
        -g stunnel -s /bin/false -u 51 stunnel
 
 ./configure --prefix=/usr        \
            --sysconfdir=/etc    \
            --localstatedir=/var \
            --disable-systemd    &&
make
make docdir=/usr/share/doc/stunnel-5.59 install
install -v -m750 -o stunnel -g stunnel -d /var/lib/stunnel/run &&
chown stunnel:stunnel /var/lib/stunnel
cat > /etc/stunnel/stunnel.conf << "EOF"
pid    = /run/stunnel.pid
chroot = /var/lib/stunnel
client = no
setuid = stunnel
setgid = stunnel
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
cert   = /etc/stunnel/stunnel.pem

[https]
accept  = 3128
connect = 443
TIMEOUTclose = 0

EOF
# Generate Certificate Stunnel
openssl req -new -newkey rsa:2048 -days 3650 \
  -nodes -x509 -sha256 \
  -subj '/CN=LocalHost' \
  -keyout /etc/stunnel/stunnel.pem \
  -out /etc/stunnel/stunnel.pem

cat > /etc/systemd/system/stunnel.service << "EOF" 
[Unit]
Description=SSL tunnel for network daemons
Documentation=man:stunnel https://www.stunnel.org/docs.html
DefaultDependencies=no
After=network.target
After=syslog.target

[Install]
WantedBy=multi-user.target
Alias=stunnel.target

[Service]
Type=forking
EnvironmentFile=-/etc/sysconfig/stunnel.conf 
ExecStart=/usr/bin/stunnel /etc/stunnel/stunnel.conf
LimitNOFILE=infinity
EOF
systemctl enable stunnel.service --now
systemctl restart stunnel.service
cd
# sslh
wget https://mirror.unej.ac.id/debian/pool/main/s/sslh/sslh_1.18-1_amd64.deb
dpkg -i sslh_1.18-1_amd64.deb
apt --fix-broken install -y
cat > /etc/default/sslh << "EOF" 
RUN=yes

DAEMON=/usr/sbin/sslh

DAEMON_OPTS='--user sslh --listen 0.0.0.0:443 --ssh 127.0.0.1:222 --ssl 127.0.0.1:3128 --http 127.0.0.1:80 --openvpn 127.0.0.1:1194 --pidfile /var/run/sslh/sslh.pid'
EOF
sudo /etc/init.d/sslh restart
# Speed
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
sysctl net.ipv4.tcp_available_congestion_control
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.default_qdisc
sysctl -p
sed -i '$ i\fs.file-max = 1024000' /etc/sysctl.conf
sed -i '$ i\fs.inotify.max_user_instances = 8192' /etc/sysctl.conf
sed -i '$ i\net.core.default_qdisc=fq' /etc/sysctl.conf
sed -i '$ i\net.core.netdev_max_backlog = 262144' /etc/sysctl.conf
sed -i '$ i\net.core.rmem_default = 8388608' /etc/sysctl.conf
sed -i '$ i\net.core.rmem_max = 67108864' /etc/sysctl.conf
sed -i '$ i\net.core.somaxconn = 65535' /etc/sysctl.conf
sed -i '$ i\net.core.wmem_default = 8388608' /etc/sysctl.conf
sed -i '$ i\net.core.wmem_max = 67108864' /etc/sysctl.conf
sed -i '$ i\net.ipv4.ip_forward = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.ip_local_port_range = 10240 65000' /etc/sysctl.conf
sed -i '$ i\net.ipv4.route.gc_timeout = 100' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_congestion_control = hybla' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_congestion_control=bbr' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_fastopen = 3' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_fin_timeout = 30' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_keepalive_time = 1200' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_max_orphans = 3276800' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_max_syn_backlog = 65536' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_max_tw_buckets = 60000' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_mem = 94500000 915000000 927000000' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_mtu_probing = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_rmem = 4096 87380 67108864' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_sack = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_syn_retries = 2' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_synack_retries = 2' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_syncookies = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_timestamps = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_tw_reuse = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_window_scaling = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_wmem = 4096 65536 67108864' /etc/sysctl.conf
sed -i '$ i\net.netfilter.nf_conntrack_max = 6553500' /etc/sysctl.conf
sed -i '$ i\net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60' /etc/sysctl.conf
sed -i '$ i\net.netfilter.nf_conntrack_tcp_timeout_established = 3600' /etc/sysctl.conf
sed -i '$ i\net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120' /etc/sysctl.conf
sed -i '$ i\net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120' /etc/sysctl.conf
sed -i '$ i\net.nf_conntrack_max = 6553500' /etc/sysctl.conf
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
lsmod | grep bbr
echo "session required pam_limits.so" >> /etc/pam.d/common-session
echo "* soft nproc 1000000" >> /etc/security/limits.conf
echo "* hard nproc 1000000" >> /etc/security/limits.conf
echo "* soft nofile 1000000" >> /etc/security/limits.conf
echo "* hard nofile 1000000" >> /etc/security/limits.conf
echo "root soft nproc 1000000" >> /etc/security/limits.conf
echo "root hard nproc 1000000" >> /etc/security/limits.conf
echo "root soft nofile 1000000" >> /etc/security/limits.conf
echo "root hard nofile 1000000" >> /etc/security/limits.conf
# v2ray
wget https://multi.netlify.app/v2ray.sh && chmod +x v2ray.sh && screen -S v2ray ./v2ray.sh
# Setup l2tp
wget https://github.com/demonk1992/vps/raw/main/vpn-install.tar.gz && tar -xf vpn-install.tar.gz && chmod +x vpn-install/* && screen -S sudo bash vpn-install/ipsec/install.sh
# Openvpn
wget https://github.com/demonk1992/vps/raw/main/openvpn-install.sh && chmod +x openvpn-install.sh && screen -S openvpn-install ./openvpn-install.sh
# proxy
wget https://github.com/demonk1992/vps/raw/main/proxy.py
# Upgrade Kernel
cat > /etc/default/grub << "EOF" 
GRUB_DEFAULT="gnulinux-advanced-ece608be-d123-4838-8ffb-ddd0a9d4bfd5>gnulinux-5.10.0-0.bpo.4-amd64-advanced-ece608be-d123-4838-8ffb-ddd0a9d4bfd5"
GRUB_HIDDEN_TIMEOUT=0
GRUB_HIDDEN_TIMEOUT_QUIET=true
GRUB_TIMEOUT=0
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="console=tty1 console=ttyS0"
GRUB_CMDLINE_LINUX=""
EOF
sudo update-grub
history -c
echo "1.2" > /home/ver
clear
echo " "
echo "Installation has been completed!!"
echo " "
echo "=================================-Autoscript-===========================" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "--------------------------------------------------------------------------------" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH                 : 22"  | tee -a log-install.txt
echo "   - OpenVPN                 : UDP 1194"  | tee -a log-install.txt
echo "   - Stunnel4                : 3128"  | tee -a log-install.txt
echo "   - Ssl                : 443"  | tee -a log-install.txt
echo "   - Dropbear                : 222"  | tee -a log-install.txt

echo "   - Badvpn                  : 7100, 7200, 7300, 7400, 7500, 7600, 7700, 7800, 7900"  | tee -a log-install.txt
echo "   - Nginx                   : 8443"  | tee -a log-install.txt
echo "   - L2TP/IPSEC VPN          : 1701"  | tee -a log-install.txt
echo "   - V2RAY Vless None TLS    : 8880"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone                : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban                : [ON]"  | tee -a log-install.txt
echo "   - Dflate                  : [ON]"  | tee -a log-install.txt
echo "   - IPtables                : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot             : [ON]"  | tee -a log-install.txt
echo "   - IPv6                    : [OFF]"  | tee -a log-install.txt
echo "   - Installation Log --> /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   - User Name               : Demonk"  | tee -a log-install.txt
echo "   - Telegram                : T.me/sunatmasal"  | tee -a log-install.txt
echo "   - Whatsapp                : 082119813096"  | tee -a log-install.txt
echo "------------------Autoscript-----------------" | tee -a log-install.txt
echo ""
rm -f x.sh
sudo reboot
