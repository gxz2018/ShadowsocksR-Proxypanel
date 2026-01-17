#!/bin/bash
#=================================================================#
#   V2Ray + SSR + IP盾构机一键部署脚本                             #
#   适配 CentOS 7+, Ubuntu 14+ 4合1脚本                           #
#   日志统一管理：保留3天，每天凌晨5点自动清理                      #
#=================================================================#

# 颜色定义
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
cyan='\033[0;36m'
plain='\033[0m'

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 检测 sh/dash
if readlink /proc/$$/exe 2>/dev/null | grep -q "dash"; then
    echo -e "${red}请使用 bash 运行此脚本，不要使用 sh${plain}"
    exit 1
fi

# 检查 root 权限
if [[ "$EUID" -ne 0 ]]; then
    echo -e "${red}错误: 必须使用 root 用户运行此脚本!${plain}"
    exit 1
fi

# 检查系统
check_system(){
    sys_bit=$(uname -m)
    if [[ -f /usr/bin/apt ]] || [[ -f /usr/bin/yum && -f /bin/systemctl ]]; then
        if [[ -f /usr/bin/yum ]]; then
            cmd="yum"
            $cmd -y install epel-release > /dev/null 2>&1
        fi
        if [[ -f /usr/bin/apt ]]; then
            cmd="apt"
        fi
        if [[ -f /bin/systemctl ]]; then
            systemd=true
        fi
    else
        echo -e "${red}只支持CentOS7+及Ubuntu14+${plain}" && exit 1
    fi
    
    if grep -qs "14.04" /etc/os-release || grep -qs "jessie" /etc/os-release; then
        echo -e "${red}不支持 Ubuntu 14.04 或 Debian 8${plain}"
        exit 1
    fi
    if grep -qs "CentOS release 6" /etc/redhat-release 2>/dev/null; then
        echo -e "${red}不支持 CentOS 6${plain}"
        exit 1
    fi
}

service_Cmd() {
    if [[ $systemd ]]; then
        systemctl $1 $2
    else
        service $2 $1
    fi
}

# 显示主菜单
show_menu(){
    check_system
    clear
    echo -e "${cyan}"
    echo "============================================================"
    echo "  V2Ray + SSR + IP盾构机 一键部署脚本"
    echo "  适配 CentOS 7+, Ubuntu 14+"
    echo "  日志管理: 保留3天 | 每天5:00自动清理"
    echo "============================================================"
    echo -e "${plain}"
    echo "【V2Ray 服务】"
    echo -e "${green}1.${plain} 安装 V2Ray"
    echo ""
    echo "【SSR 服务】"
    echo -e "${green}2.${plain} SSR 独立模式 - 单节点服务器"
    echo -e "${green}3.${plain} SSR 面板模式 - 对接 SSRPanel 前端"
    echo -e "${green}4.${plain} 卸载 SSR (独立模式)"
    echo -e "${green}5.${plain} 卸载 SSR (面板模式)"
    echo ""
    echo "【IP盾构机】"
    echo -e "${green}6.${plain} 落地机-全局初始化"
    echo ""
    echo -e "${green}0.${plain} 退出脚本"
    echo ""
    read -p "请输入选项 [0-6]: " choice
    
    case "$choice" in
        1) install_v2ray_menu ;;
        2) install_standalone ;;
        3) install_panel ;;
        4) uninstall_standalone ;;
        5) uninstall_panel ;;
        6) ip_landing_init ;;
        0) exit 0 ;;
        *) echo -e "${red}无效选项${plain}" && sleep 2 && show_menu ;;
    esac
}

#=================================================================#
#                      V2Ray 部署函数                              #
#=================================================================#

install_v2ray_menu(){
    echo -e "\n${cyan}=== V2Ray 节点配置 ===${plain}\n"
    
    echo "正在安装依赖包..."
    $cmd update -y > /dev/null 2>&1
    $cmd install -y wget curl unzip git gcc vim lrzsz screen ntp ntpdate cron net-tools telnet python3-pip m2crypto logrotate > /dev/null 2>&1
    
    # 设置时区为CST
    echo yes | cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime > /dev/null 2>&1
    ntpdate cn.pool.ntp.org > /dev/null 2>&1
    hwclock -w > /dev/null 2>&1
    sed -i '/^.*ntpdate*/d' /etc/crontab
    sed -i '$a\* * * * 1 ntpdate cn.pool.ntp.org >> /dev/null 2>&1' /etc/crontab
    service_Cmd restart crond > /dev/null 2>&1
    echo -e "${green}依赖包安装完成${plain}"
    
    read -p "面板分配的节点ID，如 6 ：" node_Id
    read -p "V2Ray端口(不可80/443，默认：10086)：" v2ray_Port
        [ -z "$v2ray_Port" ] && v2ray_Port="10086"
    read -p "配置同步端口(不可80/443，默认：10087)：" usersync_Port
        [ -z "$usersync_Port" ] && usersync_Port="10087"
    read -p "转发路径(不要带/，默认：game)：" forward_Path
        [ -z "$forward_Path" ] && forward_Path="game"
    read -p "V2Ray额外ID(默认：16)：" alter_Id
        [ -z "$alter_Id" ] && alter_Id="16"
    read -p "数据库地址，如 1.1.1.1 ：" db_Host
    read -p "数据库端口(默认：3306)：" db_Port
        [ -z "$db_Port" ] && db_Port="3306"
    read -p "数据库名称(默认：ssrpanel)：" db_Name
        [ -z "$db_Name" ] && db_Name="ssrpanel"
    read -p "数据库用户(默认：ssrpanel)：" db_User
        [ -z "$db_User" ] && db_User="ssrpanel"
    read -p "数据库密码，如 ssrpanel ：" db_Password
    
    install_v2ray
    setup_v2ray_log_rotation
    firewall_set_v2ray
    service_Cmd status v2ray
    
    echo -e "\n${green}============================================${plain}"
    echo -e "${green}✅ V2Ray 安装完成!${plain}"
    echo -e "${green}============================================${plain}"
    echo -e "日志级别: error"
    echo -e "日志保留: 3天"
    echo -e "自动清理: 每天凌晨5点"
    echo -e "配置文件: /etc/v2ray/config.json"
    echo ""
    
    read -p "按 Enter 返回主菜单..." && show_menu
}

install_v2ray(){
    echo -e "\n${cyan}正在安装V2Ray...${plain}"
    
    # 先卸载再装
    systemctl stop v2ray > /dev/null 2>&1
    rm -rf /usr/bin/v2ray /etc/init.d/v2ray /lib/systemd/system/v2ray.service

    curl -L -s https://raw.githubusercontent.com/fei5seven/v2ray-ssrpanel-plugin/master/install-release.sh | bash > /dev/null 2>&1
    wget --no-check-certificate -O config.json https://raw.githubusercontent.com/fei5seven/ssrpanel-v2ray-java/master/resource/v2ray-config.json > /dev/null 2>&1
    
    sed -i -e "s/v2ray_Port/$v2ray_Port/g" config.json
    sed -i -e "s/alter_Id/$alter_Id/g" config.json
    sed -i -e "s/forward_Path/$forward_Path/g" config.json
    sed -i -e "s/usersync_Port/$usersync_Port/g" config.json
    sed -i -e "s/node_Id/$node_Id/g" config.json
    sed -i -e "s/db_Host/$db_Host/g" config.json
    sed -i -e "s/db_Port/$db_Port/g" config.json
    sed -i -e "s/db_Name/$db_Name/g" config.json
    sed -i -e "s/db_User/$db_User/g" config.json
    sed -i -e "s/db_Password/$db_Password/g" config.json
    
    # 将日志级别改为 error
    sed -i 's/"loglevel".*:.*"debug"/"loglevel": "error"/g' config.json
    sed -i 's/"loglevel".*:.*"info"/"loglevel": "error"/g' config.json
    sed -i 's/"loglevel".*:.*"warning"/"loglevel": "error"/g' config.json
    
    mv -f config.json /etc/v2ray/
    service_Cmd restart v2ray > /dev/null 2>&1
    echo -e "${green}V2Ray安装完成${plain}"
}

setup_v2ray_log_rotation(){
    echo -e "${cyan}配置日志自动清理 (保留3天, 每天5:00清理)...${plain}"
    
    # 创建 logrotate 配置
    cat > /etc/logrotate.d/v2ray <<EOF
/var/log/v2ray/*.log {
    daily
    rotate 3
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    dateext
    dateformat -%Y%m%d
    maxage 3
}
EOF

    # 添加定时清理任务 - 每天凌晨5点
    sed -i '/v2ray.*log/d' /etc/crontab
    echo "0 5 * * * root find /var/log/v2ray/ -name '*.log*' -mtime +3 -delete > /dev/null 2>&1" >> /etc/crontab
    
    # 立即清理超过3天的旧日志
    find /var/log/v2ray/ -name "*.log*" -mtime +3 -delete > /dev/null 2>&1
    
    service_Cmd restart crond > /dev/null 2>&1
    echo -e "${green}日志清理配置完成${plain}"
}

firewall_set_v2ray(){
    echo -e "${cyan}正在配置防火墙...${plain}"
    if command -v firewall-cmd >/dev/null 2>&1; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            firewall-cmd --permanent --zone=public --remove-port=${v2ray_Port}/tcp > /dev/null 2>&1
            firewall-cmd --permanent --zone=public --remove-port=${v2ray_Port}/udp > /dev/null 2>&1
            firewall-cmd --permanent --zone=public --add-port=${v2ray_Port}/tcp > /dev/null 2>&1
            firewall-cmd --permanent --zone=public --add-port=${v2ray_Port}/udp > /dev/null 2>&1
            firewall-cmd --reload > /dev/null 2>&1
        fi
    elif command -v iptables >/dev/null 2>&1; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -D INPUT -p tcp --dport ${v2ray_Port} -j ACCEPT > /dev/null 2>&1
            iptables -A INPUT -p tcp --dport ${v2ray_Port} -j ACCEPT > /dev/null 2>&1
            iptables -D INPUT -p udp --dport ${v2ray_Port} -j ACCEPT > /dev/null 2>&1
            iptables -A INPUT -p udp --dport ${v2ray_Port} -j ACCEPT > /dev/null 2>&1
            ip6tables -D INPUT -p tcp --dport ${v2ray_Port} -j ACCEPT > /dev/null 2>&1
            ip6tables -A INPUT -p tcp --dport ${v2ray_Port} -j ACCEPT > /dev/null 2>&1
            ip6tables -D INPUT -p udp --dport ${v2ray_Port} -j ACCEPT > /dev/null 2>&1
            ip6tables -A INPUT -p udp --dport ${v2ray_Port} -j ACCEPT > /dev/null 2>&1
            /etc/init.d/iptables save > /dev/null 2>&1
            /etc/init.d/iptables restart > /dev/null 2>&1
            /etc/init.d/ip6tables save > /dev/null 2>&1
            /etc/init.d/ip6tables restart > /dev/null 2>&1
        fi
    fi
    echo -e "${green}防火墙配置完成${plain}"
}

#=================================================================#
#                      IP盾构机部署函数                            #
#=================================================================#

ip_landing_init(){
    echo -e "\n${cyan}=== 落地机初始化 ===${plain}\n"
    echo -e "${yellow}注意: 请提前手动放行防火墙端口!${plain}\n"
    
    echo -e "${cyan}安装依赖...${plain}"
    if [[ -f /etc/redhat-release ]]; then
        yum install -y wget curl ca-certificates
    else
        apt-get update && apt-get install -y wget curl ca-certificates
    fi
    
    read -p "是否下载被控端文件? (首次必须安装) [y/N]: " down_files_1
    if [[ "$down_files_1" =~ ^[yY]$ ]]; then
        echo -e "${cyan}下载 gost 2.11...${plain}"
        wget -q --show-progress http://eltty.elttycn.com/gost -O /usr/bin/gost
        chmod +x /usr/bin/gost
        
        echo -e "${cyan}下载被控端...${plain}"
        wget -q --show-progress http://eltty.elttycn.com/iptables_gost -O /usr/bin/iptables_gost
        chmod +x /usr/bin/iptables_gost
        
        echo -e "${green}✓ 文件下载完成${plain}"
    fi
    
    echo ""
    echo -e "${green}============================================${plain}"
    echo -e "${green}✅ 落地机初始化完成!${plain}"
    echo -e "${green}============================================${plain}"
    echo ""
    echo "重要提示:"
    echo "1. 请手动执行 'crontab -e' 添加定时任务"
    echo "2. 确保已放行必要的防火墙端口"
    echo ""
    echo "工具路径:"
    echo "  /usr/bin/gost"
    echo "  /usr/bin/iptables_gost"
    echo ""
    
    read -p "按 Enter 返回主菜单..." && show_menu
}

#=================================================================#
#                      SSR独立模式部署函数                         #
#=================================================================#

libsodium_file="libsodium-1.0.18"
libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz"
shadowsocks_r_file="shadowsocksr-3.2.2"
shadowsocks_r_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"

cur_dir=`pwd`

ciphers=(none aes-256-cfb aes-192-cfb aes-128-cfb aes-256-cfb8 aes-192-cfb8 aes-128-cfb8 aes-256-ctr aes-192-ctr aes-128-ctr chacha20-ietf chacha20 salsa20 xchacha20 xsalsa20 rc4-md5)
protocols=(origin verify_deflate auth_sha1_v4 auth_sha1_v4_compatible auth_aes128_md5 auth_aes128_sha1 auth_chain_a auth_chain_b auth_chain_c auth_chain_d auth_chain_e auth_chain_f)
obfs=(plain http_simple http_simple_compatible http_post http_post_compatible tls1.2_ticket_auth tls1.2_ticket_auth_compatible tls1.2_ticket_fastauth tls1.2_ticket_fastauth_compatible)

get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( curl -s ifconfig.me 2>/dev/null )
    [ -z ${IP} ] && IP=$( curl -s ipinfo.io/ip 2>/dev/null )
    [ ! -z ${IP} ] && echo ${IP} || echo
}

pre_install_standalone(){
    echo -e "\n${cyan}=== SSR 独立模式配置 ===${plain}\n"
    
    read -p "请输入 SSR 密码 (默认: teddysun.com): " shadowsockspwd
    [ -z "$shadowsockspwd" ] && shadowsockspwd="teddysun.com"
    shadowsockspwd=$(echo "$shadowsockspwd" | xargs)
    
    dport=$(shuf -i 9000-19999 -n 1)
    read -p "请输入端口 [1-65535] (默认: ${dport}): " shadowsocksport
    [ -z "${shadowsocksport}" ] && shadowsocksport=${dport}
    
    echo -e "\n请选择加密方式:"
    for ((i=1;i<=${#ciphers[@]};i++ )); do
        echo -e "${green}${i})${plain} ${ciphers[$i-1]}"
    done
    read -p "选择 (默认: 2): " pick
    [ -z "$pick" ] && pick=2
    shadowsockscipher=${ciphers[$pick-1]}
    
    echo -e "\n请选择协议:"
    for ((i=1;i<=${#protocols[@]};i++ )); do
        echo -e "${green}${i})${plain} ${protocols[$i-1]}"
    done
    read -p "选择 (默认: 1): " protocol
    [ -z "$protocol" ] && protocol=1
    shadowsockprotocol=${protocols[$protocol-1]}
    
    echo -e "\n请选择混淆:"
    for ((i=1;i<=${#obfs[@]};i++ )); do
        echo -e "${green}${i})${plain} ${obfs[$i-1]}"
    done
    read -p "选择 (默认: 1): " r_obfs
    [ -z "$r_obfs" ] && r_obfs=1
    shadowsockobfs=${obfs[$r_obfs-1]}
    
    echo -e "\n${cyan}配置确认:${plain}"
    echo "密码: ${shadowsockspwd}"
    echo "端口: ${shadowsocksport}"
    echo "加密: ${shadowsockscipher}"
    echo "协议: ${shadowsockprotocol}"
    echo "混淆: ${shadowsockobfs}"
    echo ""
    read -p "按 Enter 开始安装..."
}

install_deps_standalone(){
    echo -e "\n${cyan}安装依赖...${plain}"
    if [[ -f /etc/redhat-release ]]; then
        yum install -y python3 python3-devel python3-setuptools openssl openssl-devel \
            curl wget unzip gcc automake autoconf make libtool libsodium-devel
    else
        apt-get -y update
        apt-get -y install python3 python3-dev python3-setuptools openssl libssl-dev \
            curl wget unzip gcc automake autoconf make libtool libsodium-dev
    fi
}

download_files_standalone(){
    cd ${cur_dir}
    
    if [ ! -f "/usr/lib/libsodium.a" ] && [ ! -f "/usr/local/lib/libsodium.a" ]; then
        echo "下载 libsodium..."
        wget --no-check-certificate -O ${libsodium_file}.tar.gz ${libsodium_url} || exit 1
    fi
    
    echo "下载 SSR..."
    wget --no-check-certificate -O ${shadowsocks_r_file}.tar.gz ${shadowsocks_r_url} || exit 1
}

config_shadowsocks_standalone(){
    cat > /etc/shadowsocks.json<<-EOF
{
    "server":"0.0.0.0",
    "server_ipv6":"[::]",
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":120,
    "method":"${shadowsockscipher}",
    "protocol":"${shadowsockprotocol}",
    "protocol_param":"",
    "obfs":"${shadowsockobfs}",
    "obfs_param":"",
    "redirect":"",
    "dns_ipv6":false,
    "fast_open":false,
    "workers":1
}
EOF
}

install_ssr_standalone(){
    if [ ! -f "/usr/lib/libsodium.a" ] && [ ! -f "/usr/local/lib/libsodium.a" ]; then
        cd ${cur_dir}
        tar zxf ${libsodium_file}.tar.gz
        cd ${libsodium_file}
        ./configure --prefix=/usr && make && make install || exit 1
    fi

    ldconfig
    
    cd ${cur_dir}
    tar zxf ${shadowsocks_r_file}.tar.gz
    mv ${shadowsocks_r_file}/shadowsocks /usr/local/
    
    if [ -f /usr/local/shadowsocks/server.py ]; then
        cat > /etc/systemd/system/shadowsocks-standalone.service <<EOF
[Unit]
Description=ShadowsocksR Server (Standalone)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/shadowsocks/server.py -c /etc/shadowsocks.json
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable shadowsocks-standalone
        systemctl start shadowsocks-standalone
        sleep 2
        
        if systemctl is-active --quiet shadowsocks-standalone; then
            clear
            echo -e "${green}✅ SSR 独立模式部署成功!${plain}\n"
            echo "=========================================="
            echo -e "服务器 IP: ${cyan}$(get_ip)${plain}"
            echo -e "端口: ${cyan}${shadowsocksport}${plain}"
            echo -e "密码: ${cyan}${shadowsockspwd}${plain}"
            echo -e "协议: ${cyan}${shadowsockprotocol}${plain}"
            echo -e "混淆: ${cyan}${shadowsockobfs}${plain}"
            echo -e "加密: ${cyan}${shadowsockscipher}${plain}"
            echo "=========================================="
            echo -e "\n常用命令:"
            echo "  systemctl start shadowsocks-standalone"
            echo "  systemctl stop shadowsocks-standalone"
            echo "  systemctl restart shadowsocks-standalone"
            echo "  systemctl status shadowsocks-standalone"
            echo "  journalctl -u shadowsocks-standalone -f"
            echo ""
            echo "日志管理: systemd journal 自动轮转"
            echo ""
        else
            echo -e "${red}启动失败，请查看日志: journalctl -u shadowsocks-standalone${plain}"
            exit 1
        fi
    else
        echo -e "${red}安装失败${plain}"
        exit 1
    fi
    
    rm -rf ${shadowsocks_r_file}.tar.gz ${shadowsocks_r_file} ${libsodium_file}.tar.gz ${libsodium_file}
}

install_standalone(){
    pre_install_standalone
    install_deps_standalone
    download_files_standalone
    config_shadowsocks_standalone
    install_ssr_standalone
    read -p "按 Enter 返回主菜单..." && show_menu
}

uninstall_standalone(){
    echo -e "\n${yellow}确定要卸载 SSR 独立模式吗? (y/n)${plain}"
    read -p "(默认: n): " answer
    [ -z ${answer} ] && answer="n"
    
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        systemctl stop shadowsocks-standalone 2>/dev/null
        systemctl disable shadowsocks-standalone 2>/dev/null
        rm -f /etc/shadowsocks.json
        rm -f /etc/systemd/system/shadowsocks-standalone.service
        rm -rf /usr/local/shadowsocks
        systemctl daemon-reload
        echo -e "${green}✅ 卸载成功${plain}"
    else
        echo -e "${yellow}已取消${plain}"
    fi
    
    read -p "按 Enter 返回主菜单..." && show_menu
}

#=================================================================#
#                      SSR面板模式部署函数                         #
#=================================================================#

pre_install_panel(){
    echo -e "\n${cyan}=== SSR 面板模式配置 ===${plain}\n"
    
    read -p "MySQL 地址 (如 127.0.0.1): " mysqla
    read -p "MySQL 用户名: " mysqlu
    read -p "MySQL 密码: " mysqlp
    read -p "MySQL 数据库名: " mysqld
    read -p "节点 ID: " node
    
    echo -e "\n${cyan}配置确认:${plain}"
    echo "数据库: ${mysqla}/${mysqld}"
    echo "用户: ${mysqlu}"
    echo "节点 ID: ${node}"
    echo ""
    read -p "按 Enter 开始安装..."
}

install_deps_panel(){
    echo -e "\n${cyan}安装依赖...${plain}"
    if [[ $cmd == "apt" ]]; then
        apt update -y
        apt install -y git python3 python3-pip net-tools build-essential \
            iptables supervisor curl libffi-dev libsodium-dev openssl libssl-dev
    else
        yum install -y git python3 python3-pip net-tools gcc \
            iptables supervisor curl libffi-devel libsodium-devel openssl openssl-devel
    fi
}

setup_firewall(){
    echo -e "\n${cyan}配置防火墙...${plain}"
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            firewall-cmd --zone=public --add-port=22-65535/tcp --permanent
            firewall-cmd --zone=public --add-port=22-65535/udp --permanent
            firewall-cmd --reload
        fi
    else
        iptables -F
        iptables -I INPUT -p tcp --dport 22:65535 -j ACCEPT
        iptables -I INPUT -p udp --dport 22:65535 -j ACCEPT
        
        if [[ $cmd == "apt" ]]; then
            echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
            echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
            
            if ! dpkg -l | grep -q iptables-persistent; then
                DEBIAN_FRONTEND=noninteractive apt install -y iptables-persistent
            else
                netfilter-persistent save
            fi
        else
            service iptables save
        fi
    fi
}

setup_bbr(){
    echo -e "\n${cyan}启用 BBR 加速...${plain}"
    kernel_version=$(uname -r | cut -d. -f1)
    
    if [ "$kernel_version" -ge 4 ]; then
        modprobe tcp_bbr
        
        if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
            cat >> /etc/sysctl.conf <<EOF

# BBR 加速配置
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
        fi
        
        sysctl -p
        
        if lsmod | grep -q bbr && sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
            echo -e "${green}✓ BBR 已启用${plain}"
        else
            echo -e "${yellow}⚠ BBR 启用可能失败${plain}"
        fi
    else
        echo -e "${yellow}⚠ 内核版本过低 (需要 4.9+)${plain}"
    fi
}
#=================================================================#
#                           主程序入口                             #
#=================================================================#

show_menu