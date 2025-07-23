#!/bin/bash

ipsaya=$(curl -s ipv4.icanhazip.com)
data_server=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$data_server")
data_ip="https://raw.githubusercontent.com/prass02/allos/main/izin"
checking_sc() {
  useexp=$(wget -qO- $data_ip | grep $ipsaya | awk '{print $3}')
  if [[ $date_list < $useexp ]]; then
    echo -ne
  else
    echo -e "VPS anda tidak memiliki akses untuk script"
    exit 0
  fi
}
checking_sc

function Anuanunya() {
g="\033[1;92m"
y='\033[1;93m'
u="\033[0;35m"
NC='\e[0m'
RED="\033[31m"
r="\033[1;91m"
z="\033[96m"
q="\e[1;92;41m"
ungu='\033[0;35m'
blue="\033[0;96m"
y="\033[1;93m"
j="\033[0;33m"
bl="\e[0;36m"
w="\e[1;97m"
link="https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh"
clear
if ! command -v curl &> /dev/null; then
echo "Please wait..."
sleep 2
apt install curl -y
fi
}

function cmd() {
curl -sL "${link}" -o reinstall.sh && bash reinstall.sh $1 $2 && reboot
}

function rdebian() {
Anuanunya
clear
echo -e "${z}┌──────────────────────────────────────────┐${NC}"
echo -e "${z}│${g}              Menu OS Debian              ${z}│$NC"
echo -e "${z}└──────────────────────────────────────────┘${NC}"
echo -e "${z}┌──────────────────────────────────────────┐${NC}"
echo -e "${z}│${NC} ${bl}[${w}1${bl}]${NC} Rebuild Untuk Vps Debian 10 ( Selain ISP DO )${NC}"
echo -e "${z}│${NC} ${bl}[${w}2${bl}]${NC} Rebuild Untuk Vps Debian 11${NC}"
echo -e "${z}│${NC} ${bl}[${w}3${bl}]${NC} Rebuild Untuk Vps Debian 12${NC}"
echo -e "${z}│${NC} ${bl}[${w}0${bl}]${NC} Back To Menu${NC}"
echo -e "${z}└──────────────────────────────────────────┘${NC}"
echo -e ""
read -p " Select Options [ 1 - 3 or 0 ] : " options
case $options in
1) cmd debian 10 ;;
2) cmd debian 11 ;;
3) cmd debian 12 ;;
0) menu ;;
*) echo -e "You Wrong Command !"; sleep 2; rdebian ;;
esac
}

function rubuntu() {
Anuanunya
clear
echo -e "${z}┌──────────────────────────────────────────┐${NC}"
echo -e "${z}│${g}              Menu OS Ubuntu              ${z}│$NC"
echo -e "${z}└──────────────────────────────────────────┘${NC}"
echo -e "${z}┌──────────────────────────────────────────┐${NC}"
echo -e "${z}│${NC} ${bl}[${w}1${bl}]${NC} Rebuild Untuk Vps Ubuntu 20.04${NC}"
echo -e "${z}│${NC} ${bl}[${w}2${bl}]${NC} Rebuild Untuk Vps Ubuntu 22.04${NC}"
echo -e "${z}│${NC} ${bl}[${w}3${bl}]${NC} Rebuild Untuk Vps Ubuntu 24.04${NC}"
echo -e "${z}│${NC} ${bl}[${w}0${bl}]${NC} Back To Menu${NC}"
echo -e "${z}└──────────────────────────────────────────┘${NC}"
echo -e ""
read -p " Select Options [ 1 - 3 or 0 ] : " options
case $options in
1) cmd ubuntu 20.04 ;;
2) cmd ubuntu 22.04 ;;
3) cmd ubuntu 24.04 ;;
0) menu ;;
*) echo -e "You Wrong Command !"; sleep 2; rubuntu ;;
esac
}

function fixdpkg() {

function cekos() {
    if [[ -e /etc/os-release ]]; then
        source /etc/os-release
        echo "$ID $VERSION_ID"
    else
        menu
    fi
}

if [[ $(cekos) == "debian 10" ]] || [[ $(cekos) == "ubuntu 20.04" ]]; then
pid_proses=$(lsof /var/lib/dpkg/lock)

if [ -n "$pid_proses" ]; then
  echo "$pid_proses"
  PID=$(echo "$pid_proses" | awk 'NR==2 {print $2}')
  kill -9 "$PID"
else
  echo -ne
fi

rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend
rm -f /var/cache/apt/archives/lock
dpkg --configure -a
apt update
apt upgrade -y

else

set -e

cp /var/lib/dpkg/statoverride /var/lib/dpkg/statoverride.backup

grep -v 'Debian-exim' /var/lib/dpkg/statoverride > /var/lib/dpkg/statoverride.temp
mv /var/lib/dpkg/statoverride.temp /var/lib/dpkg/statoverride

apt-get install -f -y
apt-get clean
apt-get update
fi

echo "Fix dpkg done"
}

function menurb() {
Anuanunya
clear
echo -e "${z}┌──────────────────────────────────────────┐${NC}"
echo -e "${z}│${g}             Menu Rebuild Vps             ${z}│$NC"
echo -e "${z}└──────────────────────────────────────────┘${NC}"
echo -e "${z}┌──────────────────────────────────────────┐${NC}"
echo -e "${z}│${NC} ${bl}[${w}1${bl}]${NC} Rebuild Untuk Vps Debian 10 ( Selain ISP DO )${NC}"
echo -e "${z}│${NC} ${bl}[${w}2${bl}]${NC} Rebuild Untuk Vps Debian 11${NC}"
echo -e "${z}│${NC} ${bl}[${w}3${bl}]${NC} Rebuild Untuk Vps Debian 12${NC}"
echo -e "${z}│${NC} ${bl}[${w}4${bl}]${NC} Rebuild Untuk Vps Ubuntu 20.04${NC}"
echo -e "${z}│${NC} ${bl}[${w}5${bl}]${NC} Rebuild Untuk Vps Ubuntu 22.04${NC}"
echo -e "${z}│${NC} ${bl}[${w}6${bl}]${NC} Rebuild Untuk Vps Ubuntu 24.04${NC}"
echo -e "${z}│${NC} ${bl}[${w}0${bl}]${NC} Back To Menu${NC}"
echo -e "${z}└──────────────────────────────────────────┘${NC}"
echo -e ""
read -p " Select Options [ 1 - 6 or 0 ] : " options
case $options in
1) cmd debian 10 ;;
2) cmd debian 11 ;;
3) cmd debian 12 ;;
4) cmd ubuntu 20.04 ;;
5) cmd ubuntu 22.04 ;;
6) cmd ubuntu 24.04 ;;
0) menu ;;
*) echo -e "You Wrong Command !"; sleep 2; rdebian ;;
esac
}

function menu() {
Anuanunya
clear
echo -e "${z}┌──────────────────────────────────────────┐${NC}"
echo -e "${z}│${g}             Tools Simple Vps             ${z}│$NC"
echo -e "${z}└──────────────────────────────────────────┘${NC}"
echo -e "${z}┌──────────────────────────────────────────┐${NC}"
echo -e "${z}│${NC} ${bl}[${w}1${bl}]${NC} Menu Rebuild Vps${NC}"
echo -e "${z}│${NC} ${bl}[${w}2${bl}]${NC} Fix dpkg${NC}"
echo -e "${z}│${NC} ${bl}[${w}0${bl}]${NC} Exit Menu${NC}"
echo -e "${z}└──────────────────────────────────────────┘${NC}"
echo -e ""
read -p " Select Options [ 1 - 2 or 0 ] : " options
case $options in
1) menurb ;;
2) fixdpkg ;;
0) exit ;;
*) echo -e "You Wrong Command !"; sleep 2; menu ;;
esac
}

if [[ $1 == "debian" ]]
then
rdebian
elif [[ $1 == "ubuntu" ]]
then
rubuntu
else
menu
fi

