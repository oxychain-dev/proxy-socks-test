#!/bin/bash
RUNDIR=`dirname $0`
if [ "${RUNDIR:0:1}" != "/" ];then RUNDIR=`pwd`/$RUNDIR;fi
cd $RUNDIR
while [[ $# -ge 1 ]]
do
    arg=$1
    if echo $arg |grep -q '\-\-proxyip'
    then
	shift
        proxyip="$1"
        echo "proxyip $proxyip"
    elif echo $arg |grep -q '\-\-proxyport'
    then
	shift
	proxyport="$1"
        echo "proxyport $proxyport"
    elif echo $arg |grep -q '\-\-serverip'
    then
	shift
        serverip="$1"
        echo "serverip $serverip"
    elif echo $arg |grep -q '\-\-auth'
    then
	shift
        auth="$1"
        echo "auth $auth"
    elif echo $arg |grep -q '\-\-datasize'
    then
	shift
        echo "datasize $datasize"
        datasize="--datasize $1"
    elif echo $arg |grep -q '\-\-debug'
    then
	shift
        debug="--debug"
        echo "auth $auth"
    fi
    shift
done
if [ -z $proxyport ] || [ -z $proxyip ] || [ -z $serverip ]
then
    echo "example:"
    echo "$0 --proxyip 10.206.118.122 --proxyport 1080 --serverip 10.206.118.65"
    echo "example with auth:"
    echo "$0 --proxyip 10.206.118.122 --proxyport 1080 --serverip 10.206.118.65 --auth user1:user1"
    exit 0
fi

eval_cmd()
{
   echo "$@"
   eval $@
}
eval_cmd ./proxy-socks-test --proxyip $proxyip --proxyport $proxyport --serverip $serverip --casename socks4_connect $datasize $debug
eval_cmd ./proxy-socks-test --proxyip $proxyip --proxyport $proxyport --serverip $serverip --casename socks4a_connect $datasize $debug
eval_cmd ./proxy-socks-test --proxyip $proxyip --proxyport $proxyport --serverip $serverip --casename socks5_connect $datasize $debug
eval_cmd ./proxy-socks-test --proxyip $proxyip --proxyport $proxyport --serverip $serverip --casename socks4a_connect_hostname $datasize $debug
eval_cmd ./proxy-socks-test --proxyip $proxyip --proxyport $proxyport --serverip $serverip --casename socks5_connect_hostname $datasize $debug
eval_cmd ./proxy-socks-test --proxyip $proxyip --proxyport $proxyport --serverip $serverip --casename socks4_bind $datasize $debug
eval_cmd ./proxy-socks-test --proxyip $proxyip --proxyport $proxyport --serverip $serverip --casename socks5_bind $datasize $debug
eval_cmd ./proxy-socks-test --proxyip $proxyip --proxyport $proxyport --serverip $serverip --casename socks5_udp $datasize $debug
if [ ! -z $auth ]
then
    ./proxy-socks-test --proxyip $proxyip --proxyport $proxyport --serverip $serverip --casename socks5_auth_connect --auth $auth $datasize $debug
fi
