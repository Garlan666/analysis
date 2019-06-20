package com.network.analysis.catchPacket;

import com.network.analysis.entity.myPacket;
import com.network.analysis.entity.timeQueue;
import jpcap.packet.*;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.locks.Lock;

/**
 * Created by Garlan on 2019/6/13.
 */
public class PacketChecker extends Thread {

    private Queue<Packet> packets = new ConcurrentLinkedDeque<>();
    private myPacket mp;
    private ArrayList<InetAddress> inetAddress = new ArrayList<InetAddress>();//本机网络信息
    private Map<String, String> ARPChart = new HashMap();//HashMap摸拟ARP表
    private final int ICMP_DDOS = 11;
    private timeQueue udpTimeQueue;
    private final int ICMP_FLOOD = 12;
    private final int ARP_CHEAT = 13;
    HashMap<String, IpTime> tcpMap = new HashMap<>();
    HashMap<String, IpTime> icmpMap = new HashMap<>();
    private timeQueue tcpTimeQueue;
    private timeQueue icmpTimeQueue;
    private int synlevel;   //syn报文正常参考数量



    private final int TCP_LAND = 1;
    private final int TCP_SYN_DDOS = 2;
    private final int SYN_FLOOD = 3;
    private final int TCP_PORT_SCAN = 4;
    private final int TCP_SCAN = 5;
    private final int UDP_DDOS = 6;
    private final int UDP_FLOOD = 7;
    private final int UDP_SCAN = 8;
    private final int ICMP_DEATH = 9;
    private final int ICMP_PING = 10;
    private int udplevel;
    private int icmplevel;
    private double syna;    //平滑参数

    private ArrayList<String> whiteList = new ArrayList<>();

    public ArrayList<String> getWhiteList() {
        return whiteList;
    }

    public void addWhiteList(String ip) {
        int j = 0;
        for (int i = 0; i < whiteList.size(); i++) {
            if (!ip.equals(whiteList.get(i))) j++;
            else break;
        }
        if (j == whiteList.size()) whiteList.add(ip);
    }

    public void removeWhite(String ip) {
        for (int i = 0; i < whiteList.size(); i++) {
            if (ip.equals(whiteList.get(i))) {
                whiteList.remove(i);
                return;
            }
        }
    }

    private boolean ifInWhite(String ip) {
        for (int i = 0; i < whiteList.size(); i++) {
            if (ip.equals("/" + whiteList.get(i))) {
                return true;
            }
        }
        return false;
    }


    @Override
    public void run() {
        init();

        while (true) {//轮询队列是否为空
            while (!packets.isEmpty()) {
                check(packets.poll());
            }

            synchronized (Lock.class) {
                try {
                    Lock.class.wait();//等待通知
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private double udpa;


    private void getInetAddress() {

        try {
            for (Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces(); interfaces.hasMoreElements(); ) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (networkInterface.isLoopback() || networkInterface.isVirtual() || !networkInterface.isUp()) {
                    continue;
                }
                Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                if (addresses.hasMoreElements()) {
                    InetAddress t = addresses.nextElement();
                    if (t.getHostAddress().startsWith("169.254.")) {
                        continue;
                    }
                    inetAddress.add(t);
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
    }

    private boolean ifContain(String ip) {
        for (int i = 0; i < inetAddress.size(); i++) {
            if (ip.equals("/" + inetAddress.get(i).getHostAddress())) {
                return true;
            }
        }
        return false;
    }


    private static String getMACAddress(InetAddress ia) {
        // 获得网络接口对象（即网卡），并得到mac地址，mac地址存在于一个byte数组中。
        byte[] mac = new byte[0];
        try {
            mac = NetworkInterface.getByInetAddress(ia).getHardwareAddress();
        } catch (SocketException e) {
            e.printStackTrace();
        }
        // 下面代码是把mac地址拼装成String
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < mac.length; i++) {
            if (i != 0) {
                sb.append(":");
            }
            // mac[i] & 0xFF 是为了把byte转化为正整数
            String s = Integer.toHexString(mac[i] & 0xFF);
            sb.append(s.length() == 1 ? 0 + s : s);
        }
        return sb.toString();
    }


    public void check(Packet packet) {

        mp = new myPacket(packet);

        if (packet instanceof jpcap.packet.TCPPacket) {
            TCPPacket p = (TCPPacket) packet;
            TCPChecker(p);
        } else if (packet instanceof jpcap.packet.UDPPacket) {
            UDPPacket p = (UDPPacket) packet;
            UDPChecker(p);
        } else if (packet instanceof jpcap.packet.ICMPPacket) {
            ICMPPacket p = (ICMPPacket) packet;
            ICMPChecker(p);
        } else if (packet instanceof jpcap.packet.ARPPacket) {
            ARPPacket p = (ARPPacket) packet;
            ARPChecker(p);
        }
    }

    //加入队列
    public void addQueue(Packet packet) {
        packets.offer(packet);
    }

    private class IpTime {
        Queue<Long> ipqueue = new LinkedList<>();
        HashMap<Integer, Long> ipport = new HashMap<>();
        long createtime = 0;//hash连接创建时间
        long refreshtime = 0;//上次刷新时间
    }

    private double icmpa;
    HashMap<String, IpTime> udpMap = new HashMap<>();

    private void init() {
        getInetAddress();
        for (int i = 0; i < inetAddress.size(); i++) {
            ARPChart.put(inetAddress.get(i).getHostAddress(), getMACAddress(inetAddress.get(i)));
        }

        runTask();

        tcpTimeQueue = new timeQueue(6, 2);
        synlevel = 8000;   //syn报文正常参考数量
        syna = 0.5;    //平滑参数


        udpTimeQueue = new timeQueue(6, 2);
        //设置
        udplevel = 5000;
        udpa = 0.5;

        icmpTimeQueue = new timeQueue(6, 2);
        //设置
        icmplevel = 500;
        icmpa = 0.5;
    }

    //每10分钟检查一次tcpMap，如果存在iptime 10分钟未刷新，删除键值对,清空ipqueue和ipport
    private void runTask() {
        final long timeInterval = 10 * 60 * 60;
        Runnable runnable = new Runnable() {
            public void run() {
                while (true) {
                    for (Map.Entry<String, IpTime> entry : tcpMap.entrySet()) {
                        if (entry.getValue().refreshtime - entry.getValue().createtime >= timeInterval) {
                            entry.getValue().ipqueue = null;
                            tcpMap.remove(entry.getKey());
                        }
                    }
                    for (Map.Entry<String, IpTime> entry : udpMap.entrySet()) {
                        if (entry.getValue().refreshtime - entry.getValue().createtime >= timeInterval) {
                            entry.getValue().ipqueue = null;
                            udpMap.remove(entry.getKey());
                        }
                    }
                    for (Map.Entry<String, IpTime> entry : icmpMap.entrySet()) {
                        if (entry.getValue().refreshtime - entry.getValue().createtime >= timeInterval) {
                            entry.getValue().ipqueue = null;
                            icmpMap.remove(entry.getKey());
                        }
                    }
                    try {
                        Thread.sleep(timeInterval);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        };
        new Thread(runnable).start();
    }

    public void TCPChecker(TCPPacket tcpPacket) {
        if (ifContain(tcpPacket.dst_ip.toString()) && !ifInWhite(tcpPacket.src_ip.toString())) {
            if (tcpPacket.syn) {
                if (tcpPacket.src_ip == tcpPacket.dst_ip) {
                    mp.setProtocol(1);
                    mp.setWarnType(TCP_LAND);
                    mp.setSrcIp(tcpPacket.src_ip.toString());
                    mp.setWarningMsg("此报文源IP与目的IP相同，疑似Land攻击");
                    PacketHandler.catchWarn(mp);
                }
                tcpTimeQueue.add(tcpPacket.sec);
                int f = tcpTimeQueue.average();
                if (tcpTimeQueue.last() / (syna * f + (1 - syna) * synlevel) >= 2) {
                    mp.setProtocol(1);
                    mp.setWarnType(TCP_SYN_DDOS);
                    mp.setSrcIp(tcpPacket.src_ip.toString());
                    mp.setWarningMsg("当前时段SYN请求过多，疑似DDos攻击");
                    PacketHandler.catchWarn(mp);
                }
                IpTime iptime = new IpTime();
                if (tcpMap.containsKey(tcpPacket.src_ip.toString())) {
                    iptime.refreshtime = tcpPacket.sec;
                    iptime = tcpMap.get(tcpPacket.src_ip.toString());
                    iptime.ipqueue.offer(tcpPacket.sec);
                    iptime.ipport.put(new Integer(tcpPacket.dst_port), tcpPacket.sec);
                    if (iptime.ipqueue.size() > 250) {
                        iptime.ipqueue.poll();
                        if (tcpPacket.sec - iptime.ipqueue.peek() < 10) {
                            //syn洪流报警
                            mp.setProtocol(1);
                            mp.setWarnType(SYN_FLOOD);
                            mp.setSrcIp(tcpPacket.src_ip.toString());
                            mp.setWarningMsg("此IP的SYN请求过多，疑似SYN洪流攻击");
                            PacketHandler.catchWarn(mp);
                        }
                    }
                    tcpMap.put(tcpPacket.src_ip.toString(), iptime);
                } else {
                    iptime.ipport.put(new Integer(tcpPacket.dst_port), tcpPacket.sec);
                    iptime.createtime = tcpPacket.sec;
                    iptime.ipqueue = new LinkedList<>();
                    iptime.ipqueue.offer(tcpPacket.sec);
                    tcpMap.put(tcpPacket.src_ip.toString(), iptime);
                }
                //ipport存入5分钟内试图连接的端口
                for (Map.Entry<Integer, Long> entry : iptime.ipport.entrySet()) {
                    if (tcpPacket.sec - entry.getValue() >= 5 * 60 * 60) iptime.ipport.remove(entry.getKey());
                }
                if (iptime.ipport.size() >= 100) {
                    mp.setProtocol(1);
                    mp.setWarnType(TCP_PORT_SCAN);
                    mp.setSrcIp(tcpPacket.src_ip.toString());
                    mp.setWarningMsg("此IP在短时间内大量访问不同端口，疑似端口扫描");
                    PacketHandler.catchWarn(mp);
                }
            }
            if ((tcpPacket.fin && tcpPacket.urg && tcpPacket.psh) || (tcpPacket.fin && tcpPacket.syn) || (!tcpPacket.syn && !tcpPacket.fin && !tcpPacket.ack && !tcpPacket.psh && !tcpPacket.rst && !tcpPacket.urg)) {
                mp.setProtocol(1);
                mp.setSrcIp(tcpPacket.src_ip.toString());
                mp.setWarnType(TCP_SCAN);
                mp.setWarningMsg("此报文非法，疑似扫描");
                PacketHandler.catchWarn(mp);
            }

        }
    }

    private void UDPChecker(UDPPacket udpPacket) {
        if (ifContain(udpPacket.dst_ip.toString()) && !ifInWhite(udpPacket.src_ip.toString())) {
            udpTimeQueue.add(udpPacket.sec);
            int f = udpTimeQueue.average();
            if (udpTimeQueue.last() / (udpa * f + (1 - udpa) * udplevel) >= 2) {
                mp.setProtocol(2);
                mp.setSrcIp(udpPacket.src_ip.toString());
                mp.setWarnType(UDP_DDOS);
                mp.setWarningMsg("当前时段收到的UDP数据包过多，疑似DDos攻击");
                PacketHandler.catchWarn(mp);
            }
            IpTime udpiptime = new IpTime();
            if (udpMap.containsKey(udpPacket.src_ip.toString())) {
                udpiptime.refreshtime = udpPacket.sec;
                udpiptime = udpMap.get(udpPacket.src_ip.toString());
                udpiptime.ipqueue.offer(udpPacket.sec);
                udpiptime.ipport.put(new Integer(udpPacket.dst_port), udpPacket.sec);
                if (udpiptime.ipqueue.size() > 250) {
                    udpiptime.ipqueue.poll();
                    //设置
                    if (udpPacket.sec - udpiptime.ipqueue.peek() < 10) {
                        mp.setProtocol(2);
                        mp.setSrcIp(udpPacket.src_ip.toString());
                        mp.setWarnType(UDP_FLOOD);
                        mp.setWarningMsg("来自此IP的UDP数据包过多，疑似UDP洪流攻击");
                        PacketHandler.catchWarn(mp);
                    }
                }
                udpMap.put(udpPacket.src_ip.toString(), udpiptime);
            } else {
                udpiptime.ipport.put(new Integer(udpPacket.dst_port), udpPacket.sec);
                udpiptime.createtime = udpPacket.sec;
                udpiptime.ipqueue = new LinkedList<>();
                udpiptime.ipqueue.offer(udpPacket.sec);
                udpMap.put(udpPacket.src_ip.toString(), udpiptime);
            }
            //ipport存入5分钟内试图连接的端口
            for (Map.Entry<Integer, Long> entry : udpiptime.ipport.entrySet()) {
                if (udpPacket.sec - entry.getValue() >= 5 * 60 * 60) udpiptime.ipport.remove(entry.getKey());
            }
            //设置
            if (udpiptime.ipport.size() >= 500) {
                mp.setProtocol(2);
                mp.setSrcIp(udpPacket.src_ip.toString());
                mp.setWarnType(UDP_SCAN);
                mp.setWarningMsg("此IP在短时间内大量访问不同端口，疑似端口扫描");
                PacketHandler.catchWarn(mp);
            }
        }
    }


    private void ICMPChecker(ICMPPacket icmpPacket) {
        if (icmpPacket.type == 8) {
            if (icmpPacket.len > 421) {
                mp.setProtocol(3);
                mp.setSrcIp(icmpPacket.src_ip.toString());
                mp.setWarnType(ICMP_DEATH);
                mp.setWarningMsg("收到异常的ICMP报文，有可能遭遇“死亡之ping”攻击");
                PacketHandler.catchWarn(mp);
            }
            if (ifContain(icmpPacket.dst_ip.toString())) {
                mp.setProtocol(3);
                mp.setSrcIp(icmpPacket.src_ip.toString());
                mp.setWarnType(ICMP_PING);
                mp.setWarningMsg("收到ICMP_ECHO报文，某机器在试图ping通该设备");
                PacketHandler.catchWarn(mp);
            }
        }
        if (ifContain(icmpPacket.dst_ip.toString()) && !ifInWhite(icmpPacket.src_ip.toString())) {
            icmpTimeQueue.add(icmpPacket.sec);
            int f = icmpTimeQueue.average();
            if (icmpTimeQueue.last() / (icmpa * f + (1 - icmpa) * icmplevel) >= 2) {
                mp.setProtocol(3);
                mp.setSrcIp(icmpPacket.src_ip.toString());
                mp.setWarnType(ICMP_DDOS);
                mp.setWarningMsg("当前时段收到的ICMP数据包过多，疑似DDos攻击");
                PacketHandler.catchWarn(mp);
            }
            IpTime icmpiptime = new IpTime();
            if (icmpMap.containsKey(icmpPacket.src_ip.toString())) {
                icmpiptime.refreshtime = icmpPacket.sec;
                icmpiptime = icmpMap.get(icmpPacket.src_ip.toString());
                icmpiptime.ipqueue.offer(icmpPacket.sec);
                if (icmpiptime.ipqueue.size() > 250) {
                    icmpiptime.ipqueue.poll();
                    //设置
                    if (icmpPacket.sec - icmpiptime.ipqueue.peek() < 10) {
                        mp.setProtocol(3);
                        mp.setSrcIp(icmpPacket.src_ip.toString());
                        mp.setWarnType(ICMP_FLOOD);
                        mp.setWarningMsg("来自此IP的ICMP数据包过多，疑似ICMP洪流攻击");
                        PacketHandler.catchWarn(mp);
                    }
                }
                icmpMap.put(icmpPacket.src_ip.toString(), icmpiptime);
            } else {
                icmpiptime.createtime = icmpPacket.sec;
                icmpiptime.ipqueue = new LinkedList<>();
                icmpiptime.ipqueue.offer(icmpPacket.sec);
                icmpMap.put(icmpPacket.src_ip.toString(), icmpiptime);
            }
        }
    }

    private void ARPChecker(ARPPacket arpPacket) {
        if (ARPChart.containsKey(arpPacket.getSenderProtocolAddress().toString())) {//如果ARP表中有记录

            if (!arpPacket.getSenderHardwareAddress().toString().equals(ARPChart.get(arpPacket.getSenderProtocolAddress().toString()))) {//如果包中的源MAC地址与表中记录的MAC地址不相同

                if (!arpPacket.getSenderProtocolAddress().toString().equals("/0.0.0.0")) {
                    String target = "";
                    for (String key : ARPChart.keySet()) {//尝试查找对应IP
                        if (ARPChart.get(key).equals(arpPacket.getSenderHardwareAddress().toString())) {
                            target = key;
                            break;
                        }
                    }
                    if (!target.equals("")) {
                        target = "</br>表中MAC地址" + arpPacket.getSenderHardwareAddress() + "&nbsp;对应IP地址：" + target;
                    }
                    mp.setProtocol(4);
                    mp.setSrcIp(arpPacket.sender_protoaddr.toString());
                    mp.setWarnType(ARP_CHEAT);
                    mp.setWarningMsg("该ARP包中源IP地址与MAC地址和ARP表中记录不符,疑似发生ARP欺骗" + target);
                    PacketHandler.catchWarn(mp);
                }
            }
        } else {
            ARPChart.put(arpPacket.getSenderProtocolAddress().toString(), arpPacket.getSenderHardwareAddress().toString());//记录进ARP表
        }
    }

}
