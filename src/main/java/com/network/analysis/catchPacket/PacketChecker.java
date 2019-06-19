package com.network.analysis.catchPacket;

import com.network.analysis.entity.myPacket;
import com.network.analysis.entity.timeQueue;
import com.sun.jmx.snmp.tasks.ThreadService;
import jpcap.packet.*;

import java.io.IOException;
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
    private ArrayList<InetAddress> inetAddress=new ArrayList<InetAddress>();//本机网络信息
    private Map<String, String> ARPChart = new HashMap();//HashMap摸拟ARP表
    private timeQueue tcptimequeue;
    private timeQueue udpTimeQueue;
    private int flevel;   //syn报文正常参考数量
    private double a;    //平滑参数


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

    private void init(){
        getInetAddress();

        for(int i=0;i<inetAddress.size();i++){
            ARPChart.put(inetAddress.get(i).getHostAddress(),getMACAddress(inetAddress.get(i)));
        }

        runTask();

        tcptimequeue=new timeQueue(6,2);
        flevel=8000;   //syn报文正常参考数量
        a=0.5;    //平滑参数


        udpTimeQueue = new timeQueue(6, 2);

    }


    private void getInetAddress(){

        try {
            for (Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces(); interfaces.hasMoreElements(); ) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (networkInterface.isLoopback() || networkInterface.isVirtual() || !networkInterface.isUp()) {
                    continue;
                }
                Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                if (addresses.hasMoreElements()) {
                    InetAddress t=addresses.nextElement();
                    if(t.getHostAddress().startsWith("169.254.")){
                        continue;
                    }
                   inetAddress.add(t);
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
    }

    private boolean ifContain(String ip){
        for(int i=0;i<inetAddress.size();i++){
            if(ip.equals("/"+inetAddress.get(i).getHostAddress())){
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
        HashMap<Integer,Long>ipport=new HashMap<>();
        long createtime=0;//hash连接创建时间
        long refreshtime=0;//上次刷新时间
//        int min=400;
    }

    HashMap<String, IpTime> tcpmap = new HashMap<>();
    HashMap<String, IpTime> udpMap = new HashMap<>();
    //每10分钟检查一次tcpmap，如果存在iptime 10分钟未刷新，删除键值对,清空ipqueue和ipport
    private void runTask() {
        final long timeInterval = 10*60*60;
        Runnable runnable = new Runnable() {
            public void run() {
                while (true) {
                    for (Map.Entry<String,IpTime> entry : tcpmap.entrySet()) {
                        if(entry.getValue().refreshtime-entry.getValue().createtime>=timeInterval) {
                            entry.getValue().ipqueue=null;
                            tcpmap.remove(entry.getKey());
                        }
                    }
                    for (Map.Entry<String,IpTime> entry : udpMap.entrySet()) {
                        if(entry.getValue().refreshtime-entry.getValue().createtime>=timeInterval)
                            udpMap.remove(entry.getKey());
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
int max=0;

    public void TCPChecker(TCPPacket tcpPacket) {
        if (ifContain(tcpPacket.dst_ip.toString())&&!tcpPacket.src_ip.toString().equals("/202.38.193.65")) {
            if (tcpPacket.syn) {
                if (tcpPacket.src_ip == tcpPacket.dst_ip) {
                    mp.setProtocol(1);
                    mp.setWarningMsg("此报文源IP与目的IP相同，疑似Land攻击");
                    PacketHandler.catchWarn(mp);
                }
                tcptimequeue.add(tcpPacket.sec);
                int f = tcptimequeue.average();
                if (tcptimequeue.last() / (a * f + (1 - a) * flevel) >= 2) {
                    mp.setProtocol(1);
                    mp.setWarningMsg("当前时段SYN请求过多，疑似DDos攻击");
                    PacketHandler.catchWarn(mp);
                }
                IpTime iptime = new IpTime();
                if (tcpmap.containsKey(tcpPacket.src_ip.toString())) {
                    iptime.refreshtime=tcpPacket.sec;
                    iptime = tcpmap.get(tcpPacket.src_ip.toString());
                    iptime.ipqueue.offer(tcpPacket.sec);
                    iptime.ipport.put(new Integer(tcpPacket.dst_port),tcpPacket.sec);
                    if (iptime.ipqueue.size() > 250) {
                        iptime.ipqueue.poll();
//                        if(tcpPacket.sec-iptime.ipqueue.peek()<iptime.min)iptime.min=(int)(tcpPacket.sec-iptime.ipqueue.peek());
//                        System.out.println(tcpPacket.src_ip+" "+iptime.min);
                        if (tcpPacket.sec - iptime.ipqueue.peek() < 10) {
                            //syn洪流报警
                            mp.setProtocol(1);
                            mp.setWarningMsg("此IP的SYN请求过多，疑似SYN洪流攻击");
                            PacketHandler.catchWarn(mp);
                        }
                    }
                    tcpmap.put(tcpPacket.src_ip.toString(), iptime);
                }
                else {
                    iptime.ipport.put(new Integer(tcpPacket.dst_port),tcpPacket.sec);
                    iptime.createtime=tcpPacket.sec;
                    iptime.ipqueue = new LinkedList<>();
                    iptime.ipqueue.offer(tcpPacket.sec);
                    tcpmap.put(tcpPacket.src_ip.toString(), iptime);
                }
                //ipport存入5分钟内试图连接的端口
                for (Map.Entry<Integer,Long> entry : iptime.ipport.entrySet()) {
                    if(tcpPacket.sec-entry.getValue()>=5*60*60)iptime.ipport.remove(entry.getKey());
                }
                if(iptime.ipport.size()>max)max=iptime.ipport.size();
                if(iptime.ipport.size()>=100){
                    mp.setProtocol(1);
                    mp.setWarningMsg("此IP在短时间内大量访问不同端口，疑似端口扫描");
                    PacketHandler.catchWarn(mp);
                }
            }
            if ((tcpPacket.fin&&tcpPacket.urg&&tcpPacket.psh)||(tcpPacket.fin && tcpPacket.syn) || (!tcpPacket.syn && !tcpPacket.fin && !tcpPacket.ack && !tcpPacket.psh && !tcpPacket.rst && !tcpPacket.urg)) {
                mp.setProtocol(1);
                mp.setWarningMsg("此报文非法，疑似扫描");
                PacketHandler.catchWarn(mp);
            }

        }
//        mp.setProtocol(1);
//        PacketHandler.catchWarn(mp);
    }

    private void UDPChecker(UDPPacket udpPacket) {
        if (ifContain(udpPacket.dst_ip.toString())&&!udpPacket.src_ip.toString().equals("/202.38.193.65")){
            if (udpPacket.src_ip == udpPacket.dst_ip) {
                mp.setProtocol(2);
                mp.setWarningMsg("此报文源IP与目的IP相同，疑似Land攻击");
                PacketHandler.catchWarn(mp);
            }
            udpTimeQueue.add(udpPacket.sec);
            int f2 = udpTimeQueue.average();
            if (udpTimeQueue.last() / (a * f2 + (1 - a) * flevel) >= 2) {
                mp.setProtocol(2);
                mp.setWarningMsg("当前时段收到的UDP数据包过多，疑似DDos攻击");
                PacketHandler.catchWarn(mp);
            }
            IpTime udpiptime = new IpTime();
            if (udpMap.containsKey(udpPacket.src_ip.toString())) {
                udpiptime.refreshtime=udpPacket.sec;
                udpiptime = udpMap.get(udpPacket.src_ip.toString());
                udpiptime.ipqueue.offer(udpPacket.sec);
                udpiptime.ipport.put(new Integer(udpPacket.dst_port),udpPacket.sec);
                if (udpiptime.ipqueue.size() > 250) {
                    udpiptime.ipqueue.poll();
//                        if(tcpPacket.sec-iptime.ipqueue.peek()<iptime.min)iptime.min=(int)(tcpPacket.sec-iptime.ipqueue.peek());
//                        System.out.println(tcpPacket.src_ip+" "+iptime.min);
                    if (udpPacket.sec - udpiptime.ipqueue.peek() < 10) {
                        //udp洪流报警
                        mp.setProtocol(2);
                        mp.setWarningMsg("来自此IP的UDP数据包过多，疑似UDP洪流攻击");
                        PacketHandler.catchWarn(mp);
                    }
                }
                udpMap.put(udpPacket.src_ip.toString(), udpiptime);
            }
            else {
                udpiptime.ipport.put(new Integer(udpPacket.dst_port),udpPacket.sec);
                udpiptime.createtime=udpPacket.sec;
                udpiptime.ipqueue = new LinkedList<>();
                udpiptime.ipqueue.offer(udpPacket.sec);
                udpMap.put(udpPacket.src_ip.toString(), udpiptime);
            }
            //ipport存入5分钟内试图连接的端口
            for (Map.Entry<Integer,Long> entry : udpiptime.ipport.entrySet()) {
                if(udpPacket.sec-entry.getValue()>=5*60*60)udpiptime.ipport.remove(entry.getKey());
            }
            if(udpiptime.ipport.size()>max)max=udpiptime.ipport.size();
            if(udpiptime.ipport.size()>=100){
                mp.setProtocol(2);
                mp.setWarningMsg("此IP在短时间内大量访问不同端口，疑似端口扫描");
                PacketHandler.catchWarn(mp);
            }
        }
    }


    private void ICMPChecker(ICMPPacket icmpPacket) {
        if (icmpPacket.len > 65535) {
            mp.setProtocol(3);
            mp.setWarningMsg("收到一个异常的ICMP报文，有可能遭遇“死亡之ping”攻击");
            PacketHandler.catchWarn(mp);
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
                    mp.setWarningMsg("该ARP包中源IP地址与MAC地址和ARP表中记录不符,疑似发生ARP欺骗" + target);
                    PacketHandler.catchWarn(mp);
                }
            }
        } else {
            ARPChart.put(arpPacket.getSenderProtocolAddress().toString(), arpPacket.getSenderHardwareAddress().toString());//记录进ARP表
        }
    }

}
