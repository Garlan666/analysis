package com.network.analysis.catchPacket;

import com.network.analysis.entity.myPacket;
import jpcap.packet.*;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.locks.Lock;

/**
 * Created by Garlan on 2019/6/13.
 */
public class PacketChecker extends Thread {

    private Queue<Packet> packets = new ConcurrentLinkedDeque<>();
    private myPacket mp;
    private InetAddress inetAddress;//本机网络信息
    private Map<String, String> ARPChart = new HashMap();//HashMap摸拟ARP表

    @Override
    public void run() {
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

    public void setInetAddress(InetAddress inetAddress) {
        this.inetAddress = inetAddress;
        ARPChart.put("/" + this.inetAddress.getHostAddress(), getMACAddress(this.inetAddress));
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

    private void TCPChecker(TCPPacket tcpPacket) {
//        mp.setProtocol(1);
//        PacketHandler.catchWarn(mp);
    }

    private void UDPChecker(UDPPacket udpPacket) {
//        mp.setProtocol(2);
//        PacketHandler.catchWarn(mp);
    }


    private void ICMPChecker(ICMPPacket icmpPacket) {
//        mp.setProtocol(3);
//        PacketHandler.catchWarn(mp);
    }

    private void ARPChecker(ARPPacket arpPacket) {
        if (ARPChart.containsKey(arpPacket.getSenderProtocolAddress().toString())) {//如果ARP表中有记录
            if (!arpPacket.getSenderHardwareAddress().equals(ARPChart.get(arpPacket.getSenderProtocolAddress().toString()))) {//如果包中的源MAC地址与表中记录的MAC地址不相同
                if (!arpPacket.getSenderProtocolAddress().equals("0.0.0.0")) {
                    String target = "";
                    for (String key : ARPChart.keySet()) {//尝试查找对应IP
                        if (ARPChart.get(key).equals(arpPacket.getSenderHardwareAddress())) {
                            target = key;
                            break;
                        }
                    }
                    if (!target.equals("")) {
                        target = "</br>表中MAC地址" + arpPacket.getSenderHardwareAddress() + "&nbsp;对应IP地址：" + target;
                    }
                    mp.setProtocol(4);
                    mp.setWarningMsg("该ARP包中源IP地址与MAC地址和ARP表中记录不符,疑似ARP欺骗" + target);
                    PacketHandler.catchWarn(mp);
                }
            }
        } else {
            ARPChart.put(arpPacket.getSenderProtocolAddress().toString(), arpPacket.getSenderHardwareAddress().toString());//记录进ARP表
        }
    }

}
