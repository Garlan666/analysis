package com.network.analysis.catchPacket;

import com.network.analysis.entity.Attack;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Created by Garlan on 2019/6/18.
 */
public class PacketSender extends Thread {
    private NetworkInterface networkInterface;
    private JpcapSender sender;
    private Attack attack;

    public PacketSender(NetworkInterface nc, Attack attack) throws IOException {
        this.attack = attack;
        this.networkInterface = nc;
        sender = JpcapSender.openDevice(networkInterface);
    }


    //构造MAC地址byte数组
    public static byte[] stomac(String s) {
        byte[] mac = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        String[] s1 = s.split("-");
        for (int x = 0; x < s1.length; x++) {
            mac[x] = (byte) ((Integer.parseInt(s1[x], 16)) & 0xff);
        }
        return mac;
    }

    @Override
    public void run() {
        try {
            switch (attack.getType()) {
                case 1:
                    sendARPRequest(attack.getRound(), attack.getSleep(), attack.getSpeed(), attack.getSrcIp(), attack.getSrcMac(), attack.getDesIp());
                    break;
                case 2:
                    sendARPReply(attack.getRound(), attack.getSleep(), attack.getSpeed(), attack.getSrcIp(), attack.getSrcMac(), attack.getDesIp(), attack.getDesMac());
                    break;
                case 3:
                    sendPINGRequest(10, 0, 1, "125.216.246.33", "a0-8c-fd-4f-c0-45", "125.216.246.30", "98-e7-f4-4b-f1-e3");
                    break;
                case 4:
                    sendPINGReply(10, 0, 1, "125.216.246.33", "a0-8c-fd-4f-c0-45", "125.216.246.30", "98-e7-f4-4b-f1-e3");
                    break;
                case 5:
                    sendTCP(10, 0, 1, "125.216.246.33", "a0-8c-fd-4f-c0-45", "125.216.246.30", "98-e7-f4-4b-f1-e3",10000,10000);
                    break;
                case 6:
                    sendUDP(10, 0, 1, "125.216.246.33", "a0-8c-fd-4f-c0-45", "125.216.246.30", "98-e7-f4-4b-f1-e3",888,80);
                    break;
            }

        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    //ARP应答
    private void sendARPReply(int round, int sleep, int speed, String srcIp, String srcMac, String desIp, String desMac) throws UnknownHostException {

        InetAddress srcip = InetAddress.getByName(srcIp);
        byte[] srcmac = stomac(srcMac);

        //"a0-8c-fd-4f-c0-45"

        InetAddress desip = InetAddress.getByName(desIp);
        byte[] desmac = stomac(desMac);
        // 设置ARP包
        ARPPacket arp = new ARPPacket();
        arp.hardtype = ARPPacket.HARDTYPE_ETHER;
        arp.prototype = ARPPacket.PROTOTYPE_IP;

        // ARPPacket.ARP_REPLY用于接受MAC地址
        arp.operation = ARPPacket.ARP_REPLY;
        arp.hlen = 6;
        arp.plen = 4;
        arp.sender_hardaddr = srcmac;
        arp.sender_protoaddr = srcip.getAddress();
        arp.target_hardaddr = desmac;
        arp.target_protoaddr = desip.getAddress();

        // 设置DLC帧
        EthernetPacket ether = new EthernetPacket();
        ether.frametype = EthernetPacket.ETHERTYPE_ARP;
        ether.src_mac = srcmac;
        ether.dst_mac = desmac;
        arp.datalink = ether;
        System.out.println("Send Arp To IPAddr: " + arp.getSenderProtocolAddress());
        while (round >= 0) {
            for (int i = 0; i < speed; i++) {
                sender.sendPacket(arp);
            }
            round--;
            try {
                if (sleep > 0)
                    sleep(sleep);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    //ARP请求
    private void sendARPRequest(int round, int sleep, int speed, String srcIp, String srcMac, String desIp) throws UnknownHostException {
        byte[] broadcast = stomac("ff-ff-ff-ff-ff-ff");
        InetAddress srcip = InetAddress.getByName(srcIp);
        byte[] srcmac = stomac(srcMac);

        // 设置需要向其发送ARP请求的主机IP
        InetAddress desip = InetAddress.getByName(desIp);
        ARPPacket arpPacket = new ARPPacket();
        arpPacket.hardtype = ARPPacket.HARDTYPE_ETHER;
        arpPacket.prototype = ARPPacket.PROTOTYPE_IP;

        // ARP_REQUEST用于请求目标主机的MAC地址
        arpPacket.operation = ARPPacket.ARP_REQUEST;
        arpPacket.hlen = 6;
        arpPacket.plen = 4;
        arpPacket.sender_hardaddr = srcmac;
        arpPacket.sender_protoaddr = srcip.getAddress();
        arpPacket.target_hardaddr = broadcast;
        arpPacket.target_protoaddr = desip.getAddress();

        EthernetPacket ether = new EthernetPacket();
        ether.frametype = EthernetPacket.ETHERTYPE_ARP;
        ether.src_mac = srcmac;
        ether.dst_mac = broadcast;
        arpPacket.datalink = ether;

        while (round >= 0) {
            for (int i = 0; i < speed; i++) {
                sender.sendPacket(arpPacket);
                System.out.println("Send Arp To IPAddr: " + "broadcast");
            }
            round--;
            try {
                if (sleep > 0)
                    sleep(sleep);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }


    //PING请求
    private void sendPINGRequest(int round, int sleep, int speed, String srcIp, String srcMac, String desIp, String desMac) throws UnknownHostException {
        InetAddress srcip = InetAddress.getByName(srcIp);
        byte[] srcmac = stomac(srcMac);

        InetAddress desip = InetAddress.getByName(desIp);
        byte[] desmac = stomac(desMac);


        ICMPPacket icmpPacket = new ICMPPacket();

        icmpPacket.usec = 888888;
        icmpPacket.protocol = 1;
        icmpPacket.type = ICMPPacket.ICMP_ECHO;
        icmpPacket.seq = (short) 0x0005;
        icmpPacket.id = (short) 0x0006;

        icmpPacket.setIPv4Parameter(0, false, false, false, 0, false, false,
                false, 0, 1010101, 100, IPPacket.IPPROTO_ICMP, srcip, desip);

        icmpPacket.data = "abcdefghijklmnopqrstuvwabcdefghi".getBytes();

        EthernetPacket ether = new EthernetPacket();
        ether.frametype = EthernetPacket.ETHERTYPE_IP;
        ether.src_mac = srcmac;
        ether.dst_mac = desmac;
        icmpPacket.datalink = ether;


        System.out.println("Send PING request to " + icmpPacket.dst_ip);

        while (round >= 0) {
            for (int i = 0; i < speed; i++) {
                icmpPacket.sec = System.currentTimeMillis() / 1000;
                icmpPacket.ident++;
                sender.sendPacket(icmpPacket);
            }
            round--;
            try {
                if (sleep > 0)
                    sleep(sleep);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    //PING应答
    private void sendPINGReply(int round, int sleep, int speed, String srcIp, String srcMac, String desIp, String desMac) throws UnknownHostException {
        InetAddress srcip = InetAddress.getByName(srcIp);
        byte[] srcmac = stomac(srcMac);

        InetAddress desip = InetAddress.getByName(desIp);
        byte[] desmac = stomac(desMac);


        ICMPPacket icmpPacket = new ICMPPacket();

        icmpPacket.usec = 888888;
        icmpPacket.protocol = 1;
        icmpPacket.type = ICMPPacket.ICMP_ECHOREPLY;
        icmpPacket.seq = (short) 0x0005;
        icmpPacket.id = (short) 0x0006;

        icmpPacket.setIPv4Parameter(0, false, false, false, 0, false, false,
                false, 0, 1010101, 100, IPPacket.IPPROTO_ICMP, srcip, desip);

        icmpPacket.data = "abcdefghijklmnopqrstuvwabcdefghi".getBytes();


        EthernetPacket ether = new EthernetPacket();
        ether.frametype = EthernetPacket.ETHERTYPE_IP;
        ether.src_mac = srcmac;
        ether.dst_mac = desmac;
        icmpPacket.datalink = ether;

        System.out.println("Send PING reply to " + icmpPacket.dst_ip);

        while (round >= 0) {
            for (int i = 0; i < speed; i++) {
                icmpPacket.sec = System.currentTimeMillis() / 1000;
                icmpPacket.ident++;
                sender.sendPacket(icmpPacket);
            }
            round--;
            try {
                if (sleep > 0)
                    sleep(sleep);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    //UDP
    private void sendUDP(int round, int sleep, int speed, String srcIp, String srcMac, String desIp, String desMac,int srcPort,int desPort) throws UnknownHostException {
        InetAddress srcip = InetAddress.getByName(srcIp);
        byte[] srcmac = stomac(srcMac);
        InetAddress desip = InetAddress.getByName(desIp);
        byte[] desmac = stomac(desMac);

        UDPPacket udpPacket = new UDPPacket(srcPort, desPort);
        udpPacket.usec = 123456;
        udpPacket.data = "Hello world!".getBytes();

        udpPacket.setIPv4Parameter(0, false, false, false, 0, false,
                false, false, 0, 10600, 128, IPPacket.IPPROTO_UDP, srcip, desip);

        EthernetPacket ether = new EthernetPacket();
        ether.frametype = EthernetPacket.ETHERTYPE_IP;
        ether.src_mac = srcmac;
        ether.dst_mac = desmac;
        udpPacket.datalink = ether;


        System.out.println("Send UDP to " + udpPacket.dst_ip);

        while (round >= 0) {
            for (int i = 0; i < speed; i++) {
                udpPacket.sec = System.currentTimeMillis() / 1000;
                sender.sendPacket(udpPacket);
            }
            round--;
            try {
                if (sleep > 0)
                    sleep(sleep);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    //TCP
    private void sendTCP(int round, int sleep, int speed, String srcIp, String srcMac, String desIp, String desMac,int srcPort,int desPort) throws UnknownHostException {
        InetAddress srcip = InetAddress.getByName(srcIp);
        byte[] srcmac = stomac(srcMac);
        InetAddress desip = InetAddress.getByName(desIp);
        byte[] desmac = stomac(desMac);


        TCPPacket tcpPacket = new TCPPacket(srcPort, desPort, 123, 0, false, false, false, false,
                true, false, false, false, 2, 0);
        tcpPacket.data = "Hello world!".getBytes();
        tcpPacket.setIPv4Parameter(0, false, false, false, 0, false,
                false, false, 0, 10600, 64, IPPacket.IPPROTO_TCP, srcip, desip);

        EthernetPacket ether = new EthernetPacket();
        ether.frametype = EthernetPacket.ETHERTYPE_IP;
        ether.src_mac = srcmac;
        ether.dst_mac = desmac;
        tcpPacket.datalink = ether;

        while (round >= 0) {
            for (int i = 0; i < speed; i++) {
                sender.sendPacket(tcpPacket);
            }
            round--;
            try {
                if (sleep > 0)
                    sleep(sleep);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
