package com.network.analysis.catchPacket;


import jpcap.packet.*;

/**
 * Created by Garlan on 2019/6/1.
 */
public class PacketReceiver implements jpcap.PacketReceiver {

    public void receivePacket(Packet packet) {
        PacketHandler.packetNumTotal++;
        double len=(double)packet.len/1024;
        PacketHandler.packetLenTotal+=len;
        PacketHandler.check(packet);

        //Tcp包,在java Socket中只能得到负载数据
        if (packet instanceof jpcap.packet.TCPPacket) {
//            TCPPacket p = (TCPPacket) packet;
//            String s = "TCPPacket:| dst_ip " + p.dst_ip + ":" + p.dst_port
//                    + "|src_ip " + p.src_ip + ":" + p.src_port
//                    + " |len: " + p.len;
            //System.out.println(s);
            PacketHandler.packetNumKind[0]++;
            PacketHandler.packetLenKind[0]+=len;
        }
        //UDP包,开着QQ,你就会看到:它是tcp+udp
        else if (packet instanceof jpcap.packet.UDPPacket) {
//            UDPPacket p = (UDPPacket) packet;
//            String s = "UDPPacket:| dst_ip " + p.dst_ip + ":" + p.dst_port
//                    + "|src_ip " + p.src_ip + ":" + p.src_port
//                    + " |len: " + p.len;
            //System.out.println(s);
            PacketHandler.packetNumKind[1]++;
            PacketHandler.packetLenKind[1]+=len;
        }
        //如果你要在程序中构造一个ping报文,就要构建ICMPPacket包
        else if (packet instanceof jpcap.packet.ICMPPacket) {
//            ICMPPacket p = (ICMPPacket) packet;
//            //ICMP包的路由链
//            String router_ip = "";
//            for (int i = 0; i < p.router_ip.length; i++) {
//                router_ip += " " + p.router_ip[i].getHostAddress();
//            }
//            String s = "@ @ @ ICMPPacket:| router_ip " + router_ip
//                    + " |redir_ip: " + p.redir_ip
//                    + " |mtu: " + p.mtu
//                    + " |length: " + p.len;
            //System.out.println(s);
            PacketHandler.packetNumKind[2]++;
            PacketHandler.packetLenKind[2]+=len;
        }
        //是否地址转换协议请求包
        else if (packet instanceof jpcap.packet.ARPPacket) {
//            ARPPacket p = (ARPPacket) packet;
//            //Returns the hardware address (MAC address) of the sender
//            Object saa = p.getSenderHardwareAddress();
//            Object taa = p.getTargetHardwareAddress();
//            String s = "* * * ARPPacket:| SenderHardwareAddress " + saa
//                    + "|TargetHardwareAddress " + taa
//                    + " |len: " + p.len;
            //System.out.println(s);
            PacketHandler.packetNumKind[3]++;
            PacketHandler.packetLenKind[3]+=len;
        }
        //取得链路层数据头 :如果你想局网抓包或伪造数据包
        DatalinkPacket datalink = packet.datalink;
        //如果是以太网包
        if (datalink instanceof jpcap.packet.EthernetPacket) {
//            EthernetPacket ep = (EthernetPacket) datalink;
//            String s = "  datalink layer packet: "
//                    + "|DestinationAddress: " + ep.getDestinationAddress()
//                    + "|SourceAddress: " + ep.getSourceAddress();
            //System.out.println(s);
            PacketHandler.packetNumKind[4]++;
            PacketHandler.packetLenKind[4]+=len;
        }
    }
}
