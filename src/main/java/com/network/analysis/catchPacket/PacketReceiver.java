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
            PacketHandler.packetNumKind[0]++;
            PacketHandler.packetLenKind[0]+=len;
        }
        //UDP包,开着QQ,你就会看到:它是tcp+udp
        else if (packet instanceof jpcap.packet.UDPPacket) {
            PacketHandler.packetNumKind[1]++;
            PacketHandler.packetLenKind[1]+=len;
        }
        //如果你要在程序中构造一个ping报文,就要构建ICMPPacket包
        else if (packet instanceof jpcap.packet.ICMPPacket) {
            PacketHandler.packetNumKind[2]++;
            PacketHandler.packetLenKind[2]+=len;
        }
        //是否地址转换协议请求包
        else if (packet instanceof jpcap.packet.ARPPacket) {
            PacketHandler.packetNumKind[3]++;
            PacketHandler.packetLenKind[3]+=len;
        }
        //取得链路层数据头 :如果你想局网抓包或伪造数据包
        DatalinkPacket datalink = packet.datalink;
        //如果是以太网包
        if (datalink instanceof jpcap.packet.EthernetPacket) {
            PacketHandler.packetNumKind[4]++;
            PacketHandler.packetLenKind[4]+=len;
        }
    }
}
