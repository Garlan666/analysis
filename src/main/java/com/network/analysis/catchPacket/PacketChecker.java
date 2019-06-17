package com.network.analysis.catchPacket;

import com.network.analysis.entity.myPacket;
import jpcap.packet.*;

import java.net.InetAddress;
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

    @Override
    public void run() {
        while (true) {//轮询队列是否为空
            while (!packets.isEmpty()) {
                check(packets.poll());
                //System.out.println("queue.size=" + packets.size());
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

    public void setInetAddress(InetAddress inetAddress){
        this.inetAddress=inetAddress;
    }


    public void check(Packet packet) {

        mp=new myPacket(packet);

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

    public void TCPChecker(TCPPacket tcpPacket) {
//        mp.setProtocol(1);
//        PacketHandler.catchWarn(mp);
    }

    public void UDPChecker(UDPPacket udpPacket) {
//        mp.setProtocol(2);
//        PacketHandler.catchWarn(mp);
    }


    public void ICMPChecker(ICMPPacket icmpPacket) {
//        mp.setProtocol(3);
//        PacketHandler.catchWarn(mp);
    }

    public void ARPChecker(ARPPacket arpPacket) {
        mp.setProtocol(4);
        PacketHandler.catchWarn(mp);
    }

}
