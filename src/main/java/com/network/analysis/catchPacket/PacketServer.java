package com.network.analysis.catchPacket;

import com.network.analysis.entity.Attack;
import com.network.analysis.entity.PacketInfo;
import com.network.analysis.entity.myPacket;
import com.network.analysis.entity.netInterface;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Garlan on 2019/6/3.
 */
public class PacketServer {
    private boolean working=false;
    private NetworkInterface[] devices = null;
    private List<netInterface> interfaceList = new ArrayList<>();
    private PacketHandler packetHandler=new PacketHandler();

    public PacketServer() {
        try {
            //获取本机上的网络接口对象数组
            devices = JpcapCaptor.getDeviceList();
            for (int i = 0; i < devices.length; i++) {
                NetworkInterface nc = devices[i];
                //一块卡上可能有多个地址:
                String address = "";
                for (int t = 0; t < nc.addresses.length; t++) {
                    address +=   t + ": " + nc.addresses[t].address.toString()+"</br>";
                }
                interfaceList.add(new netInterface(nc.name,nc.description,nc.datalink_name,nc.datalink_description,address,nc.loopback));

            }
            packetHandler.setInetAddress(InetAddress.getLocalHost());

        } catch (Exception ef) {
            ef.printStackTrace();
            System.out.println("显示网络接口数据失败:  " + ef);
        }
    }


    public List<netInterface> getInterface() {
        return interfaceList;
    }

    //开始抓取
    public boolean startCatchPacket(int index,boolean promisc) {
        try {
            NetworkInterface nc = devices[index];
            //创建某个卡口上的抓取对象
            JpcapCaptor jpcap = JpcapCaptor.openDevice(nc, 65535, promisc, 20);
            if(working)
                return false;
            working=true;
            packetHandler.startCapThread(jpcap);
            interfaceList.get(index).setOn(true);
            interfaceList.get(index).setPromisc(promisc);
            System.out.println("开始抓取第" + index + "个卡口上的数据");
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            working=false;
            return false;
        }
    }

    //返回数据情况
    public PacketInfo getPacketInfo() {
        return packetHandler.getPacketInfo();
    }

    //停止抓取
    public boolean stopCatch(int index) {
        if (packetHandler.stopLoop()) {
            interfaceList.get(index).setOn(false);
            working=false;
            return true;
        } else {
            return false;
        }
    }

    //返回可疑数据包列表
    public List<myPacket> getWarn(int offset) { return packetHandler.getWarnPacketList(offset); }


    public boolean packetAttack(int index, Attack attack){
        try {
            new PacketSender(devices[index],attack).start();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

}
