package com.network.analysis.server.impl;

import com.network.analysis.catchPacket.PacketServer;
import com.network.analysis.entity.Attack;
import com.network.analysis.entity.PacketInfo;
import com.network.analysis.entity.myPacket;
import com.network.analysis.entity.netInterface;
import com.network.analysis.server.NetworkServer;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;


/**
 * Created by Garlan on 2019/6/1.
 */
@Service("NetworkServer")
public class NetworkServerImpl implements NetworkServer {

    private PacketServer packetServer = new PacketServer();


    @Override
    public List<netInterface> getNetworkInterface() {
        return packetServer.getInterface();
    }

    @Override
    public boolean startCatchPacket(int index,boolean promisc) {
        return packetServer.startCatchPacket(index,promisc);
    }

    @Override
    public PacketInfo getPacketInfoPS() {
        return packetServer.getPacketInfo();
    }

    @Override
    public boolean stopCatch(int index) {
        return packetServer.stopCatch(index);
    }

    @Override
    public List<myPacket> getWarn(int offset) {
        return packetServer.getWarn(offset);
    }

    @Override
    public boolean packetAttack(int index, Attack attack){return packetServer.packetAttack(index,attack);}

    @Override
    public ArrayList<String>getWhiteList(){
        return packetServer.getWhiteList();
    }

    @Override
    public void addWhite(String ip){
        packetServer.addWhite(ip);
    }

    @Override
    public void removeWhite(String ip){
        packetServer.removeWhite(ip);
    }



}
