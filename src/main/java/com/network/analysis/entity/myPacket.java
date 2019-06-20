package com.network.analysis.entity;

import jpcap.packet.Packet;

import java.net.InetAddress;

/**
 * Created by Garlan on 2019/6/13.
 */
public class myPacket {
    private int protocol;
    private int warnType;
    private Packet packet;
    private String srcIp;

    private String warningMsg;

    public myPacket(Packet packet){
        this.packet=packet;
    }

    public myPacket(int protocol){
        this.protocol=protocol;
    }

    public int getProtocol() {
        return protocol;
    }

    public void setProtocol(int protocol) {
        this.protocol = protocol;
    }

    public String getWarningMsg() {
        return warningMsg;
    }

    public void setWarningMsg(String warningMsg) {
        this.warningMsg = warningMsg;
    }

    public Packet getPacket() {
        return packet;
    }

    public void setPacket(Packet packet) {
        this.packet = packet;
    }

    public int getWarnType() {
        return warnType;
    }

    public void setWarnType(int warnType) {
        this.warnType = warnType;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public void setSrcIp(String srcIp) {
        this.srcIp = srcIp;
    }


    public myPacket(myPacket m) {
        this.protocol = m.protocol;
        this.warnType = m.warnType;
        this.packet = m.packet;
        this.srcIp = m.srcIp;
        this.warningMsg = m.warningMsg;
    }
}
