package com.network.analysis.entity;

import jpcap.packet.Packet;

/**
 * Created by Garlan on 2019/6/13.
 */
public class myPacket {
    private int protocol;
    private Packet packet;

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

}
