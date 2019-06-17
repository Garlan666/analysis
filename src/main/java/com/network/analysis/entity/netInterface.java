package com.network.analysis.entity;

import com.network.analysis.catchPacket.PacketHandler;
import com.network.analysis.catchPacket.PacketServer;

/**
 * Created by Garlan on 2019/6/2.
 */
public class netInterface {
    private String name;
    private String description;
    private String datalink_name;
    private String datalink_description;
    private String address;
    private boolean loopback;
    private boolean promisc;

    private boolean on;

    public netInterface(String name,String description,String datalink_name,String datalink_description,String address,boolean loopback){
        this.name=name;
        this.description=description;
        this.datalink_name=datalink_name;
        this.datalink_description=datalink_description;
        this.address=address;
        this.loopback=loopback;
        this.on=false;
        this.promisc=false;
    }


    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isOn() {
        return on;
    }

    public void setOn(boolean on) {
        this.on = on;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDatalink_name() {
        return datalink_name;
    }

    public void setDatalink_name(String datalink_name) {
        this.datalink_name = datalink_name;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getDatalink_description() {
        return datalink_description;
    }

    public void setDatalink_description(String datalink_description) {
        this.datalink_description = datalink_description;
    }

    public boolean getLoopback() {
        return loopback;
    }

    public void setLoopback(boolean loopback) {
        this.loopback = loopback;
    }

    public boolean isPromisc() {
        return promisc;
    }

    public void setPromisc(boolean promisc) {
        this.promisc = promisc;
    }
}
