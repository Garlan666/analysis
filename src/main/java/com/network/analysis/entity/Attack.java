package com.network.analysis.entity;

/**
 * Created by Garlan on 2019/6/18.
 */
public class Attack {
    private int type;//攻击种类
    private int round;//攻击轮数
    private int speed;//每轮攻击次数
    private int sleep;//每轮攻击暂停时间
    private String srcIp;
    private String srcMac;
    private int srcPort;
    private String desIp;
    private String desMac;
    private int desPort;

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public int getRound() {
        return round;
    }

    public void setRound(int round) {
        this.round = round;
    }

    public int getSpeed() {
        return speed;
    }

    public void setSpeed(int speed) {
        this.speed = speed;
    }

    public int getSleep() {
        return sleep;
    }

    public void setSleep(int sleep) {
        this.sleep = sleep;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public void setSrcIp(String srcIp) {
        this.srcIp = srcIp;
    }

    public String getSrcMac() {
        return srcMac;
    }

    public void setSrcMac(String srcMac) {
        this.srcMac = srcMac;
    }

    public String getDesIp() {
        return desIp;
    }

    public void setDesIp(String desIp) {
        this.desIp = desIp;
    }

    public String getDesMac() {
        return desMac;
    }

    public void setDesMac(String desMac) {
        this.desMac = desMac;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDesPort() {
        return desPort;
    }

    public void setDesPort(int desPort) {
        this.desPort = desPort;
    }

}
