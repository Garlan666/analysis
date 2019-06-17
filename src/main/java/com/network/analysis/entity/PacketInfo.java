package com.network.analysis.entity;

/**
 * Created by Garlan on 2019/6/13.
 */
public class PacketInfo {
    private int total;
    private int [] kind;
    private double lenTotal;
    private double [] lenKind;

    public PacketInfo(int total,int []kind,double lenTotal,double []lenKind){
        this.total=total;
        this.kind=kind;
        this.lenTotal=lenTotal;
        this.lenKind=lenKind;
    }

    public int[] getKind() {
        return kind;
    }

    public void setKind(int[] kind) {
        this.kind = kind;
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public double getLenTotal() {
        return lenTotal;
    }

    public void setLenTotal(double lenTotal) {
        this.lenTotal = lenTotal;
    }

    public double[] getLenKind() {
        return lenKind;
    }

    public void setLenKind(double[] lenKind) {
        this.lenKind = lenKind;
    }
}
