package com.network.analysis.catchPacket;

import com.network.analysis.entity.PacketInfo;
import com.network.analysis.entity.myPacket;
import jpcap.JpcapCaptor;
import jpcap.packet.Packet;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.locks.Lock;

/**
 * Created by Garlan on 2019/6/1.
 */
public class PacketHandler {

    public static int packetNumTotal = 0;
    public static int[] packetNumKind = new int[]{0, 0, 0, 0, 0};
    public static double packetLenTotal = 0;
    public static double[] packetLenKind = new double[]{0, 0, 0, 0, 0};
    public static List<myPacket> warnPacketList = new ArrayList<>();//可疑数据包列表
    public static List<myPacket> warnMessageList=new ArrayList<>();//可疑消息列表
    public static PacketChecker packetChecker = new PacketChecker();//数据包检查线程

    private JpcapCaptor jp = null;
    private File file;
    private static FileWriter fileWriter;

    private static SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd_HH mm ss");//设置日期格式
    private static SimpleDateFormat df=new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public PacketHandler() {
        packetChecker.start();//启动检查线程
    }

    //开始抓包
    public void startCapThread(final JpcapCaptor jpcap) {
        jp = jpcap;
        java.lang.Runnable runner = new Runnable() {
            public void run() {
                //使用循环抓包
                jpcap.loopPacket(-1, new PacketReceiver());

            }
        };


        file = new File("log");
        if(!file.exists()){
            file.mkdirs();
        }
        file=new File("log\\"+sdf.format(new Date()) + ".txt");
        try {
            fileWriter = new FileWriter(file, false);
        } catch (IOException e) {
            e.printStackTrace();
        }

        new Thread(runner).start();//启动抓包线程
    }


    //返回数据包情况
    public PacketInfo getPacketInfo() {
        return new PacketInfo(packetNumTotal, packetNumKind, packetLenTotal, packetLenKind);
    }

    public static void savePacket(Packet packet) {
        try {
            fileWriter.append(df.format(new Date(packet.sec*1000L))+" :"+packet.toString()+"\r\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //停止抓包
    public boolean stopLoop() {
        if (jp != null) {
            jp.breakLoop();
            try {
                fileWriter.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            packetNumTotal = 0;
            packetLenTotal = 0;
            for (int i = 0; i < 5; i++) {
                packetNumKind[i] = 0;
                packetLenKind[i] = 0;
            }
            warnPacketList.clear();
            return true;
        } else {
            return false;
        }
    }

    //返回可疑数据包列表
    public List<myPacket> getWarnPacketList(int offset) {
        if(offset>warnMessageList.size())
            return null;
        return warnMessageList.subList(offset,warnMessageList.size());
    }


    public static void check(Packet packet) {
        packetChecker.addQueue(packet);//添加Packet进队列待检查
        synchronized (Lock.class) {
            Lock.class.notify();//唤醒轮询线程
        }
    }


    public static void catchWarn(myPacket mp){
        try {
            fileWriter.append(df.format(new Date(mp.getPacket().sec*1000L))+mp.getWarningMsg()+" :"+mp.getPacket().toString()+"\r\n");
            warnPacketList.add(mp);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }



}

