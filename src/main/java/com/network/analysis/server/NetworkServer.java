package com.network.analysis.server;


import com.network.analysis.entity.PacketInfo;
import com.network.analysis.entity.myPacket;
import com.network.analysis.entity.netInterface;

import java.util.List;

/**
 * Created by Garlan on 2019/6/1.
 */
public interface NetworkServer {

    List<netInterface> getNetworkInterface();

    boolean startCatchPacket(int index,boolean promisc);

    PacketInfo getPacketInfoPS();

    boolean stopCatch(int index);

    List<myPacket> getWarn(int offset);

}
