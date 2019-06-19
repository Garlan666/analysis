package com.network.analysis.controller;

import com.network.analysis.entity.Attack;
import com.network.analysis.entity.Return;
import com.network.analysis.server.NetworkServer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by Garlan on 2019/6/1.
 */
@RestController
@RequestMapping("/sys/network/")
public class AnalysisController {

    @Autowired
    private NetworkServer networkServer;

    @GetMapping(value = "getNetworkInterface")
    public Return getNetworkInterface() {
        return new Return<>(networkServer.getNetworkInterface());
    }

    @PostMapping(value = "startCatch")
    public Return startCatch(int index,boolean promisc){
        if (networkServer.startCatchPacket(index,promisc))
            return Return.SUCCESS;
        return Return.SERVER_ERROR;
    }

    @PostMapping(value = "getPacketPS")
    public Return getPacketPS(){
        return new Return<>(networkServer.getPacketInfoPS());
    }

    @PostMapping(value = "stopCatch")
    public Return stopCatch(int index){
        if(networkServer.stopCatch(index))
            return Return.SUCCESS;
        else return Return.SERVER_ERROR;
    }

    @PostMapping(value = "getWarn")
    public Return getWarn(int offset){
        return new Return<>(networkServer.getWarn(offset));
    }


    @PostMapping(value = "packetAttack")
    public Return packetAttack(int index, Attack attack){
        if(networkServer.packetAttack(index,attack))
            return Return.SUCCESS;
        else return Return.SERVER_ERROR;
    }

    @PostMapping(value = "getWhite")
    public Return getWhite(){return new Return<>(networkServer.getWhiteList());}

    @PostMapping(value = "addWhite")
    public void addWhite(String ip){
        networkServer.addWhite(ip);
    }

    @PostMapping(value = "removeWhite")
    public void removeWhite(String ip){
        networkServer.removeWhite(ip);
    }

}
