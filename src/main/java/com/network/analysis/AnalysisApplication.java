package com.network.analysis;

import com.network.analysis.catchPacket.PacketServer;
import org.mybatis.spring.boot.autoconfigure.MybatisAutoConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class, MybatisAutoConfiguration.class})
public class AnalysisApplication {


    public static void main(String[] args) {

        SpringApplication.run(AnalysisApplication.class, args);
    }


}
