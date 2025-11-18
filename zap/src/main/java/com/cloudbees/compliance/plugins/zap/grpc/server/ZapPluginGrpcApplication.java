package com.cloudbees.compliance.plugins.zap.grpc.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan({ "com.cloudbees" })
public class ZapPluginGrpcApplication {

	private static final Logger LOGGER = LoggerFactory.getLogger(ZapPluginGrpcApplication.class);

	public static void main(String[] args) {
		LOGGER.info("Starting ZAP DAST Plugin");
		  SpringApplication.run(ZapPluginGrpcApplication.class, args);


	}
}
