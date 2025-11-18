package com.cloudbees.compliance.plugins.zap.grpc.server;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import com.cloudbees.compliance.plugins.zap.auth.ZapAuthManager;
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthServerInfo;
import com.cloudbees.compliance.plugins.zap.components.ZapAddOn;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;
import com.google.protobuf.ByteString;

@ComponentScan({ "com.cloudbees" })
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"grpc.inProcessName=6", // Enable inProcess server
		"grpc.port=2", // Disable external server
		"grpc.client.inProcess.address=in-process:6" // Configure the client to connect to the inProcess
																// server
})
class ZapAddOnTest extends  ZapAddOn{
	
	
	private ZapAddOn addOn = mock(ZapAddOn.class);
	
	@MockBean
	@Qualifier("universalRestTemplate")
	RestTemplate restTemplate;
	
	private ZapAuthServerInfo authServerInfo;
	
	@Autowired
	ZapAuthManager zapAuthManager;
	
	@Autowired
	ZapUtil utils;
	
	private static final Logger logger = LoggerFactory.getLogger(ScriptAuthServiceImplTest.class);
	

	@Test
	void installAddon_Test() {
		logger.debug("Enter installAddon_Test");
		ByteString metadata = ByteString
				.copyFromUtf8("{\"zapAddress\":\"localhost\",\"zapPort\":8082,\"apiKey\":\"xxxxxxxxxxxx\"}");	
		authServerInfo = zapAuthManager.getZapAuthFromString(metadata);
		ReflectionTestUtils.setField(zapAuthManager, "zapAuthServerInfo", authServerInfo);
		ReflectionTestUtils.setField(utils, "authManager", zapAuthManager);
		String url = "/autoupdate/action/installAddon";		
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));	
		
		addOn.installAddon("2");
		verify(addOn,times(1)).installAddon("2");
		installAddon("2");
		logger.debug("Exit installAddon_Test");
	}
	
	@Test
	void installAddon_Test_Err() {
		logger.debug("Enter installAddon_Test_Err");
		String url = "/autoupdate/action/installAddon";		
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));	
		
		addOn.installAddon("2");
		verify(addOn,times(1)).installAddon("2");
		installAddon("2");
		logger.debug("Exit installAddon_Test_Err");
	}

}
