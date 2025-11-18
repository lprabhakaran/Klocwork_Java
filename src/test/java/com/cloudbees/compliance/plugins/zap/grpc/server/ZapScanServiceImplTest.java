package com.cloudbees.compliance.plugins.zap.grpc.server;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.jupiter.api.BeforeEach;
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
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthConfig;
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthServerInfo;
import com.cloudbees.compliance.plugins.zap.service.impl.ZapScanServiceImpl;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.ByteString;



@ComponentScan({ "com.cloudbees" })
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"grpc.inProcessName=test5", // Enable inProcess server
		"grpc.port=6", // Disable external server
		"grpc.client.inProcess.address=in-process:test5" // Configure the client to connect to the inProcess server
})
class ZapScanServiceImplTest extends ZapScanServiceImpl {
	
	@MockBean
	@Qualifier("universalRestTemplate")
	RestTemplate restTemplate;

	private ZapAuthConfig authConfig;
	private String contextId = "3";	
	private String contextName = "test-context";
	
	private ZapAuthServerInfo authServerInfo;
	
	@Autowired
	ZapAuthManager zapAuthManager;
	
	private static final Logger LOGGER = LoggerFactory.getLogger(ZapScanServiceImplTest.class);
	
	@Autowired
	ZapUtil utils;
	
	private ZapScanServiceImpl impl = mock(ZapScanServiceImpl.class);
	
	
	@BeforeEach
	public void setUp() {		
		authConfig = mockNoAuthConfig();
		ByteString metadata = ByteString
				.copyFromUtf8("{\"zapAddress\":\"localhost\",\"zapPort\":8082,\"apiKey\":\"xxxxxxxxxxxx\"}");
	
		authServerInfo = zapAuthManager.getZapAuthFromString(metadata);
		ReflectionTestUtils.setField(utils, "authManager", zapAuthManager);
		ReflectionTestUtils.setField(zapAuthManager, "zapAuthServerInfo", authServerInfo);
		ReflectionTestUtils.setField(this, "utils", utils);
	}
	
	ZapAuthConfig mockNoAuthConfig()  {
		try {
		ObjectMapper map = new ObjectMapper();
		return map.readValue(getJsonString("src/test/resources/no-auth-config.json"), ZapAuthConfig.class);
		}catch(Exception e) {
			//ignore
		}
		return null;
	}
	
	private static String getJsonString(String jsonFilePath) {
		String result = null;

		try {
			result = new String(Files.readAllBytes(Paths.get(jsonFilePath)));
		} catch (IOException e) {
			e.printStackTrace();
		}
		return result;
	}
	
		@Test	
	 void runSpiderTest_NoAuth() {
		LOGGER.debug("start runSpiderTest_NoAuth()");
		
		String url = "/spider/action/scan/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("{scan:1}", HttpStatus.OK));
		
		String checkStatus = "/spider/view/status/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(checkStatus), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("{status:100}", HttpStatus.OK));
		
		String spiderResultsUrl = "/spider/view/results/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(spiderResultsUrl), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>(getJsonString("src/test/resources/spiderResults.json"), HttpStatus.OK));
		
		impl.runSpider(authConfig.getPathsToScan(), contextId,contextName,null);
		verify(impl,times(1)).runSpider(authConfig.getPathsToScan(), contextId,contextName,null);
		runSpider(authConfig.getPathsToScan(), contextId,contextName,null);
		LOGGER.debug("End runSpiderTest_NoAuth()");
		
	}
	
	@Test
	 void runActiveScan_NoAuth() {
		LOGGER.debug("start runActiveScan_NoAuth()");
		
		String url = "/ascan/action/scan/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("{scan:1}", HttpStatus.OK));
		
		String checkStatus = "/ascan/view/status/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(checkStatus), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("{status:100}", HttpStatus.OK));
		
		
		impl.runActiveScan(authConfig.getPathsToScan(), contextId,null);
		verify(impl,times(1)).runActiveScan(authConfig.getPathsToScan(), contextId,null);
		runActiveScan(authConfig.getPathsToScan(), contextId,null);
		
		LOGGER.debug("End runActiveScan_NoAuth()");
	}
	
	
	

}
