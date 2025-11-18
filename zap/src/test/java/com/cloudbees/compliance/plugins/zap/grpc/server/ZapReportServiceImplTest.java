package com.cloudbees.compliance.plugins.zap.grpc.server;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
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
import com.cloudbees.compliance.plugins.zap.service.impl.ZapReportServiceImpl;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;
import com.google.protobuf.ByteString;


@ComponentScan({ "com.cloudbees" })
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"grpc.inProcessName=testreport", // Enable inProcess server
		"grpc.port=7", // Disable external server
		"grpc.client.inProcess.address=in-process:testreport" // Configure the client to connect to the inProcess server
})
class ZapReportServiceImplTest extends ZapReportServiceImpl {
	@MockBean
	@Qualifier("universalRestTemplate")
	private RestTemplate restTemplate;
	
	private String contextName = "cbc-dev-dast-1";
	
	@Value("${zap.server.resource.url}")
	String resourceUrl;

	@Value("${zap.server.resource.includeInContextEndpoint}")
	String includeInContextEndpoint;
	
	@Value("${zap.server.resource.excludeInContextEndpoint}")
	String excludeInContextEndpoint;
	
	
	ZapAuthServerInfo auth;
	
	@Autowired
	ZapAuthManager zapAuthManager;
	
	@Autowired
	ZapUtil utils;
	private static final Logger LOGGER = LoggerFactory.getLogger(ZapReportServiceImplTest.class);
	
	@BeforeEach
	public void setUp() {
		
		ByteString responseByteStr = ByteString
				.copyFrom(new String("{\"zapAddress\":\"localhost\",\"zapPort\":8084,\"apiKey\":\"fgbmqkgdkhfapf0lalqf92mil6\"}").getBytes(StandardCharsets.UTF_8));
		auth = zapAuthManager.getZapAuthFromString(responseByteStr);
		ReflectionTestUtils.setField(zapAuthManager, "zapAuthServerInfo", auth);
		ReflectionTestUtils.setField(utils, "authManager", zapAuthManager);
		ReflectionTestUtils.setField(this, "utils", utils);
	
		
	}
	

	@Test
	void generateReport_Test() throws IOException {
		LOGGER.debug("start generateReport_Test_FileNotFoundException()");
		
		String url = "/other/core/other/jsonreport/";
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>(getJsonString("src/test/resources/ZAP-Report.json"), HttpStatus.OK));
		
		Assertions.assertNotNull(generateReport(contextName));
		
		LOGGER.debug("end generateReport_Test_FileNotFoundException()");
	}
	
	private String getJsonString(String jsonFilePath) {
        String result = null;
        try {
            result = new String(Files.readAllBytes(Paths.get(jsonFilePath)));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }
}
