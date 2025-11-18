package com.cloudbees.compliance.plugins.zap.grpc.server;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
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
import com.cloudbees.compliance.plugins.zap.auth.model.ScriptAuthConfig;
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthServerInfo;
import com.cloudbees.compliance.plugins.zap.service.impl.ScriptAuthServiceImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.ByteString;
@ComponentScan({ "com.cloudbees" })
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"grpc.inProcessName=test3", // Enable inProcess server
		"grpc.port=1", // Disable external server
		"grpc.client.inProcess.address=in-process:test3" // Configure the client to connect to the inProcess server
})
class ScriptAuthServiceImplTest  extends ScriptAuthServiceImpl {
	@MockBean
	@Qualifier("restTemplate")
	RestTemplate restTemplate;

	private ScriptAuthConfig authConfig;
	private String contextId = "3";
	private String userId = "1";
	
	private ZapAuthServerInfo authServerInfo;
	
	@Autowired
	ZapAuthManager zapAuthManager;
	
	private ScriptAuthServiceImpl impl = mock(ScriptAuthServiceImpl.class);
	
	private static final Logger logger = LoggerFactory.getLogger(ScriptAuthServiceImplTest.class);
	
	@BeforeEach
	public void setUp() {		
		authConfig = mockScriptAuthConfig();
		ByteString metadata = ByteString
				.copyFromUtf8("{\"zapAddress\":\"localhost\",\"zapPort\":8082,\"apiKey\":\"xxxxxxxxxxxx\"}");
	
		authServerInfo = zapAuthManager.getZapAuthFromString(metadata);
		ReflectionTestUtils.setField(zapAuthManager, "zapAuthServerInfo", authServerInfo);
		ReflectionTestUtils.setField(this, "authManager", zapAuthManager);
	}
	
	ScriptAuthConfig mockScriptAuthConfig() {
		try {
		ObjectMapper map = new ObjectMapper();
		return map.readValue(getJsonString("src/test/resources/auth0_auth_config.json"), ScriptAuthConfig.class);
		}catch(Exception e) {
			//ignore
		}
		return null;
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
	
	@Test
	void setAuthenticationMethod_Test() throws UnsupportedEncodingException {
		logger.debug("Enter setAuthenticationMethod_Test");
		String url = "/authentication/action/setAuthenticationMethod/";
		

		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
		
		
		impl.setAuthenticationMethod(authConfig, contextId);
		verify(impl,times(1)).setAuthenticationMethod(authConfig, contextId);
		setAuthenticationMethod(authConfig, contextId);
		logger.debug("Exit setAuthenticationMethod_Test");
	}
	
	@Test
	void setUserAuthConfig_test() throws UnsupportedEncodingException {
		logger.debug("Enter setUserAuthConfig_test");
		
		String setAuthCredUrl = "/users/action/setAuthenticationCredentials/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(setAuthCredUrl), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
		
		String setUserEnableUrl = "/users/action/setUserEnabled/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(setUserEnableUrl), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
		
		String forcedUrl = "/forcedUser/action/setForcedUser";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(forcedUrl), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
		
		String setForcedUser = "/forcedUser/action/setForcedUserModeEnabled/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(setForcedUser), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
		
		String getByUserId = "/users/view/getUserById/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(getByUserId), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>(getJsonString("src/test/resources/creds_config.json"), HttpStatus.OK));
		
		impl.setUserAuthConfig(authConfig,contextId,userId);
		verify(impl,times(1)).setUserAuthConfig(authConfig,contextId,userId);
		setUserAuthConfig(authConfig,contextId,userId);
		
		logger.debug("Exit setUserAuthConfig_test");
		
	}
}
