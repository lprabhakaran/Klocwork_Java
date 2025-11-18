package com.cloudbees.compliance.plugins.zap.grpc.server;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.cloudbees.compliance.plugins.zap.auth.ZapAuthManager;
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthServerInfo;
import com.google.protobuf.ByteString;

@ComponentScan({ "com.cloudbees" })
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"grpc.inProcessName=test1", // Enable inProcess server
		"grpc.port=4", // Disable external server
		"grpc.client.inProcess.address=in-process:test" // Configure the client to connect to the inProcess server
})
class ZapAuthManagerTest extends ZapAuthManager{

	
	@Mock
	private Environment environment;

	private static final Logger LOGGER = LoggerFactory.getLogger(ZapAuthManagerTest.class);
	private ZapAuthServerInfo authServerInfo;
	private ByteString metadata;
	private ByteString incorrectMetaData;
	private ZapAuthServerInfo incorrectAuthServerInfo;
	
	@MockBean
	@Qualifier("universalRestTemplate")
	RestTemplate restTemplate;

	@BeforeEach
	public void setUp() {
		metadata = ByteString
				.copyFromUtf8("{\"zapAddress\":\"localhost\",\"zapPort\":8082,\"apiKey\":\"xxxxxxxxxxxx\"}");
	
		authServerInfo = getZapAuthFromString(metadata);
		incorrectMetaData = ByteString.copyFromUtf8("{\"zapPort\":8082,\"apiKey\":\"xxxxxxxxxxxxxxxx\"}");
		incorrectAuthServerInfo = getZapAuthFromString(incorrectMetaData);
		ReflectionTestUtils.setField(this, "environment", environment);
		
	}

	@Test
	void authenticate_Test_Using_Metadata_Creds() {

		LOGGER.debug("start @authenticate_Test_Using_Metadata_Creds test");
		String url = "/context/view/contextList";
		

		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
		
		
		Assertions.assertTrue(authenticate(metadata));
		

		LOGGER.debug("exit @authenticate_Test_Using_Metadata_Creds test");
	}

	@Test
	void authenticate_Test_Using_Creds_From_YML() {

		LOGGER.debug("start @authenticate_Test_Using_Creds_From_YML test");
		String url = "/context/view/contextList";
	
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
		
		Assertions.assertFalse(authenticate(ByteString.EMPTY));
		LOGGER.debug("exit @authenticate_Test_Using_Creds_From_YML test");

	}
	
	@Test
	void authenticate_Test_Error() {

		LOGGER.debug("start @authenticate_Test_Using_Creds_From_YML test");
		String url = "/context/view/contextList";
	
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST,"Connecting with ZAP Server failed"));
		
		String url1 = "/context/view/contextList";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(url1), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
		
		Assertions.assertTrue(authenticate(metadata));
		LOGGER.debug("exit @authenticate_Test_Using_Creds_From_YML test");

	}
	
	@Test
	void authenticate_Test_Validation() {

		LOGGER.debug("start @authenticate_Test_Using_Creds_From_YML test");
		
		LOGGER.debug("start @authenticate_Test_Using_Creds_From_YML test");
		String url = "/context/view/contextList";
	
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
				
		Assertions.assertFalse(authenticate(incorrectMetaData));
		
		LOGGER.debug("exit @authenticate_Test_Using_Creds_From_YML test");

	}

}
