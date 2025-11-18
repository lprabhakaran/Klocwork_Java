package com.cloudbees.compliance.plugins.zap.grpc.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.cloudbees.compliance.plugins.zap.auth.ZapAuthManager;
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthServerInfo;
import com.cloudbees.compliance.plugins.zap.components.ZapContext;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;
import com.google.protobuf.ByteString;

@ComponentScan({ "com.cloudbees" })
@ExtendWith(MockitoExtension.class)
@SpringBootTest(
		webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = {
				"grpc.inProcessName=testmaster",// Enable inProcess server
				"grpc.port=123", // Disable external server
				"grpc.client.inProcess.address=in-process:testmaster" // Configure the client to connect to the inProcess server
		})
class ZapContextTest extends ZapContext{

	
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
	
	ZapContext contxt = mock(ZapContext.class);
	

		
	private static final Logger LOGGER = LoggerFactory.getLogger(ZapContextTest.class);

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
	void includeInContext_Test() throws Exception {
		LOGGER.debug("start @includeInContext_Test test");
		List<String> regexes = new ArrayList<>();
		regexes.add("https://www.xxx.cbc.beescloud.com.*");
		ReflectionTestUtils.setField(this, "includeInContextEndpoint", "/context/action/includeInContext/?contextName={contextName}&regex={regex}&");
			String url = "/context/action/includeInContext";
		
	
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
		
		
		contxt.includeInContext(contextName, regexes);
		verify(contxt,times(1)).includeInContext(contextName, regexes);
		includeInContext(contextName, regexes);
		LOGGER.debug("exit @includeInContext_Test test");
	}

	@Test
	void excludeFromContext_Test() throws Exception {
		LOGGER.debug("start @excludeFromContext_Test test");
		List<String> regexes = new ArrayList<>();
		regexes.add("https://www.xxx.cbc.beescloud.com.*");
		String url = "/context/action/excludeFromContext";
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
		contxt.excludeFromContext(contextName, regexes);
		verify(contxt,times(1)).excludeFromContext(contextName, regexes);
		excludeFromContext(contextName, regexes);
		LOGGER.debug("exit @excludeFromContext_Test test");
	}
	
	@Test
	void createNewContext_Test() throws Exception {
		LOGGER.debug("start @createNewContext_Test test");
		String url = "/context/action/newContext/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("{contextId:contextId}", HttpStatus.OK));
		
		assertEquals("contextId", createNewContext(contextName));
		
		LOGGER.debug("exit @createNewContext_Test test");
	}
	
	@Test
	void contextExists_Test() throws Exception {
		LOGGER.debug("start @contextExists_Test test");
		String url = "/context/view/context/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
		
		Assertions.assertTrue(contextExists(contextName));
		
		
		
		LOGGER.debug("exit @contextExists_Test test");
	}

	@Test
	void context_Does_Not_Exists_Test() throws Exception {
		LOGGER.debug("start @context_Does_Not_Exists_Test test");
		
		String url = "/context/view/context/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST,"BadRequest: 400 Bad Request"));
		
		Assertions.assertFalse(contextExists(contextName));
		LOGGER.debug("exit @context_Does_Not_Exists_Test test");
	}
	
	
	@Test
	void deleteContext_Test() throws Exception {
		LOGGER.debug("start @deleteContext_Test test");
		
		String url1 = "/context/view/context/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(url1), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
		
		String url = "/context/action/removeContext/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>("{Result:OK}", HttpStatus.OK));
		
		contxt.deleteContext(contextName);
		verify(contxt,times(1)).deleteContext(contextName);
		deleteContext(contextName);
		LOGGER.debug("exit @deleteContext_Test test");
	}
	
	@Test
	void deleteContext_Test_Error() throws Exception {
		LOGGER.debug("start @deleteContext_Test_Error test");
		
		String url = "/context/action/removeContext/";
		
		Mockito.when(restTemplate.exchange( Mockito.contains(url), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST,"Does not exist"));
		
		contxt.deleteContext(contextName);
		verify(contxt,times(1)).deleteContext(contextName);
		deleteContext(contextName);
		LOGGER.debug("exit @deleteContext_Test_Error test");
	}
	

	

}
