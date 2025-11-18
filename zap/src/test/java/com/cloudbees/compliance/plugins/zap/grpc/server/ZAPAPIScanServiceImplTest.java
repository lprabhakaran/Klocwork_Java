package com.cloudbees.compliance.plugins.zap.grpc.server;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import com.cloudbees.compliance.plugins.zap.auth.ZapAuthManager;
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthConfig;
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthServerInfo;
import com.cloudbees.compliance.plugins.zap.components.ZapContext;
import com.cloudbees.compliance.plugins.zap.response.model.ZapResponse;
import com.cloudbees.compliance.plugins.zap.service.ZapReportService;
import com.cloudbees.compliance.plugins.zap.service.impl.ZapApiScanServiceImpl;
import com.cloudbees.compliance.plugins.zap.util.ZapEvaluationUtils;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;
import com.cloudbees.compliance.service.v040.Asset;
import com.cloudbees.compliance.service.v040.AssetProfile;
import com.cloudbees.compliance.service.v040.MasterAsset;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

@ComponentScan({ "com.cloudbees" })
@SpringBootTest
class ZAPAPIScanServiceImplTest {

	@InjectMocks
	ZapApiScanServiceImpl apiScanImpl;

	@Mock
	ZapUtil util;

	@Mock
	ZapAuthManager manager;

	@Mock
	@Qualifier("universalRestTemplate")
	RestTemplate restTemplate;

	@Mock
	ZapContext context;

	private ZapAuthConfig authConfig;

	@Mock
	private ZapReportService zapReportServiceImpl;

	@Autowired
	private ZapEvaluationUtils evalUtil;
	private static final Logger LOGGER = LoggerFactory.getLogger(ZAPAPIScanServiceImplTest.class);

	private void commonMocks() throws FileNotFoundException {
		HttpHeaders headers = new HttpHeaders();
		headers.add("X-ZAP-API-Key", "testAPIKey");
		Mockito.when(manager.getAuthenticationHeader()).thenReturn(headers);
		ReflectionTestUtils.setField(apiScanImpl, "setScriptVarsUrl", "/script/action/setGlobalVar/");
		ReflectionTestUtils.setField(apiScanImpl, "evaluationUtils", evalUtil);
		ReflectionTestUtils.setField(apiScanImpl, "healthzUrl", "/healthz");
		ReflectionTestUtils.setField(apiScanImpl, "writeToFileUrl", "/writeFile");
		ReflectionTestUtils.setField(apiScanImpl, "deleteFileUrl", "/deleteFile");

		Mockito.when(restTemplate.exchange(Mockito.contains("/core/action/deleteAllAlerts"), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>(HttpStatus.OK));

		Mockito.when(restTemplate.exchange(Mockito.contains("/script/action/clearGlobalVars/"),
				Mockito.eq(HttpMethod.GET), Mockito.any(), Mockito.eq(String.class)))
				.thenReturn(new ResponseEntity<>(HttpStatus.OK));

		Mockito.when(restTemplate.exchange(Mockito.contains("/script/action/setGlobalVar/"), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>(HttpStatus.OK));
		Mockito.when(restTemplate.exchange(Mockito.contains("/script/action/setGlobalVar/"), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>(HttpStatus.OK));
		Mockito.when(restTemplate.exchange(Mockito.contains("/script/action/setGlobalVar/"), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>(HttpStatus.OK));
		Mockito.when(restTemplate.exchange(Mockito.contains("/script/action/setGlobalVar/"), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>(HttpStatus.OK));
		Mockito.when(restTemplate.exchange(Mockito.contains("/healthz"), Mockito.eq(HttpMethod.GET),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>(HttpStatus.OK));
		Mockito.when(restTemplate.exchange(Mockito.contains("/writeFile"), Mockito.eq(HttpMethod.POST),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>(HttpStatus.OK));
		Mockito.when(restTemplate.exchange(Mockito.contains("/writeFile"), Mockito.eq(HttpMethod.DELETE),
				Mockito.any(), Mockito.eq(String.class))).thenReturn(new ResponseEntity<>(HttpStatus.OK));
		try {
			Mockito.when(context.createNewContext("test")).thenReturn("contextName");
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		JsonReader reader = new JsonReader(new FileReader("src/test/resources/ZAP-Report.json"));
		ZapResponse zapResponse = new Gson().fromJson(reader, ZapResponse.class);

		try {
			Mockito.when(zapReportServiceImpl.generateReport("test")).thenReturn(zapResponse);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		AssetProfile assetProfile = AssetProfile.newBuilder().setUuid("test")
				.setIdentifier("https://cbcdemo.eu.auth0.com/").setType("CORE").build();
		MasterAsset master = MasterAsset.newBuilder().setSubType("zap_dast").setType("CORE")
				.setIdentifier("appId-sample-1").build();
		Asset asset = Asset.newBuilder().setMasterAsset(master).setUuid("asset-uuid-1").addProfiles(assetProfile)
				.build();

		assertEquals(8, apiScanImpl.doAPIScan(authConfig, "test", assetProfile, asset).size());

	}

	@Test
	void doAPiScanUrlTest_success() throws Exception {
		LOGGER.debug("In doAPiScanUrlTest_success");

		ReflectionTestUtils.setField(apiScanImpl, "openAPIUrl", "/openapi/action/importUrl/");

		authConfig = mockAuthConfig("src/test/resources/apiauthconfig.json");
		authConfig.setUrl("testUrl");

		Mockito.when(restTemplate.postForEntity(Mockito.contains("/openapi/action/importUrl/"), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(new ResponseEntity<>(HttpStatus.OK));
		Mockito.when(util.buildAPIEndpointURL("/openapi/action/importUrl/")).thenReturn("http://test.com/openapi/action/importUrl/");
		commonMocks();
		LOGGER.debug("Exit doAPiScanUrlTest_success");
	}

	@Test
	void doAPiScanJsonTest_success() throws FileNotFoundException {
		LOGGER.debug("In doAPiScanJsonTest_success");
		
		ReflectionTestUtils.setField(apiScanImpl, "openAPIJsonUrl", "/openapi/action/importFile/");

		Mockito.when(restTemplate.postForEntity(Mockito.contains("/openapi/action/importFile/"), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(new ResponseEntity<>(HttpStatus.OK));

		authConfig = mockAuthConfig("src/test/resources/apiauthconfigjson.json");
		authConfig.setUrl("testUrl");
		ZapAuthServerInfo server = new ZapAuthServerInfo();
		server.setZapAddress("test.com");
		Mockito.when(manager.getZapAuthServerInfo()).thenReturn(server);
		Mockito.when(util.buildAPIEndpointURL("/openapi/action/importFile/")).thenReturn("http://test.com/openapi/action/importFile/");
		commonMocks();
		LOGGER.debug("Exit doAPiScanJsonTest_success");

	}

	ZapAuthConfig mockAuthConfig(String jsonPath) {
		try {
			ObjectMapper map = new ObjectMapper();
			return map.readValue(getJsonString(jsonPath), ZapAuthConfig.class);
		} catch (Exception e) {
			// ignore
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

}
