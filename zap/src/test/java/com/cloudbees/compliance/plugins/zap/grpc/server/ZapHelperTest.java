package com.cloudbees.compliance.plugins.zap.grpc.server;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.when;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.util.ReflectionTestUtils;

import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthConfig;
import com.cloudbees.compliance.plugins.zap.components.ZapContext;
import com.cloudbees.compliance.plugins.zap.response.model.ZapResponse;
import com.cloudbees.compliance.plugins.zap.service.AbstractZapAuthService;
import com.cloudbees.compliance.plugins.zap.service.ZapHelper;
import com.cloudbees.compliance.plugins.zap.service.ZapReportService;
import com.cloudbees.compliance.plugins.zap.service.impl.NoAuthServiceImpl;
import com.cloudbees.compliance.plugins.zap.service.impl.ZapScanServiceImpl;
import com.cloudbees.compliance.plugins.zap.util.ZapEvaluationUtils;
import com.cloudbees.compliance.service.v040.Asset;
import com.cloudbees.compliance.service.v040.AssetProfile;
import com.cloudbees.compliance.service.v040.Evaluation;
import com.cloudbees.compliance.service.v040.MasterAsset;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;


@ComponentScan({ "com.cloudbees" })
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"grpc.inProcessName=test2", // Enable inProcess server
		"grpc.port=5", // Disable external server
		"grpc.client.inProcess.address=in-process:test2" // Configure the client to connect to the inProcess server
})
class ZapHelperTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(ZapHelperTest.class);
	private static final String contextName = "cbc-dev-dast-1";
	private static final String contextId = "100";
	@InjectMocks
	ZapHelper zapHelper;
	@Mock
	ZapHelper mockerZapHelper;
	@Mock
	private BeanFactory factory;
	@Mock
	private ZapContext zapContext;

	@Mock
	NoAuthServiceImpl authService;
	@Mock
	ZapScanServiceImpl zapScanServiceImpl;
	@Mock
	private ZapEvaluationUtils evaluationUtils;
	@Autowired
	private ZapEvaluationUtils evaluationUtils1;
	@MockBean
	private ZapReportService zapReportService;

	

	@Test
	void getEvaluations__NoAuth_Test() throws Exception {
		LOGGER.info("start getEvaluations__NoAuth_Test()");
		ZapAuthConfig zapAuthConfig = mockNoAuthConfig();

		AssetProfile assetProfile = AssetProfile.newBuilder().setUuid(contextName)
				.setIdentifier("https://www.dev.cbc.beescloud.com/").setType("CORE").build();
		MasterAsset master = MasterAsset.newBuilder().setSubType("zap_dast").setType("CORE")
				.setIdentifier("appId-sample-1").build();
		Asset asset = Asset.newBuilder().setMasterAsset(master).setUuid("asset-uuid-1").addProfiles(assetProfile)
				.build();

		ReflectionTestUtils.setField(mockerZapHelper, "zapContext", zapContext);
		ReflectionTestUtils.setField(mockerZapHelper, "factory", factory);
		ReflectionTestUtils.setField(mockerZapHelper, "zapScanServiceImpl", zapScanServiceImpl);
		ReflectionTestUtils.setField(mockerZapHelper, "evaluationUtils", evaluationUtils);
		ReflectionTestUtils.setField(mockerZapHelper, "zapReportService", zapReportService);

		when(zapContext.createNewContext(contextName)).thenReturn(contextId);
		when(factory.getBean("NoAuthServiceImpl", AbstractZapAuthService.class)).thenReturn(authService);

		ArrayList<String> spiderResults = new ArrayList<String>();
		spiderResults.add(
				"https://www.demo.cbc.beescloud.com/organisations/_next/static/vDRyeaCXtEP2mIqCFd1NI/_buildManifest.js");

		ArrayList<String> URLListToScan = new ArrayList<String>();
		for (String string : zapAuthConfig.getPathsToScan()) {
			URLListToScan.add(zapAuthConfig.getUrl() + "/" + string);
		}

		List<String> urlsToScan = new ArrayList<>();
		for (String path : zapAuthConfig.getPathsToScan()) {
			urlsToScan.add(zapAuthConfig.getUrl().concat(path));
		}

		when(zapScanServiceImpl.runSpider(urlsToScan, contextId, contextName, null)).thenReturn(spiderResults);

		String jsonString = getJsonString("src/test/resources/evaluations.json");
		
		JsonArray jsonArray = JsonParser.parseString(jsonString).getAsJsonArray();
		List<Evaluation> expectedEvaluations = new ArrayList<>();
		ObjectMapper mapper = new ObjectMapper();
		expectedEvaluations = mapper.readValue(jsonString, expectedEvaluations.getClass());

		JsonReader reader = new JsonReader(new FileReader("src/test/resources/ZAP-Report.json"));
		ZapResponse zapResponse = new Gson().fromJson(reader, ZapResponse.class);

		when(zapReportService.generateReport(contextName)).thenReturn(zapResponse);
		when(evaluationUtils.generateEvaluations(asset, assetProfile, zapResponse,new ArrayList<String>(),contextName)).thenReturn(expectedEvaluations);

		List<Evaluation> noAuthEvaluation = evaluationUtils1.fetchUnauthenticatedScanResponse(asset, assetProfile);
		when(evaluationUtils.fetchUnauthenticatedScanResponse(asset, assetProfile)).thenReturn(noAuthEvaluation);

		doCallRealMethod().when(mockerZapHelper).getEvaluations(any(ZapAuthConfig.class), anyString(),
				any(AssetProfile.class), any(Asset.class));

		List<Evaluation> actualEvaluations = mockerZapHelper.getEvaluations(zapAuthConfig, contextName, assetProfile,
				asset);

		assertTrue(actualEvaluations.isEmpty());
		LOGGER.info("exit getEvaluations__NoAuth_Test()");
	}

	ZapAuthConfig mockNoAuthConfig() throws JsonMappingException, JsonProcessingException {
		ObjectMapper map = new ObjectMapper();
		return map.readValue(getJsonString("src/test/resources/no-auth-config.json"), ZapAuthConfig.class);
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
	void getEvaluation_Details() throws Exception {

		AssetProfile assetProfile = AssetProfile.newBuilder().setUuid(contextName)
				.setIdentifier("https://www.dev.cbc.beescloud.com/").setType("CORE").build();
		MasterAsset master = MasterAsset.newBuilder().setSubType("zap_dast").setType("CORE")
				.setIdentifier("appId-sample-1").build();
		Asset asset = Asset.newBuilder().setMasterAsset(master).setUuid("asset-uuid-1").addProfiles(assetProfile)
				.build();
		JsonReader reader = new JsonReader(new FileReader("src/test/resources/ZAP-Report.json"));
		ZapResponse zapResponse = new Gson().fromJson(reader, ZapResponse.class);
		
		when(zapReportService.generateReport(contextName)).thenReturn(zapResponse);
		

		assertNotNull(evaluationUtils1.generateEvaluations(asset, assetProfile, zapResponse,new ArrayList<String>(),contextName));

	}

	@Test
	void getNo_Auth_Evaluation_Details() throws Exception {

		AssetProfile assetProfile = AssetProfile.newBuilder().setUuid(contextName)
				.setIdentifier("https://www.dev.cbc.beescloud.com/").setType("CORE").build();
		MasterAsset master = MasterAsset.newBuilder().setSubType("zap_dast").setType("CORE")
				.setIdentifier("appId-sample-1").build();
		Asset asset = Asset.newBuilder().setMasterAsset(master).setUuid("asset-uuid-1").addProfiles(assetProfile)
				.build();

		assertNotNull(evaluationUtils1.fetchUnauthenticatedScanResponse(asset, assetProfile));

	}

}
