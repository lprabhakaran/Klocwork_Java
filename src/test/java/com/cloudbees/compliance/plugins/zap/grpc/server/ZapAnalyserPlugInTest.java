package com.cloudbees.compliance.plugins.zap.grpc.server;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.ComponentScan;

import com.cloudbees.compliance.plugins.model.AssetType;
import com.cloudbees.compliance.plugins.zap.auth.ZapAuthManager;
import com.cloudbees.compliance.plugins.zap.service.ZapAnalyserPlugIn;
import com.cloudbees.compliance.plugins.zap.service.ZapReportService;
import com.cloudbees.compliance.plugins.zap.util.ZapEvaluationUtils;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;

@ComponentScan({ "com.cloudbees" })
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"grpc.inProcessName=testanalyser", // Enable inProcess server
		"grpc.port=3", // Disable external server
		"grpc.client.inProcess.address=in-process:testanalyser" // Configure the client to connect to the inProcess
																// server
})
@ExtendWith(MockitoExtension.class)
class ZapAnalyserPlugInTest extends ZapAnalyserPlugIn {

	private static final Logger logger = LoggerFactory.getLogger(ZapAnalyserPlugInTest.class);
	// private ExecuteRequest executeRequest;
	@InjectMocks
	ZapAnalyserPlugIn zapAnalyserPlugIn;
	@Mock
	private ZapUtil zapUtilMock;
	@Mock
	private ZapReportService zapReportService;
	@Mock(name = "zapAuthImpl")
	ZapAuthManager zapAuthImpl;
	@Autowired
	private ZapEvaluationUtils evaluationUtils;
	private static final String contextName = "cbc-dev-dast-1";
	@Mock
	private ApplicationContext applicationContext;

	@Test
	void getBinaryAttributesTypeLists() {
		logger.info("@Test getBinaryAttributesTypeLists() starts..");
		Assertions.assertTrue(getBinaryAttributesTypeList().isEmpty());
		logger.info("@Test getBinaryAttributesTypeLists() ends..");
	}

	@BeforeEach
	public void setUp() {
		zapAnalyserPlugIn = mock(ZapAnalyserPlugIn.class);
		zapAnalyserPlugIn = new ZapAnalyserPlugIn();
	}


	@Test
	void getAssetTypes() {
		logger.info("@Test getAssetTypes() starts..");
		assertEquals(AssetType.CODE, getAssetType());
		logger.info("@Test getAssetTypes() ends..");
	}

	@Test
	void getAllTags() {
		logger.info("@Test getAllTags() starts..");
		Assertions.assertTrue(getTags().isEmpty());
		logger.info("@Test getAllTags() ends..");
	}

	
	
	

}
