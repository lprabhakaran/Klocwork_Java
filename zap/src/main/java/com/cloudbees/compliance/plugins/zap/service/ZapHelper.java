package com.cloudbees.compliance.plugins.zap.service;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthConfig;
import com.cloudbees.compliance.plugins.zap.components.ZapContext;
import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.cloudbees.compliance.plugins.zap.exception.ZapPluginException;
import com.cloudbees.compliance.plugins.zap.response.model.ZapResponse;
import com.cloudbees.compliance.plugins.zap.service.impl.ZapScanServiceImpl;
import com.cloudbees.compliance.plugins.zap.util.ZapEvaluationUtils;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;
import com.cloudbees.compliance.service.v040.Asset;
import com.cloudbees.compliance.service.v040.AssetProfile;
import com.cloudbees.compliance.service.v040.Evaluation;

@Service
public class ZapHelper {

	@Autowired
	private final BeanFactory factory;
	@Autowired
	private ZapContext zapContext;
	private static final Logger LOGGER = LoggerFactory.getLogger(ZapHelper.class);
	@Autowired
	private ZapScanServiceImpl zapScanServiceImpl;
	@Autowired
	private ZapReportService zapReportService;
	@Autowired
	private ZapEvaluationUtils evaluationUtils;
	@Autowired
	private ZapUtil utils;
	@Autowired
	@Qualifier("universalRestTemplate")
	RestTemplate restTemplate;

	@Value("${zap.server.resource.createNewUser}")
	String createNewUser;

	public ZapHelper(BeanFactory factory) {
		super();
		this.factory = factory;
	}

	/**
	 * 
	 * @param zapAuthConfig
	 * @param contextName
	 * @throws Exception
	 * @throws InterruptedException
	 */
	public List<Evaluation> getEvaluations(ZapAuthConfig authConfig, String contextName, AssetProfile assetProfile,
			Asset asset) throws Exception {
		LOGGER.info("in  getEvaluations(String sourceMetaData, String contextName)");
		List<Evaluation> evaluations = new ArrayList<>();

		// if user only provide the URL
		if (!authConfig.getContextAvailable()) {
			return getEvalforEmptyValues(authConfig, contextName, assetProfile, asset);

		}
		String userId = null;
		// UsernamePasswordAuth or Auth0
		String authType = authConfig.getAuthType();
		
		LOGGER.debug("Auth type : {}",authType);

		// returns auth service implementation based on auth_type
		AbstractZapAuthService authService = factory.getBean(getAuthServiceBeanName(authType),
				AbstractZapAuthService.class);

		// validates required fields
		authService.validateContextMetaData(authConfig);

		// create new context
		String contextId = zapContext.createNewContext(contextName);
		LOGGER.debug("created context with id: {} | name: {}", contextId, contextName);

		// set Include In And Exclude From Context
		zapContext.includeInContext(contextName, authConfig.getIncludeInContextRegexes());
		zapContext.excludeFromContext(contextName, authConfig.getExcludeFromContextRegexes());

		if (!authType.contentEquals("NoAuth")) {
			// authentication method for the context
			authService.setAuthenticationMethod(authConfig, contextId);

			// regex pattern for logged in messages
			authService.setLoggedOutIndicator(contextId, authConfig.getLoggedOutIndicator());

			// regex pattern for logged out messages
			authService.setLoggedInIndicator(contextId, authConfig.getLoggedInIndicator());

			// create a new user
			String createNewUserStr = createNewUser;
			createNewUserStr = createNewUserStr
					.replace(ZapApiConstants.USERNAME, authConfig.getCredentialsConfig().getUsername())
					.replace(ZapApiConstants.CONTEXTID, contextId);
			ResponseEntity<String> createResEntity = utils.callRestAPI(createNewUserStr);

			if (HttpStatus.OK.equals(createResEntity.getStatusCode())) {
				JSONObject jsonResponse = new JSONObject(createResEntity.getBody());
				userId = jsonResponse.getString("userId");
			} else {
				LOGGER.error("Failed to create User ID : Error {}", createResEntity.getBody());
				zapContext.deleteContext(contextName);
				throw new ZapPluginException(
						"Failed to create new userId for user " + authConfig.getCredentialsConfig().getUsername());
			}
			LOGGER.debug("created user withd id: {}", userId);

			// set user auth config
			authService.setUserAuthConfig(authConfig, contextId, userId);

			// check for authentication success/failure
			if (!authService.authenticateAsUser(contextId, userId)) {
				zapContext.deleteContext(contextName);
				// set the authentication error evaluation list
				evaluations = evaluationUtils.fetchUnauthenticatedScanResponse(asset, assetProfile);
				// throw new ZapPluginException(
				// "authentication failed for user: " +
				// authConfig.getCredentialsConfig().getUsername());
			}

		}

		List<String> urlsToScan = getURLListToScan(authConfig.getPathsToScan(), authConfig.getUrl());

		// start spidering on all URL's received in input
		List<String> spiderResults = zapScanServiceImpl.runSpider(urlsToScan, contextId, contextName, userId);

		if (!spiderResults.isEmpty()) {
			// start active scan on all URL's received in input
			boolean activeScanStatus = zapScanServiceImpl.runActiveScan(urlsToScan, contextId, userId);

			if (activeScanStatus) {
				LOGGER.debug("active sacn completed progress: {}%", "100");
			}

			// generate report and save report to temporary directory
			ZapResponse zapResponse = zapReportService.generateReport(contextName);

			// process ZapResponse to generate evaluations
			evaluations = evaluationUtils.generateEvaluations(asset, assetProfile, zapResponse,
					authConfig.getIncludeInContextRegexes(),contextName);

		}

		// delete context if it exists
		zapContext.deleteContext(contextName);

		if (authType.contentEquals("NoAuth")) {
			List<Evaluation> evaluationsList = new ArrayList<>(evaluations);
			evaluationsList.add(evaluationUtils.fetchUnauthenticatedScanResponse(asset, assetProfile).get(0));
			return evaluationsList;
		}
		LOGGER.info("exit  getEvaluations(String sourceMetaData, String contextName)");
		return evaluations;

	}

	private String getAuthServiceBeanName(String authType) {
		return authType + ZapApiConstants.SERVICE_NAME_SUFFIX;
	}

	private List<String> getURLListToScan(List<String> pathsToScan, String host)
			throws MalformedURLException, URISyntaxException {
		List<String> urlsToScan = new ArrayList<>();
		if (host.endsWith("/"))
			host = host.substring(0, host.length() - 1);

		for (String path : pathsToScan) {
			if (!path.startsWith("/"))
				path = "/" + path;

			urlsToScan.add(host.concat(path));
		}

		for (String url : urlsToScan) {
			URL validURL = new URL(url);
			LOGGER.debug("URL to scan: {}", validURL.toURI().toString());
		}
		return urlsToScan;
	}

//	This method used for using only URL and without any input values to retrieve the evaluation list

	public List<Evaluation> getEvalforEmptyValues(ZapAuthConfig authConfig, String contextName,
			AssetProfile assetProfile, Asset asset) throws Exception {
		List<String> pathURLvalues = new ArrayList<String>();

		// create new context
		String contextId = zapContext.createNewContext(contextName);
		LOGGER.debug("created context with id(Context is not available): {} | name: {}", contextId, contextName);

		pathURLvalues.add(authConfig.getUrl() + ".*");

		List<Evaluation> evaluations = new ArrayList<>();
		zapContext.includeInContext(contextName, pathURLvalues);

		// start spidering on all URL's received in input
		List<String> spiderResults = zapScanServiceImpl.runSpider(pathURLvalues, contextId, contextName, null);

		if (!spiderResults.isEmpty()) {
			// start active scan on all URL's received in input
			boolean activeScanStatus = zapScanServiceImpl.runActiveScan(pathURLvalues, contextId, null);

			if (activeScanStatus) {
				LOGGER.debug("active sacn completed progress: {}%", "100");
			}

			// generate report and save report to temporary directory
			ZapResponse zapResponse = zapReportService.generateReport(contextName);

			// process ZapResponse to generate evaluations
			evaluations = evaluationUtils.generateEvaluations(asset, assetProfile, zapResponse,
					pathURLvalues,contextName);

		}

		// delete context if it exists
		zapContext.deleteContext(contextName);

		return evaluations;
	}
	
	
	
	

}
