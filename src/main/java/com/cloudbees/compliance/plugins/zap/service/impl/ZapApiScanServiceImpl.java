package com.cloudbees.compliance.plugins.zap.service.impl;

import java.io.File;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.cloudbees.compliance.plugins.exception.PluginException;
import com.cloudbees.compliance.plugins.zap.auth.ZapAuthManager;
import com.cloudbees.compliance.plugins.zap.auth.model.AuthHeader;
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthConfig;
import com.cloudbees.compliance.plugins.zap.components.ZapContext;
import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.cloudbees.compliance.plugins.zap.response.model.ZapResponse;
import com.cloudbees.compliance.plugins.zap.service.ZapApiScanService;
import com.cloudbees.compliance.plugins.zap.service.ZapReportService;
import com.cloudbees.compliance.plugins.zap.util.ZapEvaluationUtils;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;
import com.cloudbees.compliance.service.v040.Asset;
import com.cloudbees.compliance.service.v040.AssetProfile;
import com.cloudbees.compliance.service.v040.Evaluation;

@Service
public class ZapApiScanServiceImpl implements ZapApiScanService {

	@Autowired
	private ZapContext zapContext;

	@Autowired
	@Qualifier("universalRestTemplate")
	private RestTemplate restTemplate;

	@Autowired
	private ZapUtil zapUtil;

	@Autowired
	ZapAuthManager authManager;

	@Autowired
	private ZapReportService zapReportServiceImpl;

	@Value("${zap.server.resource.openAPIUrl}")
	String openAPIUrl;

	@Value("${zap.server.resource.openAPIJsonUrl}")
	String openAPIJsonUrl;

	@Value("${zap.server.resource.setScriptVars}")
	String setScriptVarsUrl;

	@Value("${zap.server.resource.clearGlobalVars}")
	String clearGlobalVarsUrl;

	@Value("${zap.server.writeToFileUrl}")
	String writeToFileUrl;

	@Value("${zap.server.resource.deleteAllAlerts}")
	String deleteAllAlerts;

	@Value("${zap.server.deleteFileUrl}")
	String deleteFileUrl;
	
	@Value("${zap.server.healthzUrl}")
	String healthzUrl;
	
	@Value("${zap.server.fileManager.port}")
	String fileManagerPort;

	@Autowired
	private ZapEvaluationUtils evaluationUtils;

	private static final Logger LOGGER = LoggerFactory.getLogger(ZapApiScanServiceImpl.class);

	@Override
	public List<Evaluation> doAPIScan(ZapAuthConfig zapAuthConfig, String contextName, AssetProfile assetProfile,
			Asset asset) {
		
	

		HttpHeaders headers = authManager.getAuthenticationHeader();
		// set `content-type` header
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		String apiScanURL = StringUtils.EMPTY;
		var jsonFilePath = StringUtils.EMPTY;

		try {

			if (StringUtils.isEmpty(zapAuthConfig.getSwaggerUrl()) && StringUtils.isEmpty(zapAuthConfig.getApiJSON())) {
				LOGGER.error("No URL / JSON file found for request");
				return new ArrayList<>();
			}
		

			zapUtil.callRestAPI(deleteAllAlerts);	

			zapUtil.callRestAPI(clearGlobalVarsUrl);			

			
			String urlToSetGlobalVars = setScriptVarsUrl;			

			
			String requestAuthTypeValues = ZapApiConstants.GBL_VAR_AUTHTYPE + zapAuthConfig.getAuthenticationType();
			urlToSetGlobalVars = urlToSetGlobalVars.concat(requestAuthTypeValues);
			zapUtil.callRestAPI(urlToSetGlobalVars);
			LOGGER.debug("Setting Authentication Type {}",requestAuthTypeValues);

			String urlToSetAuthKey = setScriptVarsUrl;
			String authKey = getAuthKeyValue(zapAuthConfig);
			String requestAuthKeyValues = ZapApiConstants.GBL_VAR_AUTHKEY + authKey;
			urlToSetAuthKey = urlToSetAuthKey.concat(requestAuthKeyValues);
			zapUtil.callRestAPI(urlToSetAuthKey);
			LOGGER.debug("Setting Authentication Key {}",requestAuthKeyValues);

			String urlToSetAuthToken = setScriptVarsUrl;
			String authToken = getAuthTokenValue(zapAuthConfig);
			String requestAuthTokenValues = ZapApiConstants.GBL_VAR_AUTHTOKEN + authToken;
			urlToSetAuthToken = urlToSetAuthToken.concat(requestAuthTokenValues);
			zapUtil.callRestAPI(urlToSetAuthToken);
			LOGGER.debug("Setting Authentication Token values...Done! ");

			if (zapAuthConfig.getHeaders() != null && !zapAuthConfig.getHeaders().isEmpty()) {				
				String urlToSetAuthHeader = zapUtil.buildAPIEndpointURL(setScriptVarsUrl);
				Map<String, String> headersMap = zapAuthConfig.getHeaders().stream()
						.collect(Collectors.toMap(AuthHeader::getHeaderKey, AuthHeader::getHeaderValue));
				JSONObject headersJson = new JSONObject(headersMap);
				String requestHeadersValues = ZapApiConstants.GBL_VAR_HEADERS + headersJson;
				HttpEntity<String> requestHeadersEntity = new HttpEntity<>(requestHeadersValues, headers);
				restTemplate.postForEntity(urlToSetAuthHeader, requestHeadersEntity, String.class);
				
			}

			String contextId = zapContext.createNewContext(contextName);
			if (StringUtils.isEmpty(contextId)) {
				LOGGER.debug("Context Id not created...continuing API scan without contextId");
				contextId = "";

			}

			String requestParams = "";
			if (ZapApiConstants.DISCVRY_TOOL_SWAGGER.equalsIgnoreCase(zapAuthConfig.getDiscoveryTool())) {
				LOGGER.debug("Swagger URL to be scanned is : {}  ", zapAuthConfig.getSwaggerUrl());
				apiScanURL = zapUtil.buildAPIEndpointURL(openAPIUrl);
				if (zapAuthConfig.getUrl() != null)
					requestParams = ZapApiConstants.OPEN_API_URL + zapAuthConfig.getSwaggerUrl() + "&hostOverride="
							+ zapAuthConfig.getUrl() + ZapApiConstants.CONTEXT_ID + contextId;
				else
					requestParams = ZapApiConstants.OPEN_API_URL + zapAuthConfig.getSwaggerUrl()
							+ ZapApiConstants.CONTEXT_ID + contextId;
			} else if (ZapApiConstants.DISCVRY_TOOL_JSON.equalsIgnoreCase(zapAuthConfig.getDiscoveryTool())) {
				LOGGER.debug("API Json UI FileName : {}  ", zapAuthConfig.getApiJSONFileName());				
				String healthFileEndpoint = healthzUrl.replace(ZapApiConstants.HOSTNAME_PARAM, authManager.getZapAuthServerInfo().getZapAddress() + ":" + fileManagerPort);
				ResponseEntity<String> responseEntity = restTemplate.exchange(healthFileEndpoint, HttpMethod.GET,new HttpEntity<Void>(authManager.getAuthenticationHeader()),String.class);				
				LOGGER.debug("Health check from utility : {}  ", responseEntity);				
				apiScanURL = zapUtil.buildAPIEndpointURL(openAPIJsonUrl);
				JSONObject reportJsonObject = new JSONObject();
				reportJsonObject.put("fileContent", zapAuthConfig.getApiJSON());
				HttpHeaders fileUploadHeader = authManager.getAuthenticationHeader();
				fileUploadHeader.setContentType(MediaType.APPLICATION_JSON);
				
				HttpEntity<String> requestFileUploadEntity = new HttpEntity<>(reportJsonObject.toString(),
						fileUploadHeader);
				String writeToFileEndpoint = writeToFileUrl.replace(ZapApiConstants.HOSTNAME_PARAM, authManager.getZapAuthServerInfo().getZapAddress() + ":" + fileManagerPort);
				
				LOGGER.debug("File Upload url : {}  ", writeToFileEndpoint);
				ResponseEntity<String> responseFileUpload = restTemplate.postForEntity(writeToFileEndpoint,
						requestFileUploadEntity, String.class);
				jsonFilePath = getJsonFilePath(jsonFilePath, responseFileUpload);
				LOGGER.debug("API Json File Path : {}  ", jsonFilePath);				
			
				requestParams = ZapApiConstants.OPEN_API_JSON + jsonFilePath + "&target=" + zapAuthConfig.getUrl()
						+ ZapApiConstants.CONTEXT_ID + contextId;

			}

			LOGGER.debug("Request  values : {}", requestParams);

			// build the request
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			HttpEntity<String> scanEntity = new HttpEntity<>(requestParams, headers);

			// send POST request
			LOGGER.debug("Scan Request Url : {}", apiScanURL);
			ResponseEntity<String> response = restTemplate.postForEntity(apiScanURL, scanEntity, String.class);

			if (response.getStatusCode().is2xxSuccessful()) {
				LOGGER.debug("API Scan successful : {}", response.getStatusCode());
			} else {
				LOGGER.debug("API Scan Failed : {}", response);
			}

			ZapResponse zapResponse = zapReportServiceImpl.generateReport(contextName);

			return evaluationUtils.generateEvaluations(asset, assetProfile, zapResponse, null,contextName);

		} catch (Exception exp) {

			throw new PluginException("Error on API Scan ", exp);

		} finally {
			// commented out for integration testing
			try {
				if (ZapApiConstants.DISCVRY_TOOL_JSON.equalsIgnoreCase(zapAuthConfig.getDiscoveryTool())) {
					deleteTempJsonFile(jsonFilePath);
				}
			} catch (Exception e) {						
				LOGGER.error("Error when cleaning up temp json file {} ", e.getMessage());
			}

		}

	}

	private void deleteTempJsonFile(String jsonFilePath) {
		LOGGER.debug("In Delete Temp Json file");
		HttpHeaders headersDelete = authManager.getAuthenticationHeader();
		HttpEntity<String> deleteEntity = new HttpEntity<>(headersDelete);
		int index = jsonFilePath.lastIndexOf(File.separator)+1;
		String fileName = jsonFilePath.substring(index);
		LOGGER.debug("File name of Temp File to be deleted {}",fileName);
		String deleteFileEndpoint = deleteFileUrl.replace(ZapApiConstants.HOSTNAME_PARAM, authManager.getZapAuthServerInfo().getZapAddress() + ":" + fileManagerPort);
		ResponseEntity<String> responseFileDelete = restTemplate.exchange(deleteFileEndpoint.replace("{fileName}", fileName),
				HttpMethod.DELETE, deleteEntity, String.class);
			JSONObject response = new JSONObject(responseFileDelete.getBody());
			if (responseFileDelete.getStatusCode().is2xxSuccessful()
					|| "success".equals(response.getString("result"))) {
				LOGGER.debug("The file is deleted successfully {} ", jsonFilePath);
			} else {
				LOGGER.error("Error when deleting file - {} {} ", jsonFilePath, responseFileDelete.getBody());
			}		
	}

	private String getJsonFilePath(String jsonFilePath, ResponseEntity<String> responseFileUpload) {
		if (responseFileUpload != null) {
			LOGGER.debug("File Upload Response {} ",responseFileUpload );
			JSONObject response = new JSONObject(responseFileUpload.getBody());
			if (responseFileUpload.getStatusCode().is2xxSuccessful()
					|| "success".equals(response.getString("result"))) {
				jsonFilePath = response.getString("filePath");
			} else {
				LOGGER.error("Path not specified or incorrect - {} {} ", jsonFilePath, responseFileUpload.getBody());
				throw new PluginException("Error on API Scan - Json file path not specified or incorrect ");
			}
		}
		return jsonFilePath;
	}

	private String getAuthTokenValue(ZapAuthConfig zapAuthConfig) {
		String authToken;
		if (zapAuthConfig.getAuthenticationType().equalsIgnoreCase(ZapApiConstants.BASIC_AUTH_TYPE)) {
			String authTkn = zapAuthConfig.getAuthenticationKey() + ":" + zapAuthConfig.getAuthenticationValue();
			authToken = Base64.getEncoder().encodeToString(authTkn.getBytes());
		} else {
			authToken = zapAuthConfig.getAuthenticationValue();
		}
		return authToken;
	}

	private String getAuthKeyValue(ZapAuthConfig zapAuthConfig) {
		String authKey;
		if (zapAuthConfig.getAuthenticationType().equalsIgnoreCase(ZapApiConstants.BASIC_AUTH_TYPE)) {
			authKey = ZapApiConstants.BASIC_AUTH_TYPE;
		} else {
			authKey = zapAuthConfig.getAuthenticationKey();
		}
		return authKey;
	}

}
