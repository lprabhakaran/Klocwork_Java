package com.cloudbees.compliance.plugins.zap.service.impl;

import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.ZAP_FORM_BASED_AUTHENTICATION;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.FORM_BASED_AUTH_CREDENTIALS_PARAM_NAMES.PASSWORD;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.FORM_BASED_AUTH_CREDENTIALS_PARAM_NAMES.USERNAME;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.FORM_BASED_AUTH_FORM_PARAMS.LOGIN_REQUEST_DATA;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.FORM_BASED_AUTH_FORM_PARAMS.LOGIN_URL;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.cloudbees.compliance.plugins.utils.MaskingUtils;
import com.cloudbees.compliance.plugins.zap.auth.ZapAuthManager;
import com.cloudbees.compliance.plugins.zap.auth.model.FormAuthConfig;
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthConfig;
import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.cloudbees.compliance.plugins.zap.service.AbstractZapAuthService;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;

@Service("UsernamePasswordAuthServiceImpl")
public class FormAuthServiceImpl extends AbstractZapAuthService {
	
	
	@Value("${zap.server.resource.setAuthenticationMethod}")
	String setAuthenticationMethod;
	
	@Value("${zap.server.resource.getAuthenticationMethod}")
	String getAuthenticationMethod;
	
	@Value("${zap.server.resource.setAuthenticationCredentials}")
	String setAuthenticationCredentials;
	
	@Value("${zap.server.resource.setUserEnabled}")
	String setUserEnabled;
	
	@Value("${zap.server.resource.forcedUserEndpoint}")
	String forcedUserEndpoint;
	
	@Value("${zap.server.resource.setForcedUserModeEnabled}")
	String setForcedUserModeEnabled;
	
	@Value("${zap.server.resource.getUserById}")
	String getUserById;
	
	@Autowired
	@Qualifier("restTemplate")
	RestTemplate restTemplate;
	
	@Autowired
	ZapUtil utils;
	
	@Autowired
	ZapAuthManager authManager;
	
	
	private static final Logger LOGGER = LoggerFactory.getLogger(FormAuthServiceImpl.class);

	@Override
	public void setAuthenticationMethod(ZapAuthConfig authConfig, String contextId)
			throws  UnsupportedEncodingException {

		FormAuthConfig formAuthConfig = (FormAuthConfig) authConfig;

		String loginRequestData = authConfig.getCredentialsConfig().getUserNameFormFieldName() + "={%username%}&"
				+ authConfig.getCredentialsConfig().getPasswordFormFieldName() + "={%password%}";

		StringBuilder formBasedConfig = new StringBuilder();
		formBasedConfig.append(LOGIN_URL).append("=" + URLEncoder.encode(formAuthConfig.getLoginPageGetUrl(), ZapApiConstants.UTF_8));
		formBasedConfig.append("&" + LOGIN_REQUEST_DATA).append("=" + URLEncoder.encode(loginRequestData, ZapApiConstants.UTF_8));
		
		Map<String,String> params = new HashMap<>();
		params.put("contextId", contextId);
		params.put("authMethodName", ZAP_FORM_BASED_AUTHENTICATION);
		params.put("authMethodConfigParams", formBasedConfig.toString());

		LOGGER.debug("Setting form based authentication configuration as: {}", formBasedConfig);
		
		String url =  this.setAuthenticationMethod.concat(utils.encodeAuthParams(params).toString());				
		String setMethodUrl = utils.buildAPIEndpointURL(url);
		

		ResponseEntity<String> response = restTemplate.exchange(setMethodUrl, HttpMethod.GET,new HttpEntity<Void>(authManager.getAuthenticationHeader()),String.class);
		LOGGER.debug("Set Authentication Method response {} :",response.getBody());
		// Check if everything is set up ok
		String getMethodUrl = this.getAuthenticationMethod.replace(ZapApiConstants.CONTEXTID, contextId);
		ResponseEntity<String> checkAuthConfigRes = utils.callRestAPI(getMethodUrl);
		LOGGER.debug("Authentication config: {}", checkAuthConfigRes.getBody());

	}

	@Override
	public void setUserAuthConfig(ZapAuthConfig authConfig, String contextId, String userId)
			throws  UnsupportedEncodingException {

		StringBuilder userAuthConfig = new StringBuilder();
		userAuthConfig.append(USERNAME)
				.append("=" + URLEncoder.encode(authConfig.getCredentialsConfig().getUsername(), ZapApiConstants.UTF_8));
		userAuthConfig.append("&" + PASSWORD)
				.append("=" + URLEncoder.encode(authConfig.getCredentialsConfig().getPassword(), ZapApiConstants.UTF_8));
		
		Map<String,String> params = new HashMap<>();
		params.put("contextId", contextId);
		params.put("userId", userId);
		params.put("authCredentialsConfigParams", userAuthConfig.toString());
		String maskedUserName =  MaskingUtils.maskFullFieldValue(authConfig.getCredentialsConfig().getUsername());
		String maskedPassword = MaskingUtils.maskFullFieldValue(authConfig.getCredentialsConfig().getPassword());

		LOGGER.debug("Setting user authentication configuration as: username - {} password - {}", maskedUserName,maskedPassword
				);
		
		String  authCredsUrl= setAuthenticationCredentials.concat(utils.encodeAuthParams(params).toString());
		makeRestCall(authCredsUrl, "Setting User AuthCreds");
		
		String enableUrl = setUserEnabled.replace(ZapApiConstants.CONTEXTID,contextId).replace(ZapApiConstants.USERID, userId);		
		makeRestCall(enableUrl, "Enable new user");
		
		String forceUserUrl = forcedUserEndpoint.replace(ZapApiConstants.CONTEXTID,contextId).replace(ZapApiConstants.USERID, userId);		
		makeRestCall(forceUserUrl, "Forced user reponse");
		
		makeRestCall(setForcedUserModeEnabled, "Forced user enable reponse");

		// Check if everything is set up ok
		String getUserByIdUrl = getUserById.replace(ZapApiConstants.CONTEXTID,contextId).replace(ZapApiConstants.USERID, userId);	
		makeRestCall(getUserByIdUrl, "Authentication config");

	}
	
	private void makeRestCall(String url,String message) {
		ResponseEntity<String> response = restTemplate.exchange(utils.buildAPIEndpointURL(url), HttpMethod.GET,new HttpEntity<Void>(authManager.getAuthenticationHeader()),String.class);
		if("Authentication config".equals(message)) {
			JSONObject jsonObj = new JSONObject(response.getBody());
			if(jsonObj.has("credentials")) {
				jsonObj.remove("credentials");
				jsonObj.put("name",MaskingUtils.maskFullFieldValue(jsonObj.get("name").toString()));
			}
			LOGGER.debug("{} : {}",message,jsonObj);
		}else
			LOGGER.debug("{} : {}",message,response.getBody());
	}
	
	

}
