package com.cloudbees.compliance.plugins.zap.service.impl;

import static com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants.AUTHO_AUTH_SCRIPT_NAME;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.ZAP_SCRIPT_BASED_AUTHENTICATION;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.SCRPIT_BASED_AUTH_CREDENTIALS_PARAM_NAMES.PASSWORD;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.SCRPIT_BASED_AUTH_CREDENTIALS_PARAM_NAMES.USERNAME;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.SCRPIT_BASED_AUTH_REQUIRED_PARAM_NAMES.DASHBOARD_HOSTNAME;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.SCRPIT_BASED_AUTH_REQUIRED_PARAM_NAMES.FIRST_GET_URI;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.SCRPIT_BASED_AUTH_REQUIRED_PARAM_NAMES.LOGIN_HOSTNAME;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.SCRPIT_BASED_AUTH_REQUIRED_PARAM_NAMES.PASSWORD_FIELD;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.SCRPIT_BASED_AUTH_REQUIRED_PARAM_NAMES.SCRIPT_NAME;
import static com.cloudbees.compliance.plugins.zap.constant.ZapAuthConstants.SCRPIT_BASED_AUTH_REQUIRED_PARAM_NAMES.USERNAME_FIELD;

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
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.cloudbees.compliance.plugins.utils.MaskingUtils;
import com.cloudbees.compliance.plugins.zap.auth.ZapAuthManager;
import com.cloudbees.compliance.plugins.zap.auth.model.ScriptAuthConfig;
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthConfig;
import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.cloudbees.compliance.plugins.zap.service.AbstractZapAuthService;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;

@Service("Auth0ServiceImpl")
@Primary
public class ScriptAuthServiceImpl extends AbstractZapAuthService {

	private static final Logger LOGGER = LoggerFactory.getLogger(ScriptAuthServiceImpl.class);
	
	@Value("${zap.server.resource.setAuthenticationMethod}")
	String setAuthenticationMethod;
	

	@Autowired
	ZapAuthManager authManager;
	
	@Autowired
	@Qualifier("restTemplate")
	RestTemplate restTemplate;
	
	
	@Autowired
	ZapUtil utils;
	
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
	
	
	
	
	@Override
	public void setAuthenticationMethod(ZapAuthConfig authConfig, String contextId) throws UnsupportedEncodingException {		

		ScriptAuthConfig scriptAuthConfig = (ScriptAuthConfig) authConfig;
		
			String authMethodParams = (SCRIPT_NAME +"=" +AUTHO_AUTH_SCRIPT_NAME + "&"+USERNAME_FIELD + "="
				+ scriptAuthConfig.getCredentialsConfig().getUserNameFormFieldName() + "&" + PASSWORD_FIELD + "="
				+ scriptAuthConfig.getCredentialsConfig().getPasswordFormFieldName() + "&" + FIRST_GET_URI + "="
				+ scriptAuthConfig.getFirstGetURI() + "&" + LOGIN_HOSTNAME + "=" + scriptAuthConfig.getLoginHostname()
				+ "&" + DASHBOARD_HOSTNAME + "=" + scriptAuthConfig.getRedirectURI());
		
		
		Map<String,String> params = new HashMap<>();
		params.put("contextId", contextId);
		params.put("authMethodName", ZAP_SCRIPT_BASED_AUTHENTICATION);
		params.put("authMethodConfigParams", authMethodParams);
		String url =  setAuthenticationMethod.concat(utils.encodeAuthParams(params).toString());		
		
		LOGGER.debug("Setting script based authentication configuration as: {}", authMethodParams);
			
		ResponseEntity<String> response = restTemplate.exchange(utils.buildAPIEndpointURL(url), HttpMethod.GET,new HttpEntity<Void>(authManager.getAuthenticationHeader()),String.class);
		LOGGER.debug("Set Authentication Method response {} :",response.getBody());
	
	}

	@Override
	public void setUserAuthConfig(ZapAuthConfig authConfig, String contextId, String userId)
			throws UnsupportedEncodingException {

		StringBuilder userAuthConfig = new StringBuilder();
		userAuthConfig.append(USERNAME)
				.append("=" + URLEncoder.encode(authConfig.getCredentialsConfig().getUsername(), ZapApiConstants.UTF_8));
		userAuthConfig.append("&" + PASSWORD)
				.append("=" + URLEncoder.encode(authConfig.getCredentialsConfig().getPassword(), ZapApiConstants.UTF_8));
		
		Map<String,String> params = new HashMap<>();
		params.put("contextId", contextId);
		params.put("userId", userId);
		params.put("authCredentialsConfigParams", userAuthConfig.toString());
		String maskedUserName = MaskingUtils.maskFullFieldValue(authConfig.getCredentialsConfig().getUsername());
		String maskedPassword = MaskingUtils.maskFullFieldValue(authConfig.getCredentialsConfig().getPassword());

		LOGGER.debug("Setting user authentication configuration as: username - {} password - {}",maskedUserName ,maskedPassword);
		
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
