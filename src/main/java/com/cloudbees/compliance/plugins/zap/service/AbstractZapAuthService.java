package com.cloudbees.compliance.plugins.zap.service;

import java.io.UnsupportedEncodingException;
import java.util.Set;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthConfig;
import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validation;
import jakarta.validation.Validator;

public abstract class AbstractZapAuthService implements ZapAuthService {

	static final Logger LOGGER = LoggerFactory.getLogger(AbstractZapAuthService.class);
	
	@Value("${zap.server.resource.setLoggedOutIndicator}")
	String setLoggedOutIndicator;
	
	@Value("${zap.server.resource.setLoggedInIndicator}")
	String setLoggedInIndicator;
	
	@Value("${zap.server.resource.authenticateAsUser}")
	String authenticateAsUser;
	
	@Autowired
	ZapUtil zapUtils;
	

	public void setAuthenticationMethod(ZapAuthConfig authConfig, String contextId)
			throws  UnsupportedEncodingException {
	}

	public void setUserAuthConfig(ZapAuthConfig authConfig, String contextId, String userId)
			throws  UnsupportedEncodingException {
	}

	public final void validateContextMetaData(ZapAuthConfig zapConfig) {
		Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
		Set<ConstraintViolation<ZapAuthConfig>> violations = validator.validate(zapConfig);
		
		if (!violations.isEmpty()) {
			StringBuilder sb = new StringBuilder();
			for (ConstraintViolation<ZapAuthConfig> constraintViolation : violations) {
				sb.append(constraintViolation.getMessage());
			}
			throw new ConstraintViolationException("Error occurred in zap configuration pojo class: " + sb.toString(), violations);
		}
		LOGGER.info("ZAP Config is Valid: {}", zapConfig);
	}


	
	public final String setLoggedInIndicator(String contextId, String loggedInIndicatorRegex)
			throws Exception {
		
		if (loggedInIndicatorRegex != null && !loggedInIndicatorRegex.isEmpty()) {
			String setLoggedInIndicatorUrl = setLoggedInIndicator.replace(ZapApiConstants.LOGIN_REGEX, loggedInIndicatorRegex).replace(ZapApiConstants.CONTEXTID, contextId);			
			ResponseEntity<String> response = zapUtils.callRestAPI(setLoggedInIndicatorUrl);
			String value = "";
			if(HttpStatus.OK.equals(response.getStatusCode())) {
				LOGGER.debug("configured logged In indicator regex: {}",response.getBody());
				JSONObject json = new JSONObject(response.getBody());
				value = json.getString("Result");
			}					
			return value;
		}
		return null;
	}


	public final String setLoggedOutIndicator(String contextId, String loggedOutIndicatorRegex)
			throws Exception {
		if (loggedOutIndicatorRegex != null && !loggedOutIndicatorRegex.isEmpty()) {			
			String url = setLoggedOutIndicator.replace(ZapApiConstants.LOGOUT_REGEX, loggedOutIndicatorRegex).replace(ZapApiConstants.CONTEXTID, contextId);	
			ResponseEntity<String> response = zapUtils.callRestAPI(url);
			String value = "";
			if(HttpStatus.OK.equals(response.getStatusCode())) {
				LOGGER.debug("configured logged out indicator regex: {}",response.getBody());
				JSONObject json = new JSONObject(response.getBody());
				value = json.getString("Result");
			}					
			return value;
		}
		return null;
	}

	public final boolean authenticateAsUser(String contextId, String userId) throws Exception {
		String url = authenticateAsUser.replace(ZapApiConstants.CONTEXTID,contextId).replace(ZapApiConstants.USERID, userId);
		ResponseEntity<String> response = zapUtils.callRestAPI(url);
		if(response.getStatusCode().equals(HttpStatus.OK)) {			
			JSONObject jsonResponse = new JSONObject(response.getBody());
			if(response.getBody().contains("authSuccessful")) {
				LOGGER.debug("authSuccessful - {}",jsonResponse.get("authSuccessful"));
				return Boolean.valueOf(jsonResponse.getString("authSuccessful"));
			}
			else if("OK".equals(jsonResponse.getString("Result"))){
				LOGGER.debug("authSuccessful - {}",jsonResponse.get("Result"));
				return true;
			}
			
		}

		return false;
	}

}
