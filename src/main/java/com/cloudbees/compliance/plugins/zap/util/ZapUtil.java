package com.cloudbees.compliance.plugins.zap.util;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.cloudbees.compliance.plugins.utils.AwsKmsUtils;
import com.cloudbees.compliance.plugins.zap.auth.ZapAuthManager;
import com.cloudbees.compliance.plugins.zap.auth.model.AuthHeader;
import com.cloudbees.compliance.plugins.zap.auth.model.FormAuthConfig;
import com.cloudbees.compliance.plugins.zap.auth.model.ScriptAuthConfig;
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthConfig;
import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.cloudbees.compliance.plugins.zap.exception.ZapPluginException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.ByteString;


@Component
@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class ZapUtil {
	
	@Autowired
	ZapAuthManager authManager;
	@Value("${zap.server.resource.url}")
	String resourceUrl;
	
	@Autowired
	@Qualifier("universalRestTemplate")
	RestTemplate restTemplate;
	
	@Autowired
	private AwsKmsUtils awsKmsUtils;

	public String buildAPIEndpointURL(String apiEndpoint) {
		
		String returnURL = null;
		if(authManager.getZapAuthServerInfo().getZapPort() != 0) {
			returnURL = resourceUrl.replace(ZapApiConstants.HOSTNAME_PARAM, authManager.getZapAuthServerInfo().getZapAddress() + ":" + authManager.getZapAuthServerInfo().getZapPortString())
					.concat(apiEndpoint);
		} else {
			returnURL = resourceUrl.replace(ZapApiConstants.HOSTNAME_PARAM, authManager.getZapAuthServerInfo().getZapAddress())
					.concat(apiEndpoint);
		}
		
		return returnURL;
	}
	
	
	private static final Logger LOGGER = LoggerFactory.getLogger(ZapUtil.class);

	public ZapAuthConfig getConfigDataFromAttr(ByteString attributes) throws ZapPluginException {

		LOGGER.debug("Entry getConfigDataFromAttr()");
		ZapAuthConfig authConfig = new ZapAuthConfig();
		ObjectMapper mapper = new ObjectMapper();
		try {

			JSONObject attributeJSON = new JSONObject(new String(attributes.toByteArray()));

			//LOGGER.debug(" attributes values : {}", attributeJSON);
			

			JSONObject subAttributeJSON = attributeJSON.getJSONObject("sub_attributes");

			//LOGGER.debug("sub attributes values : {}", subAttributeJSON);

			JSONObject zapJSON = subAttributeJSON.getJSONObject("owaspzap_context");

			String context = zapJSON.getString("context");
			String decyptedContext = awsKmsUtils.decryptData(context);
			JSONObject contextObj = new JSONObject(decyptedContext);
			
			boolean contextAvailable = false;

			try {
				contextAvailable = contextObj.getBoolean("contextAvailable");
				LOGGER.debug("contextAvailable value : {}", contextAvailable);
				
				if (contextAvailable) {
					String authType = contextObj.getString("authType");
					if (authType.equals("Auth0"))
						authConfig = mapper.readValue(decyptedContext, ScriptAuthConfig.class);
					else if (authType.equals("UsernamePasswordAuth"))
						authConfig = mapper.readValue(decyptedContext, FormAuthConfig.class);
					else
						authConfig = mapper.readValue(decyptedContext, ZapAuthConfig.class);
				}
			} catch (Exception e) {
				LOGGER.debug("Context is not available.. Defaulting to no context available and proceed further : " + e.getMessage());
			}
			
			authConfig.setContextAvailable(contextAvailable);
			authConfig.setUrl(zapJSON.getString("url"));
			authConfig.setEnv(zapJSON.getString("environment"));
			
			String scanType = StringUtils.EMPTY;
			//set API scan attributes
			if(contextObj.has("scanType"))
				scanType = contextObj.getString("scanType");
			LOGGER.debug("Type of Scan : {}", scanType);	
			if("API".equalsIgnoreCase(scanType)) {	
				populateApiScanConfig(authConfig, contextObj, scanType);
			}

		} catch (Exception e) {
			throw new ZapPluginException(
					"Error while parsing attributes from Profile. Error Message : " + e.getMessage());
		}
		LOGGER.debug("Exit getConfigDataFromAttr()");
		return authConfig;
	}

	private void populateApiScanConfig(ZapAuthConfig authConfig, JSONObject contextObj, String scanType)
			throws JsonProcessingException, JsonMappingException {
		LOGGER.debug("Entry populateApiScanConfig()");	
			if(contextObj.has("discoveryTool"))
				authConfig.setDiscoveryTool(contextObj.getString("discoveryTool"));				
			if(contextObj.has("swaggerURL"))
			authConfig.setSwaggerUrl(contextObj.getString("swaggerURL"));
			if(contextObj.has("apiJSON"))
				authConfig.setApiJSON(contextObj.getString("apiJSON"));
			if(contextObj.has("apiJSONFileName"))
				authConfig.setApiJSONFileName(contextObj.getString("apiJSONFileName"));
			authConfig.setScanType(scanType);
			if(contextObj.has("authenticationKey"))
			authConfig.setAuthenticationKey(contextObj.getString("authenticationKey"));
			if(contextObj.has("authenticationValue"))
			authConfig.setAuthenticationValue(contextObj.getString("authenticationValue"));
			if(contextObj.has("authenticationType"))
			authConfig.setAuthenticationType(contextObj.getString("authenticationType"));
			if(contextObj.has("headers")) {
				JSONArray authHeaderObject =  contextObj.getJSONArray("headers");				
				ObjectMapper objectMapper = new ObjectMapper();
				List<AuthHeader> authHeaderList = objectMapper.readValue(authHeaderObject.toString(),
						new TypeReference<List<AuthHeader>>() {});			
				authConfig.setHeaders(authHeaderList);
			}
			
		
	}

	
	
	public ResponseEntity<String> callRestAPI(String endPoint) {
		String url = buildAPIEndpointURL(endPoint);
		ResponseEntity<String> responseEntity = restTemplate.exchange(url, HttpMethod.GET,new HttpEntity<Void>(authManager.getAuthenticationHeader()),String.class);
		return responseEntity;
		
	}
	
	public  StringBuilder encodeAuthParams(Map<String,String> params ) {
		StringBuilder queryParams = new StringBuilder();	
		for (Map.Entry<String, String> p : params.entrySet()) {
			queryParams.append(encodeQueryParam(p.getKey()));
			queryParams.append('=');
            if (p.getValue() != null) {            	
            	queryParams.append(encodeQueryParam(p.getValue()));
            }
            queryParams.append('&');
        }	
		return queryParams;
	}
	
	public  String encodeQueryParam(String param) {
        try {
            return URLEncoder.encode(param, "UTF-8");
        } catch (UnsupportedEncodingException ignore) {
            LOGGER.error("Error when encoding auth parameter {}",ignore.getMessage());
        }
        return param;
    }
}
	
