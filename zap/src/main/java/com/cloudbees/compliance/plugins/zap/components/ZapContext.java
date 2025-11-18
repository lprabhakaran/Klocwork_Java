package com.cloudbees.compliance.plugins.zap.components;

import java.util.List;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;

@Service
public class ZapContext {

	

	@Value("${zap.server.resource.addOnScriptEndpoint}")
	String addOnScriptEndpoint;
	
	@Value("${zap.server.resource.createNewContextEndpoint}")
	String createNewContextEndpoint;
	
	@Value("${zap.server.resource.includeInContextEndpoint}")
	String includeInContextEndpoint;
	
	@Value("${zap.server.resource.excludeInContextEndpoint}")
	String excludeInContextEndpoint;
	
	@Value("${zap.server.resource.viewContext}")
	String viewContext;
	
	@Value("${zap.server.resource.removeContext}")
	String removeContext;
	
	
	@Autowired
	ZapUtil utils;
	
	
	private static final Logger LOGGER = LoggerFactory.getLogger(ZapContext.class);


	
	public void includeInContext(String contextName, List<String> regexes)  {
		for (String regex : regexes) {
			String url = includeInContextEndpoint.replace(ZapApiConstants.CONTEXT_NAME, contextName).replace(ZapApiConstants.REG_EX, regex);
			ResponseEntity<String> responseEntity = utils.callRestAPI(url);
					LOGGER.debug("{} include in context response: {}", regex, responseEntity.getBody());			
		}

	}


	
	public void excludeFromContext(String contextName, List<String> regexes)  {
		for (String regex : regexes) {
			String url = excludeInContextEndpoint.replace(ZapApiConstants.CONTEXT_NAME, contextName).replace(ZapApiConstants.REG_EX, regex);
			ResponseEntity<String> responseEntity = utils.callRestAPI(url);
			LOGGER.debug("{} exclude from context response: {}", regex, responseEntity.getBody());
		}
	}


	
	public String createNewContext(String contextName)  {
		String url =createNewContextEndpoint.replace(ZapApiConstants.CONTEXT_NAME, contextName);
		ResponseEntity<String> responseEntity = utils.callRestAPI(url);
		if(!ObjectUtils.isEmpty(responseEntity) && HttpStatus.OK.equals(responseEntity.getStatusCode())) {
			JSONObject jsonRes = new JSONObject(responseEntity.getBody());
			return jsonRes.getString("contextId");
		}
		return null;
	}


	
	
	public void deleteContext(String contextName) {
	if (contextExists(contextName)) {
			try {
			String url =removeContext.replace(ZapApiConstants.CONTEXT_NAME, contextName);
				ResponseEntity<String> responseEntity = utils.callRestAPI(url);
				if(!ObjectUtils.isEmpty(responseEntity) && HttpStatus.OK.equals(responseEntity.getStatusCode())) {
					JSONObject jsonRes = new JSONObject(responseEntity.getBody());
					String value =  jsonRes.getString("Result");
					LOGGER.debug("deleted context with name: {} | result: {}", contextName, value);
				}
		
			} catch (Exception e) {
				LOGGER.error("error occured while deleting context: {}", e.getMessage());
			}
		} else
			LOGGER.debug("context with name: {} doesnt exist/deleted already", contextName);
	}


	
	public boolean contextExists(String contextName) {
		try {
			String url =viewContext.replace(ZapApiConstants.CONTEXT_NAME, contextName);
			ResponseEntity<String> responseEntity = utils.callRestAPI(url);
			if(!ObjectUtils.isEmpty(responseEntity) && HttpStatus.OK.equals(responseEntity.getStatusCode())) 
				return true;
			
		}catch(Exception e) {
			LOGGER.debug("In contextExists method- context with name: {} doesnt exist/deleted already", contextName);
			
		}
		return false;	
			
	}

}
