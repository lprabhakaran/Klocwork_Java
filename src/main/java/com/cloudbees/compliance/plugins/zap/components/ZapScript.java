package com.cloudbees.compliance.plugins.zap.components;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.cloudbees.compliance.plugins.zap.exception.ZapPluginException;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;

@Service
public class ZapScript {


	@Value("${zap.server.scriptEngine}")
	private String scriptEngine;
	
	private static final Logger LOGGER = LoggerFactory.getLogger(ZapScript.class);
	
	@Value("${zap.server.filePathName}")
	private String filePathName;
	
	@Value("${zap.server.resource.loadScriptEndpoint}")
	String loadScriptEndpoint;
	
	@Autowired
	ZapUtil utils;	

	
	public String uploadScript() {
		scriptEngine = scriptEngine.replace("-", ":");
		try {
			ResponseEntity<String> responseEntity = utils.callRestAPI(loadScriptEndpoint.replace(ZapApiConstants.SCRIPTENGINE, scriptEngine));
			LOGGER.info("auth0 auth script uploaded !!: {}", responseEntity);
			return responseEntity.getBody();
		} catch (HttpClientErrorException e) {			
			if (e.getMessage().contains(ZapApiConstants.AUTHO_AUTH_SCRIPT_ALREADY_EXISTS))
				LOGGER.info("auth0 auth script already exists !!");
			else if (e.getMessage().contains(ZapApiConstants.SCRIPT_ENGINE_DOES_NOT_EXISTS))
				throw new ZapPluginException("Script Engine ECMAScript : Graal.js not installed!!");
			else
				throw new ZapPluginException("error occured while uploading script: " + e.getMessage());
		}
		return null;
	}
	

	

}
