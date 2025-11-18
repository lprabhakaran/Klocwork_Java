package com.cloudbees.compliance.plugins.zap.components;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;

@Service
public class ZapAddOn {
	private static final Logger LOGGER = LoggerFactory.getLogger(ZapAddOn.class);	

	@Value("${zap.server.resource.addOnScriptEndpoint}")
	String addOnScriptEndpoint;
	
	@Autowired
	ZapUtil utils;	

	public void installAddon(String addOnId) {
		try {
			LOGGER.info("Addon Script {},",addOnId);
			ResponseEntity<String> responseEntity = utils.callRestAPI(addOnScriptEndpoint.replace(ZapApiConstants.ADDONID, addOnId));
			LOGGER.info("Script Engine ECMAScript : Graal.js installation response: !!: {}", responseEntity);
		} catch (Exception e) {
			LOGGER.error("failure installing addOn: {} | error: {}", addOnId, e.getMessage());
		}
	}


}
