package com.cloudbees.compliance.plugins.zap.service.impl;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.cloudbees.compliance.plugins.zap.service.ZapScanRetryService;
import com.cloudbees.compliance.plugins.zap.service.ZapScanService;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class ZapScanServiceImpl implements ZapScanService {

	private static final Logger LOGGER = LoggerFactory.getLogger(ZapScanServiceImpl.class);
	@Autowired
	private ZapScanRetryService scanRetryService;
	
	@Autowired
	Environment environment;	

	@Value("${zap.server.resource.runSpiderNoAuth}")
	String runSpiderNoAuth;
	
	@Value("${zap.server.resource.spiderScanResults}")
	String spiderScanResults;
	
	@Value("${zap.server.resource.activeScanNoAuth}")
	String activeScanNoAuth;
	
	@Value("${zap.server.resource.scanAsUserSpider}")
	String scanAsUserSpider;
	
	@Value("${zap.server.resource.activeScanAsUser}")
	String activeScanAsUser;
	
	
	@Autowired
	ZapUtil utils;
	
	public List<String> runSpider(List<String> pathsToScan, String contextId, String contextName, String userId) {
		boolean spiderStatus = false;
		Set<String> results = new LinkedHashSet<>();
		ResponseEntity<String> responseEntity = null;
		String scanID = "";
		for (String target : pathsToScan) {
			LOGGER.info("spidering now: {}", target);
			String url = "";
			try {
				if (userId != null) {
					 url = scanAsUserSpider.replace(ZapApiConstants.CONTEXTID, contextId).replace(ZapApiConstants.URLTOSCAN, target)
							.replace(ZapApiConstants.RECURSE, environment.getProperty("zap.config.spiderScan.recurse")).
							replace(ZapApiConstants.SUBTREEONLY, environment.getProperty("zap.config.spiderScan.subtreeonly"))
							.replace(ZapApiConstants.MAXCHILD, environment.getProperty(ZapApiConstants.ZAP_SPIDER_MAXCHILDREN)).
							replace(ZapApiConstants.USERID, userId);
					 responseEntity = utils.callRestAPI(url);
				
				}
				else {// for no-auth
					 url = runSpiderNoAuth.replace(ZapApiConstants.CONTEXT_NAME, contextName).replace(ZapApiConstants.URLTOSCAN, target)
							.replace(ZapApiConstants.RECURSE, environment.getProperty("zap.config.spiderScan.recurse")).replace(ZapApiConstants.SUBTREEONLY, environment.getProperty("zap.config.spiderScan.subtreeonly"))
							.replace(ZapApiConstants.MAXCHILD, environment.getProperty(ZapApiConstants.ZAP_SPIDER_MAXCHILDREN));
					 responseEntity = utils.callRestAPI(url);
				}
				
				scanID = getSpiderScanId(userId, responseEntity, scanID);
				 
				spiderStatus = scanRetryService.checkSpiderScanStatus(scanID);
				LOGGER.debug("spider scan for target:{} | scanID: {} | success: {}", target, scanID, spiderStatus);
				
				if(spiderStatus) {
					LOGGER.debug("spider sacn completed progress: {}%", "100");
				}
				responseEntity = utils.callRestAPI(spiderScanResults.replace(ZapApiConstants.SCANID, scanID));
				if(!ObjectUtils.isEmpty(responseEntity) && HttpStatus.OK.equals(responseEntity.getStatusCode())) {
					JSONObject jsonRes = new JSONObject(responseEntity.getBody());
					JSONArray spiderResults = jsonRes.getJSONArray("results");
					ObjectMapper mapper = new ObjectMapper(); 
					@SuppressWarnings("unchecked")
					List<String> spiderList = mapper.readValue(spiderResults.toString(), List.class);					
					results.addAll(spiderList.stream().toList());
				}
				
			} catch (Exception e) {
				LOGGER.error("error occured while triggering spider: {}", e.getMessage());
			}
		}
		return new ArrayList<>(results);
	}



	private String getSpiderScanId(String userId, ResponseEntity<String> responseEntity, String scanID) {
		if(!ObjectUtils.isEmpty(responseEntity) && HttpStatus.OK.equals(responseEntity.getStatusCode())){
			JSONObject jsonRes = new JSONObject(responseEntity.getBody());
			if(userId != null)
				scanID = jsonRes.getString("scanAsUser");
			else
				scanID = jsonRes.getString("scan");
			
		}
		return scanID;
	}


	
	@Override
	public boolean runActiveScan(List<String> pathsToScan, String contextId, String userId) {
		boolean activeScanStatus = true;
		ResponseEntity<String> responseEntity = null;
		String scanID = "";
		for (String target : pathsToScan) {
			LOGGER.info("active scan now: {}", target);
			String url = "";
			try {
				if (userId != null) {
					url = activeScanAsUser.replace(ZapApiConstants.CONTEXTID, contextId).replace(ZapApiConstants.URLTOSCAN, target)
							.replace(ZapApiConstants.MAXCHILD, environment.getProperty(ZapApiConstants.ZAP_SPIDER_MAXCHILDREN)).replace(ZapApiConstants.USERID, userId);
				}
				else {// for no-auth
					 url = activeScanNoAuth.replace(ZapApiConstants.CONTEXTID, contextId).replace(ZapApiConstants.URLTOSCAN, target)
							.replace(ZapApiConstants.MAXCHILD, environment.getProperty(ZapApiConstants.ZAP_SPIDER_MAXCHILDREN));
						
					
				}
				responseEntity = utils.callRestAPI(url);
				scanID = getSpiderScanId(userId, responseEntity, scanID);

				activeScanStatus = scanRetryService.checkActiveScanStatus(scanID);
				LOGGER.debug("active scan for target:{} | scanID: {} | success: {}", target, scanID, activeScanStatus);
			} catch (Exception e) {
				LOGGER.error("error occured while running active scan: {}", e.getMessage());
				activeScanStatus = false;
			}
		}
		return activeScanStatus;

	}

}
