package com.cloudbees.compliance.plugins.zap.service;

import static com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants.ACTIVE_SCAN_RETRY;
import static com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants.SPIDER_SCAN_RETRY;

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
import com.cloudbees.compliance.plugins.zap.exception.ScanNotCompletedException;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;

import io.github.resilience4j.retry.annotation.Retry;

@Service
public class ZapScanRetryService {

	private static final Logger LOGGER = LoggerFactory.getLogger(ZapScanRetryService.class);
	
	

	@Value("${zap.server.resource.spiderScanGetStatus}")
	String spiderScanGetStatus;
	
	@Value("${zap.server.resource.activeScanStatus}")
	String activeScanStatus;
	
	@Autowired
	ZapUtil utils;




	@Retry(name = SPIDER_SCAN_RETRY, fallbackMethod = "spiderScanRetryFallBack")
	public boolean checkSpiderScanStatus(String scanID)
			throws ScanNotCompletedException, NumberFormatException {
		int progress = 0;
		String url = spiderScanGetStatus.replace(ZapApiConstants.SCANID, scanID);
		ResponseEntity<String> responseEntity = utils.callRestAPI(url);
		if(!ObjectUtils.isEmpty(responseEntity) && HttpStatus.OK.equals(responseEntity.getStatusCode())) {
			JSONObject jsonRes = new JSONObject(responseEntity.getBody());
				progress = Integer.parseInt(jsonRes.getString("status"));
		}
		return spideringCompleted(progress);
	}
	
	
	public boolean spideringCompleted(int progress) throws ScanNotCompletedException {
		if (progress != 100) {
			throw new ScanNotCompletedException(progress);
		} else if (progress == 100) {
			//LOGGER.debug("spider sacn completed progress: {}%", progress);
			return true;
		}
		return false;
	}

	public boolean spiderScanRetryFallBack(String scanId, Throwable t) {
		LOGGER.debug("spider scan with id: {} retry error | cause – {}", scanId, t.toString());
		/*if (t instanceof ScanNotCompletedException) {
			try {
				api.getApi().spider.stop(scanId);
				LOGGER.info("stopped spider scan with id: {}", scanId);
			} catch (ClientApiException e) {
				LOGGER.error("Error occured while stopping spider scan: {} | error: {}", scanId, e.getMessage());
			}
		}*/
		return false;
	}


	
	@Retry(name = ACTIVE_SCAN_RETRY, fallbackMethod = "activeScanRetryFallBack")
	public boolean checkActiveScanStatus(String scanID)
			throws ScanNotCompletedException, NumberFormatException {
		int progress = 0;
		String url = activeScanStatus.replace(ZapApiConstants.SCANID, scanID);
		ResponseEntity<String> responseEntity = utils.callRestAPI(url);
		if(!ObjectUtils.isEmpty(responseEntity) && HttpStatus.OK.equals(responseEntity.getStatusCode())) {
			JSONObject jsonRes = new JSONObject(responseEntity.getBody());
				progress = Integer.parseInt(jsonRes.getString("status"));
		}
		return activeScanCompleted(progress);
	}

	public boolean activeScanCompleted(int progress) throws ScanNotCompletedException {
		if (progress != 100) {
			throw new ScanNotCompletedException(progress);
		} else if (progress == 100) {
			//LOGGER.debug("active sacn completed progress: {}%", progress);
			return true;
		}

		return false;
	}

	public boolean activeScanRetryFallBack(String scanId, Throwable t) {
		LOGGER.debug("Active scan with id: {} retry error | cause – {}", scanId, t.toString());
		/*if (t instanceof ScanNotCompletedException) {
			try {
				api.getApi().ascan.stop(scanId);
				LOGGER.info("stopped active scan with id: {}", scanId);
			} catch (ClientApiException e) {
				LOGGER.error("Error occured while stopping active scan: {} | error: {}", scanId, e.getMessage());
			}
		}*/
		return false;
	}

}
