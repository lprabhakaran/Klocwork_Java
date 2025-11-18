package com.cloudbees.compliance.plugins.zap.service.impl;

import java.io.IOException;
import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;
import org.springframework.web.client.RestTemplate;

import com.cloudbees.compliance.plugins.zap.auth.ZapAuthManager;
import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.cloudbees.compliance.plugins.zap.exception.ZapPluginException;
import com.cloudbees.compliance.plugins.zap.response.model.ZapResponse;
import com.cloudbees.compliance.plugins.zap.service.ZapReportService;
import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

@Service
public class ZapReportServiceImpl implements ZapReportService {

	private static final Logger LOGGER = LoggerFactory.getLogger(ZapReportServiceImpl.class);
	private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyMMddHHmmss");

	@Value("${zap.server.generateReport}")
	String generateReport;
	
	@Autowired
	ZapAuthManager authManager;

	@Autowired
	@Qualifier("universalRestTemplate")
	RestTemplate restTemplate;
	
	
	@Override
	public ZapResponse generateReport(String contextName) throws IOException {
		LOGGER.debug("in generateReport()");

		String reportName = getReportName(contextName);

		String url = null;
		if(authManager.getZapAuthServerInfo().getZapPort() != 0) {
			url = generateReport.replace(ZapApiConstants.CONTEXT_NAME, reportName)
				.replace(ZapApiConstants.HOSTNAME_PARAM, authManager.getZapAuthServerInfo().getZapAddress() + ":" + authManager.getZapAuthServerInfo().getZapPortString());
		} else {
			
			url = generateReport.replace(ZapApiConstants.CONTEXT_NAME, reportName)
				.replace(ZapApiConstants.HOSTNAME_PARAM, authManager.getZapAuthServerInfo().getZapAddress());
		}
		
		
		ResponseEntity<String> responseEntity = restTemplate.exchange(url, HttpMethod.GET,
				new HttpEntity<Void>(authManager.getAuthenticationHeader()), String.class);
		if (!ObjectUtils.isEmpty(responseEntity) && HttpStatus.OK.equals(responseEntity.getStatusCode())) {

			try {

				Gson gson = new Gson();
				JsonReader reader = new JsonReader(new StringReader(responseEntity.getBody()));
				reader.setLenient(true);
				return gson.fromJson(reader, ZapResponse.class);
			
			} catch (Exception e) {

				throw new ZapPluginException("Error while parsing the zap response : " + e.getMessage());
			}
		}
		
		return null;
	}

	

	protected String getReportName(String contextName) {
		String date = simpleDateFormat.format(new Date());
		return contextName + "-ZAP-Report-" + date;
	}
}
