package com.cloudbees.compliance.plugins.zap.auth;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import com.cloudbees.compliance.plugins.exception.BadParameterException;
import com.cloudbees.compliance.plugins.utils.MaskingUtils;
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthServerInfo;
import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.ByteString;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validation;
import jakarta.validation.Validator;

@Service
@Qualifier("zapAuthImpl")
public class ZapAuthManager {

	private static final Logger LOGGER = LoggerFactory.getLogger(ZapAuthManager.class);
	private ZapAuthServerInfo zapAuthServerInfo;
	
	@Value("${zap.server.resource.url}")
	String resourceUrl;
	@Value("${zap.server.resource.viewContextList}")
	String viewContextList;
	
	@Autowired
	@Qualifier("universalRestTemplate")
	RestTemplate restTemplate;
	


	public boolean authenticate(ByteString metadata) {
		LOGGER.debug("in authenticate()");
		
		HttpEntity<Void> requestEntity = null;
		try {
			if(metadata == null || metadata.size() == 0 ) {				
				LOGGER.error("connection with zap server using metadata failed : Metadata Empty");
				return false;	
			} else {	
				ZapAuthServerInfo auth = getZapAuthFromString(metadata);
				validateZapAuth(auth);
				LOGGER.debug("checking connection with zap server using api key in metadata");
				
				String viewContextListUrl = null;
				if(auth.getZapPort() != 0)
					viewContextListUrl = resourceUrl.replace(ZapApiConstants.HOSTNAME_PARAM, auth.getZapAddress() + ":" + auth.getZapPortString()).concat(viewContextList);
				else
					viewContextListUrl = resourceUrl.replace(ZapApiConstants.HOSTNAME_PARAM, auth.getZapAddress()).concat(viewContextList);
				
				requestEntity = new HttpEntity<>(this.getAuthenticationHeader());			
				LOGGER.debug("checking connection with zap server using api key in metadata {} ",viewContextListUrl);
				ResponseEntity<String> responseEntity = restTemplate.exchange(viewContextListUrl, HttpMethod.GET,requestEntity,String.class);
				if(HttpStatus.OK.equals(responseEntity.getStatusCode())) {
					LOGGER.info("Connected successfully with ZAP Server!: {}", zapAuthServerInfo);
					this.zapAuthServerInfo = auth;	
					return true;
				} else {
					LOGGER.error("connection with zap server using details from metadata failed: {}", responseEntity.getBody());
					return false;
				}				
			}
		} catch (ResourceAccessException | HttpClientErrorException  | ConstraintViolationException e) {
			LOGGER.error("connection with zap server using details from metadata failed: {}", e.getMessage());
			return false;
		}
	}

	public ZapAuthServerInfo getZapAuthFromString(ByteString byteString) {
		String metadata = byteString.toStringUtf8();
		
		String maskedMetaData = MaskingUtils.maskFieldValueIndexBased(metadata,metadata.indexOf("apiKey") + 11,metadata.indexOf("apiKey") + 33);
		LOGGER.debug("in getZapAuthFromString() - metadata : {}",maskedMetaData);
				
		ZapAuthServerInfo auth = null;
		try {
			if (!byteString.isEmpty()) {
				ObjectMapper map = new ObjectMapper();
				auth = map.readValue(byteString.toStringUtf8(), ZapAuthServerInfo.class);
				LOGGER.info("ZAP Server Info from metadata: {}", auth);
			}
		} catch (Exception e) {
			throw new BadParameterException(
					"Error Parsing the Token String extracted from execrequest metadata" + e.getMessage(), e);
		}
		return auth;
	}

	public final void validateZapAuth(ZapAuthServerInfo zapAuthServerInfo) {
		Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
		Set<ConstraintViolation<ZapAuthServerInfo>> violations = validator.validate(zapAuthServerInfo);
		if (!violations.isEmpty()) {
			StringBuilder sb = new StringBuilder();
			for (ConstraintViolation<ZapAuthServerInfo> constraintViolation : violations) {
				sb.append(constraintViolation.getMessage());
			}
			throw new ConstraintViolationException("Error occurred: " + sb.toString(), violations);
		}
		this.zapAuthServerInfo = zapAuthServerInfo;
		LOGGER.info("ZapAuthServerInfo is Valid !!");
	}

	
	/**
	 * This method is called to get the personal access token required for Git Hub
	 * Endpoints
	 * 
	 * @return HttpHeader with personal access token set for rest api call
	 */
	public HttpHeaders getAuthenticationHeader() {
		HttpHeaders authenticationHeader = new HttpHeaders();
		if(zapAuthServerInfo != null && !zapAuthServerInfo.getApiKey().isBlank())
			authenticationHeader.add("X-ZAP-API-Key", zapAuthServerInfo.getApiKey());
		return authenticationHeader;
	}
	
	public ZapAuthServerInfo getZapAuthServerInfo() {
		return this.zapAuthServerInfo;
	}

}
