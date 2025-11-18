package com.cloudbees.compliance.plugins.zap.auth.model;

import lombok.Data;

@Data
public class AuthHeader {
	
	private String headerKey;
	private String headerValue;

}
