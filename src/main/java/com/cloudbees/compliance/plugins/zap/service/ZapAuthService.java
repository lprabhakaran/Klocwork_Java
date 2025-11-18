package com.cloudbees.compliance.plugins.zap.service;

import java.io.UnsupportedEncodingException;

import org.springframework.stereotype.Service;

import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthConfig;

@Service
public interface ZapAuthService {

	public void setAuthenticationMethod(ZapAuthConfig authConfig, String contextId)
			throws  UnsupportedEncodingException;

	public void setUserAuthConfig(ZapAuthConfig authConfig, String contextId, String userId)
			throws  UnsupportedEncodingException;

}
