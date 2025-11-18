package com.cloudbees.compliance.plugins.zap.auth.model;

import java.net.MalformedURLException;
import java.net.URL;

import com.cloudbees.compliance.plugins.zap.exception.ZapPluginException;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@ToString(callSuper = true)
@RequiredArgsConstructor
@Data
@EqualsAndHashCode(callSuper = false)
@ValidLoggedInIndicators
public class ScriptAuthConfig extends ZapAuthConfig {

	@NotEmpty(message = "firstGetURI cannot be null")
	@NotNull(message = "firstGetURI cannot be empty")
	private String firstGetURI;

	@NotEmpty(message = "loginHostname cannot be null")
	@NotNull(message = "loginHostname cannot be empty")
	private String loginHostname;

	@NotEmpty(message = "redirectURI cannot be null")
	@NotNull(message = "redirectURI cannot be empty")
	private String redirectURI;

	public void setLoginHostname(String loginHostname) {
		try {
			URL url = new URL(loginHostname);
			// removing '/' at end if present
			if (loginHostname.endsWith("/")) {
				loginHostname = loginHostname.substring(0, loginHostname.length() - 1);
			}
		} catch (MalformedURLException e) {
			throw new ZapPluginException("Invalid loginHostname: " + e.getMessage());
		}
		this.loginHostname = loginHostname;
	}

	public void setRedirectURI(String redirectURI) {
		String redirectURIWithTrailingSlash = redirectURI;
		try {
			// checks for a valid url
			URL url = new URL(redirectURI);
			if (!redirectURIWithTrailingSlash.endsWith("/"))
				redirectURIWithTrailingSlash = redirectURIWithTrailingSlash.concat("/");

		} catch (MalformedURLException e) {
			throw new ZapPluginException("Invalid redirectURI: " + e.getMessage());
		}
		this.redirectURI = redirectURIWithTrailingSlash;
	}

	public void setFirstGetURI(String firstGetURI) {
		if (!firstGetURI.startsWith("/"))
			firstGetURI = "/" + firstGetURI;
		if (firstGetURI.endsWith("/")) {
			firstGetURI = firstGetURI.substring(0, firstGetURI.length() - 1);
		}
		this.firstGetURI = firstGetURI;
	}

}
