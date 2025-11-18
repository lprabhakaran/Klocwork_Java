package com.cloudbees.compliance.plugins.zap.auth.model;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.cloudbees.compliance.plugins.zap.exception.ZapPluginException;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class ZapAuthConfig {

	private String env;

	@NotEmpty(message = "url cannot be null")
	@NotNull(message = "url cannot be empty")
	private String url;

	@JsonProperty("paths")
	@NotEmpty(message = "paths cannot be null")
	@NotNull(message = "paths cannot be empty")
	private List<String> pathsToScan;

	@NotEmpty(message = "includeInContextRegexes cannot be null")
	@NotNull(message = "includeInContextRegexes cannot be empty")
	private List<String> includeInContextRegexes;

	@NotEmpty(message = "excludeFromContextRegexes cannot be null")
	@NotNull(message = "excludeFromContextRegexes cannot be empty")
	private List<String> excludeFromContextRegexes;

	private String loggedInIndicator;

	private String loggedOutIndicator;

	@NotNull(message = "authType cannot be null")
	@NotEmpty(message = "authType cannot be empty")
	private String authType;
	

	private Boolean contextAvailable;
	
	@JsonProperty("credentials")
	CredentialsConfig credentialsConfig;
	
	private String scanType;
	
	private String discoveryTool;
	
	@JsonProperty("swaggerURL")
	private String swaggerUrl;
	
	@JsonIgnoreProperties
	private String apiJSON;
	
	private String authenticationType; //Basic/API Key/Bearer Token
	
	private String authenticationKey;  //
	
	private String authenticationValue;//
	
	
	private String pathToApiJson;//
	
	private List<AuthHeader> headers;
	
	private String apiJSONFileName;
	

	public void setIncludeInContextRegexes(List<String> includeInContextRegexes) {
		if (!includeInContextRegexes.isEmpty()) {
			for (String string : includeInContextRegexes) {
				try {
					Pattern.compile(string);
				} catch (PatternSyntaxException exception) {
					throw new ZapPluginException(
							"Invalid regex in includeInContextRegexes: " + exception.getDescription());
				}
			}
			this.includeInContextRegexes = includeInContextRegexes;
		}
	}

	public void setExcludeFromContextRegexes(List<String> excludeFromContextRegexes) {
		if (!excludeFromContextRegexes.isEmpty()) {
			for (String string : excludeFromContextRegexes) {
				try {
					Pattern.compile(string);
				} catch (PatternSyntaxException exception) {
					throw new ZapPluginException(
							"Invalid regex in excludeFromContextRegexes: " + exception.getDescription());
				}
			}
			this.excludeFromContextRegexes = excludeFromContextRegexes;
		}

	}
}
