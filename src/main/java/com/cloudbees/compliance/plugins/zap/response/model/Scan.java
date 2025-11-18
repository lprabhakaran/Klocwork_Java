package com.cloudbees.compliance.plugins.zap.response.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class Scan {
	
	@JsonProperty("id")
	private String scanId;
	@JsonProperty("repoId")
	private String repoId;
	@JsonProperty("version")
	private String version;
	@JsonProperty("applicationId")
	private String applicationId;
	@JsonProperty("externalUserId")
	private String externalUserId;
	@JsonProperty("env")
	private String env;
	@JsonProperty("status")
	private String status;
	@JsonProperty("applicationName")
	private String applicationName;
	@JsonProperty("timestamp")
	private String timestamp;
	@JsonProperty("envId")
	private String envId;
	
}
