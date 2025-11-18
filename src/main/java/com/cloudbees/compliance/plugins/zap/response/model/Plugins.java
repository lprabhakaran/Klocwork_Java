package com.cloudbees.compliance.plugins.zap.response.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class Plugins {
	
	@JsonProperty("pluginId")
	private Integer pluginId;
	@JsonProperty("pluginName")
	private String pluginName;
	@JsonProperty("durationMillis")
	private String durationMillis;
	@JsonProperty("numberRequests")
	private Integer numberRequests;
	@JsonProperty("status")
	private String status;
	@JsonProperty("alertCount")
	private Integer alertCount;
	@JsonProperty("messageCount")
	private Integer messageCount;
	@JsonProperty("skippedReason")
	private String skippedReason;
	@JsonProperty("progress")
	private Integer progress;
	
	
	

}
