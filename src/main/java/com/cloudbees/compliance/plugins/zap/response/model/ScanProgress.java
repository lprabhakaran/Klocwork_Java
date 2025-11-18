package com.cloudbees.compliance.plugins.zap.response.model;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class ScanProgress {
	
	@JsonProperty("scanId")
	private String scanId;
	@JsonProperty("plugins")
	private List<Plugins> plugins;
	@JsonProperty("siteStats")
	private Map<String,String> siteStats;
	@JsonProperty("globalStats")
	private Map<String,String> globalStats;
	

}
