package com.cloudbees.compliance.plugins.zap.response.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class ApplicationAlerts {
	
	@JsonProperty("pluginId")
	private Integer pluginId;
	@JsonProperty("name")
	private String name;
	@JsonProperty("description")
	private String description;
	@JsonProperty("severity")
	private String severity;
	@JsonProperty("references")
	private List<String> references;
	@JsonProperty("uriCount")
	private Integer uriCount;
	@JsonProperty("requestMethod")
	private String requestMethod;
	@JsonProperty("alertStatusStats")
	private List<AlertStatusStats> alertStatusStats;
	@JsonProperty("externalAlertsResult")
	private List<String> externalAlertsResult;
	
	
	
	
	

}
