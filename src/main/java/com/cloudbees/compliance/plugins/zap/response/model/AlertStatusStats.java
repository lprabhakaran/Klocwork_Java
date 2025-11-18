package com.cloudbees.compliance.plugins.zap.response.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class AlertStatusStats {
	
	
	@JsonProperty("alertStatus")
	private String alertStatus;
	@JsonProperty("totalCount")
	private Integer totalCount;
	@JsonProperty("severityStats")
	private SeverityStats severityStats;
	

}
