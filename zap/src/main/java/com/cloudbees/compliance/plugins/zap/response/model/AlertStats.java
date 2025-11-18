package com.cloudbees.compliance.plugins.zap.response.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class AlertStats {
	
	@JsonProperty("totalAlerts")
	private Integer totalAlerts;
	@JsonProperty("uniqueAlerts")
	private Integer uniqueAlerts;
	
	@JsonProperty("alertStatusStats")
	private List<AlertStatusStats> alertStatusStats;
	
	
	
	
	

}
