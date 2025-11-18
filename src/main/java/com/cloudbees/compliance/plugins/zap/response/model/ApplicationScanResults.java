package com.cloudbees.compliance.plugins.zap.response.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class ApplicationScanResults {
	
	
	@JsonProperty("scan")
	Scan scan;
	@JsonProperty("scanDuration")
	Integer scanDuration;
	@JsonProperty("urlCount")
	Integer urlCount;
	@JsonProperty("alertStats")
	AlertStats alertStats;
	@JsonProperty("severityStats")
	SeverityStats severityStats;
	@JsonProperty("configHash")
	Integer configHash;
	@JsonProperty("appHost")
	String appHost;
	@JsonProperty("applicationAlerts")
	List<ApplicationAlerts> applicationAlerts;
	@JsonProperty("timestamp")
	String timestamp;
	@JsonProperty("scanErrors")
	List<ScanErrors> scanErrors;
	@JsonProperty("scanProgress")
	ScanProgress scanProgress;
	@JsonProperty("percentComplete")
	Integer percentComplete;
	@JsonProperty("policyName")
	String policyName;
	@JsonProperty("externalAlertStats")
	List<String> externalAlertStats;
	@JsonProperty("tags")
	List<String> tags;
	
	
	
	
	
	
	
	

	
}