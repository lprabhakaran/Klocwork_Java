package com.cloudbees.compliance.plugins.zap.response.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class ReportResult {
	
	@JsonProperty("alert")
	private ZapAlert alert;
	@JsonProperty("category")
	private String category;
	@JsonProperty("cheetsheet")
	private String cheetsheet;
	@JsonProperty("appHost")
	private String appHost;
	@JsonProperty("isEachRuleLocked")
	private Boolean isEachRuleLocked;
	@JsonProperty("nextPageToken")
	private Integer nextPageToken;
	@JsonProperty("totalCount")
	private Integer totalCount;

	@JsonProperty("applicationScanAlertUris")
	private List<ApplicationScanAlertUris> applicationScanAlertUris;
	
	
	

}
