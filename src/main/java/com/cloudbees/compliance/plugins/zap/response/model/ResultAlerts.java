package com.cloudbees.compliance.plugins.zap.response.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class ResultAlerts {
	
	@JsonProperty("applicationScanResults")
	List<ApplicationScanResults> applicationScanResults;
	@JsonProperty("nextPageToken")
	private Integer nextPageToken;
	@JsonProperty("totalCount")
	private Integer totalCount;
	
	
	

}
