package com.cloudbees.compliance.plugins.zap.response.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class ApplicationScanAlertUris {
	
	@JsonProperty("scan")
	Scan scan;	
	@JsonProperty("pluginId")
	Integer pluginId;
	@JsonProperty("uri")
	String uri;
	@JsonProperty("msgId")
	Integer msgId;
	@JsonProperty("requestMethod")
	String requestMethod;
	@JsonProperty("status")
	String status;
	@JsonProperty("matchedRuleNote")
	String matchedRuleNote;
	@JsonProperty("matchedRuleLastUpdated")
	String matchedRuleLastUpdated;
	@JsonProperty("appUriId")
	String appUriId;
	@JsonProperty("alertUriId")
	String alertUriId;
	@JsonProperty("matchedRuleUserId")
	String matchedRuleUserId;
	@JsonProperty("ruleHistories")
	List<String> ruleHistories;
	@JsonProperty("statusLink")
	String statusLink;
	
	
	
}
