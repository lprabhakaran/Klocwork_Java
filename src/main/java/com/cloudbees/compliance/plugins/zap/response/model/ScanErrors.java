package com.cloudbees.compliance.plugins.zap.response.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class ScanErrors {
	
	@JsonProperty("error")
	String error;
	@JsonProperty("rawConf")
	String rawConf;
	@JsonProperty("errorDetail")
	String errorDetail;
	@JsonProperty("created")
	String created;
	@JsonProperty("category")
	String category;
}
