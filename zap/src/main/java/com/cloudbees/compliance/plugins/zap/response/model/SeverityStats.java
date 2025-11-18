package com.cloudbees.compliance.plugins.zap.response.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.ToString;


@Data
@ToString
public class SeverityStats {
	
	@JsonProperty("High")
	private Integer high;
	@JsonProperty("Low")
	private Integer low;
	@JsonProperty("Medium")
	private Integer medium;

}
