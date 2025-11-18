package com.cloudbees.compliance.plugins.zap.auth.model;

import com.cloudbees.compliance.plugins.utils.MaskingUtils;
import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ZapAuthServerInfo {

	public ZapAuthServerInfo() {
		/* TODO document why this constructor is empty */ }

	@NotEmpty(message = "api-key cannot be null")
	@NotNull(message = "api-key  cannot be empty")
	private String apiKey;

	@NotEmpty(message = "zapAddress cannot be null")
	@NotNull(message = "zapAddress cannot be empty")
	private String zapAddress;

	private String zapPort;

	public Integer getZapPort() {
		if(zapPort != null && !zapPort.isBlank())
			return Integer.parseInt(zapPort);
		else 
			return Integer.parseInt("0");
	}

	@JsonIgnore
	public String getZapPortString() {
		return zapPort;
	}
	
	@Override
	public String toString() {
		return "[API-Key : " + MaskingUtils.maskFullFieldValue(apiKey)+
				", zapAddress :" + zapAddress+
				", zapPort :" + zapPort+"]";
	}

}
