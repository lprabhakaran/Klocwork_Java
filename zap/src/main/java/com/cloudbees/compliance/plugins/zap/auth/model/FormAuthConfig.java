package com.cloudbees.compliance.plugins.zap.auth.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = false)
@ValidLoggedInIndicators()
public class FormAuthConfig extends ZapAuthConfig {

	@NotEmpty(message = "loginPageGetUrl cannot be null")
	@NotNull(message = "loginPageGetUrl cannot be empty")
	private String loginPageGetUrl;
	
	@NotEmpty(message = "loginPageTargetUrl cannot be null")
	@NotNull(message = "loginPageTargetUrl cannot be empty")
	private String loginPageTargetUrl;

}
