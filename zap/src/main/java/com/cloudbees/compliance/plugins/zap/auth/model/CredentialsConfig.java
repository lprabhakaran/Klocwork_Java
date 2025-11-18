package com.cloudbees.compliance.plugins.zap.auth.model;

import com.cloudbees.compliance.plugins.utils.MaskingUtils;
import com.fasterxml.jackson.annotation.JsonSetter;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;



@Data
public class CredentialsConfig {

	private String userNameFormFieldName = "username";
	private String passwordFormFieldName = "password";

	@JsonSetter("userNameFormFieldName")
	public void setUserNameFormFieldName(String userNameFormFieldName) {
		if (userNameFormFieldName != null && !userNameFormFieldName.isEmpty())
			this.userNameFormFieldName = userNameFormFieldName;
	}

	@JsonSetter("passwordFormFieldName")
	public void setPasswordFormFieldName(String passwordFormFieldName) {
		if (passwordFormFieldName != null && !passwordFormFieldName.isEmpty())
			this.passwordFormFieldName = passwordFormFieldName;
	}

	@NotNull(message = "username cannot be null")
	@NotEmpty(message = "username cannot be empty")
	private String username;

	@NotNull(message = "password cannot be null")
	@NotEmpty(message = "password cannot be empty")
	private String password;
	
	@Override
	public String toString() {
		return "[UserName : " + MaskingUtils.maskFullFieldValue(username)
		+      "][Password :" + MaskingUtils.maskFullFieldValue(password);
	}

}
