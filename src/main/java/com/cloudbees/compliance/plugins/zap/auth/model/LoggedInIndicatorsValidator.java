package com.cloudbees.compliance.plugins.zap.auth.model;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class LoggedInIndicatorsValidator implements ConstraintValidator<ValidLoggedInIndicators, ZapAuthConfig> {

	@Override
	public boolean isValid(ZapAuthConfig value, ConstraintValidatorContext context) {

		if (value.getLoggedOutIndicator() != null && !value.getLoggedOutIndicator().isEmpty()) {
			try {
				Pattern.compile(value.getLoggedOutIndicator());
			} catch (PatternSyntaxException exception) {
				return false;
			}
			return true;
		}

		if (value.getLoggedInIndicator() != null && !value.getLoggedInIndicator().isEmpty()) {
			try {
				Pattern.compile(value.getLoggedInIndicator());
			} catch (PatternSyntaxException exception) {
				return false;
			}
			return true;
		}
		return true;
	}
	

}
