package com.cloudbees.compliance.plugins.zap.auth.model;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Documented
@Constraint(validatedBy = LoggedInIndicatorsValidator.class)
@Target({ ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidLoggedInIndicators {

	String message() default "{logged_in_indicator or logged_out_indicator required with valid regex}";

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};
}
