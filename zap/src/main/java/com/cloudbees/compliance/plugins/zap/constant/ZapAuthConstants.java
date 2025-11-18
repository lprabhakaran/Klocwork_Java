package com.cloudbees.compliance.plugins.zap.constant;

public class ZapAuthConstants {

	private ZapAuthConstants() {
	}

	public static final String API_KEY_ENV_VAR = "ZAP_API_KEY";
	public static final String ZAP_SCRIPT_BASED_AUTHENTICATION = "scriptBasedAuthentication";
	public static final String ZAP_FORM_BASED_AUTHENTICATION = "formBasedAuthentication";

	public static class SCRPIT_BASED_AUTH_REQUIRED_PARAM_NAMES {
		public static final String SCRIPT_NAME = "scriptName";
		public static final String USERNAME_FIELD = "Username field";
		// deepcode ignore HardcodedPassword: not a password, just a field description
    public static final String PASSWORD_FIELD = "Password field";
		public static final String FIRST_GET_URI = "First get URI with leading slash, without trailing slash";
		public static final String LOGIN_HOSTNAME = "Login Hostname without trailing slash";
		public static final String DASHBOARD_HOSTNAME = "Dashboard Hostname with trailing slash";
	}

	public static class SCRPIT_BASED_AUTH_CREDENTIALS_PARAM_NAMES {
		public static final String USERNAME = "username";
		public static final String PASSWORD = "password";
	}
	
	public static class FORM_BASED_AUTH_CREDENTIALS_PARAM_NAMES {
		public static final String USERNAME = "username";
		public static final String PASSWORD = "password";
	}
	
	public static class FORM_BASED_AUTH_FORM_PARAMS {
		public static final String LOGIN_URL = "loginUrl";
		public static final String LOGIN_REQUEST_DATA = "loginRequestData";
		
	}
	
	public static final String APP_AUTH_FAILURE_MESSAGE = "APP_AUTH_FAILURE";
}
