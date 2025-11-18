package com.cloudbees.compliance.plugins.zap.constant;

import java.util.Arrays;
import java.util.List;

import com.cloudbees.compliance.plugins.grpc.model.DetailContext;

public class ZapApiConstants {

	private ZapApiConstants() {
	}

	public static final String AUTHO_AUTH_SCRIPT_NAME = "auth0-auth.js";
	public static final String AUTHO_AUTH_SCRIPT_TYPE = "authentication";
	public static final String HEARTBEAT_SHUTDOWN_MESSAGE = "Scheduler for sending heartbeat is shutdown";
	public static final String SERVICE_NAME_SUFFIX = "ServiceImpl";
	public static final String AUTHO_AUTH_SCRIPT_ALREADY_EXISTS = "Already Exists";
	public static final String SCRIPT_ENGINE_DOES_NOT_EXISTS = "Does Not Exist";
	public static final String SPIDER_SCAN_RETRY = "spiderScan";
	public static final String ACTIVE_SCAN_RETRY = "activeScan";
	public static final String ZAP_REPORT_TEMPLATE = "traditional-json";	
	public static final String CWEID_CODE_PREFIX = "CWE-";
	public static final String DATE_FORMAT = "yyMMddHHmmssSSS";
	public static final String HOSTNAME_PARAM = "$hostName$";
	public static final String API_KEY = "{apiKey}";
	public static final String REG_EX = "{regex}";
	public static final String CONTEXT_NAME = "{contextName}";
	public static final String SCRIPT_ENGINE = "{scriptEngine}";
	public static final String RECURSE = "{recurse}";
	public static final String SUBTREEONLY = "{subtreeOnly}";
	public static final String URLTOSCAN = "{url}";
	public static final String MAXCHILD = "{maxChildren}";
	public static final String SCANID = "{scanId}";
	public static final String ADDONID = "{addOnId}";
	public static final String CONTEXTID = "{contextId}";
	public static final String AUTHPARAMS = "authMethodConfigParams";
	public static final String LOGOUT_REGEX = "{logoutRegex}";
	public static final String LOGIN_REGEX = "{loginRegex}";
	public static final String  USERNAME = "{username}";
	public static final String  USERID = "{userId}";
	public static final String  SCRIPTENGINE = "{scriptEngine}";
	public static final String API_SCAN = "API";
	public static final String GBL_VAR_AUTHTYPE = "?varKey=authenticationType&varValue=";
	public static final String GBL_VAR_AUTHKEY = "?varKey=authenticationKey"+"&varValue=";
	public static final String GBL_VAR_AUTHTOKEN = "?varKey=authorizationToken"+"&varValue=";
	public static final String GBL_VAR_HEADERS = "varKey=requestHeaders"+"&varValue=";
	public static final String DISCVRY_TOOL_SWAGGER = "Swagger";
	public static final String DISCVRY_TOOL_JSON = "JSON";
	public static final String OPEN_API_URL = "url=";
	public static final String OPEN_API_JSON = "file=";
	public static final String CONTEXT_ID = "&contextId=";
	public static final String BASIC_AUTH_TYPE = "Basic";
	public static final String UTF_8 = "UTF-8";
	public static final String ZAP_SPIDER_MAXCHILDREN = "zap.config.spiderScan.maxchildren";
	public static final String STRING_TYPE = "String";  
	public static final String LINK_TYPE = "csv[link]";  
	public static final String JSON_TYPE = "json";  
	public static final long RETRY_SLEEP_DURATION = 7000l;
	public static final int RETRY_COUNT=8;
	public static final List<String> detailHeaders = Arrays.asList("Name","Risk","Paths", "Solution", "References","Other Info","Instances");
	public static final List<String> detailTypes = Arrays.asList(STRING_TYPE, STRING_TYPE, LINK_TYPE, STRING_TYPE, LINK_TYPE,STRING_TYPE,JSON_TYPE);
	public static final List<String> detailContexts = Arrays.asList(DetailContext.SUMMARY.toString(),DetailContext.SUMMARY.toString(),DetailContext.SUMMARY.toString(),
			DetailContext.DETAIL.toString(), DetailContext.DETAIL.toString(), DetailContext.DETAIL.toString(), DetailContext.DETAIL.toString());
	public static final String VERY_HIGH = "VERY_HIGH";
	

	
	
	
	
	
	public enum RISK_CODE {
		
		INFORMATIONAL(0), LOW(1), MEDIUM(2), HIGH(3);

		private static final RISK_CODE[] VALUES = RISK_CODE.values();

		private int level;

		private RISK_CODE(int i) {
			this.level = i;
		}

		public Integer getValue() {
			return this.level;
		}

		public static RISK_CODE getByValue(Integer value) {
			for (RISK_CODE e : VALUES) {
				if (e.getValue().equals(value)) {
					return e;
				}
			}
			return null;
		}
	}

}
