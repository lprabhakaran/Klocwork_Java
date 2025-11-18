package com.cloudbees.compliance.plugins.zap.service;

import java.util.List;

public interface ZapScanService {

	
	public boolean runActiveScan(List<String> pathsToScan, String contextId, String userId);
	public List<String> runSpider(List<String> pathsToScan, String contextId, String contextName, String userId);

}
