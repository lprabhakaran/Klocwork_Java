package com.cloudbees.compliance.plugins.zap.service;

import java.io.IOException;

import org.springframework.stereotype.Service;

import com.cloudbees.compliance.plugins.zap.response.model.ZapResponse;

@Service
public interface ZapReportService {

	public ZapResponse generateReport(String contextName) throws IOException;

}
