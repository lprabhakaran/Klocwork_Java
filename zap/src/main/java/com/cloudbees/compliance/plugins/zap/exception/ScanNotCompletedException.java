package com.cloudbees.compliance.plugins.zap.exception;

import com.cloudbees.compliance.plugins.exception.PluginException;

public class ScanNotCompletedException extends PluginException {

	private static final long serialVersionUID = 1L;

	public ScanNotCompletedException(int progress) {
		super("Scan is still in progress at " + progress + "%");
	}
}
