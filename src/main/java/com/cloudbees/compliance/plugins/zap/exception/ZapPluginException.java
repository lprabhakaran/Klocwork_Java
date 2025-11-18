package com.cloudbees.compliance.plugins.zap.exception;

import com.cloudbees.compliance.plugins.exception.PluginException;

public class ZapPluginException extends PluginException {

	private static final long serialVersionUID = 1L;

	public ZapPluginException(String msg) {
		super(msg);
	}

	public ZapPluginException(String msg, Throwable cause) {
		super(msg, cause);
	}

}
