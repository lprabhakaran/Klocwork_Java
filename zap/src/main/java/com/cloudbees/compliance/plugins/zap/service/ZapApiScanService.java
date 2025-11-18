package com.cloudbees.compliance.plugins.zap.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthConfig;
import com.cloudbees.compliance.service.v040.Asset;
import com.cloudbees.compliance.service.v040.AssetProfile;
import com.cloudbees.compliance.service.v040.Evaluation;

@Service
public interface ZapApiScanService {
	
	public List<Evaluation> doAPIScan(ZapAuthConfig zapAuthConfig,String contextName,AssetProfile assetProfile, Asset asset);

}
