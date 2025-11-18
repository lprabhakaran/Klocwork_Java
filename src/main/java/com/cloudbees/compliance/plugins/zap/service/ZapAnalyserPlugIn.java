package com.cloudbees.compliance.plugins.zap.service;

import java.security.Provider;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import com.cloudbees.compliance.plugins.grpc.service.v040.AnalyserPlugIn;
import com.cloudbees.compliance.plugins.model.AssetType;
import com.cloudbees.compliance.plugins.model.BinaryAttributesType;
import com.cloudbees.compliance.plugins.zap.auth.ZapAuthManager;
import com.cloudbees.compliance.plugins.zap.auth.model.ZapAuthConfig;
import com.cloudbees.compliance.plugins.zap.components.ZapContext;
import com.cloudbees.compliance.plugins.zap.components.ZapScript;
import com.cloudbees.compliance.plugins.zap.constant.ZapApiConstants;
import com.cloudbees.compliance.plugins.zap.exception.ZapPluginException;
import com.cloudbees.compliance.plugins.zap.util.ZapUtil;
import com.cloudbees.compliance.service.v040.Asset;
import com.cloudbees.compliance.service.v040.AssetProfile;
import com.cloudbees.compliance.service.v040.Evaluation;
import com.cloudbees.compliance.service.v040.ExecuteRequest;
import com.cloudbees.compliance.service.v040.MessageType;
import com.cloudbees.compliance.service.v040.StreamMessage;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;

@Service
@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class ZapAnalyserPlugIn extends AnalyserPlugIn {

	private static final Logger LOGGER = LoggerFactory.getLogger(ZapAnalyserPlugIn.class);
	@Autowired
	@Qualifier("zapAuthImpl")
	private ZapAuthManager authManager;
	@Value("${zap.config.heartbeatrate}")
	private long heartBeatRate;
	@Autowired
	private ZapScript zapScript;
	@Autowired
	private ZapHelper zapAuthHelper;
	private List<Evaluation> evaluationList = new ArrayList<>();
	private String contextName;
	@Autowired
	private ZapUtil zapUtil;
	@Autowired
	private ZapContext zapContext;
	@Value("${zap.server.scriptEngineAddOnId}")
	private String scriptEngineAddOnId;
	
	@Autowired
	private ZapApiScanService zapApiScanServiceImpl;

	@Override
	protected AssetType getAssetType() {
		return AssetType.CODE;
	}

	@Override
	protected ArrayList<BinaryAttributesType> getBinaryAttributesTypeList() {
		return new ArrayList<>();
	}

	@Override
	protected List<String> getTags() {
		return new ArrayList<>();
	}
	
	

	@Override
	protected void process(ExecuteRequest executeRequest) {
		LOGGER.debug("In process(executeRequest)");
		
		boolean isApplicationEnv = false;
		
		LOGGER.debug("getAssetSubTypesList values::: "+executeRequest.getAssetSubTypesList() );

		for (String asset : executeRequest.getAssetSubTypesList()) {
			if (asset.equalsIgnoreCase("ch_application_env")) {
				isApplicationEnv = true;
			}
		}
		
		LOGGER.debug("Is Application Env  ::: "+ isApplicationEnv);
		if(!isApplicationEnv) {
			throw new ZapPluginException("Invalid Asset sub type.. Stopping the processing");
		}
		
		if (authManager.authenticate(executeRequest.getMetadata())) {
			LOGGER.debug("ZAP Server authentication successful !!");
			//uploads script required for auth0 auth
			zapScript.uploadScript();
		} else
			LOGGER.error("authentication failure");

		LOGGER.debug("Exit process(executeRequest) method");
	}

	@Override
	protected void process(Asset asset) {		

		try {
			Provider[] providers = Security.getProviders();
			for (int i=0; i < providers.length;i++){
				LOGGER.info("Provider Name : {}", providers[i].getName());
			}
			// It is expected that there is going to be only single profile as ZAP
			// would scan one application at a time.
			if (asset.getProfilesCount() == 0) {
				LOGGER.error("No Asset Profile present to scan.. Stopping the processing");
				throw new ZapPluginException("No Asset Profile Present to scan.. Stopping the processing");
			}

			// Get the asset profile present at first and process it.
			AssetProfile assetProfile = asset.getProfiles(0);
		

			// attributes for context configuration
			ByteString attributes = assetProfile.getAttributes();
			

			if (attributes == null || attributes.isEmpty())
				throw new ZapPluginException("AssetProfile attributes is empty or null");

			// read zap config from attributes
			ZapAuthConfig zapAuthConfig = zapUtil.getConfigDataFromAttr(attributes);
			
			this.contextName = assetProfile.getUuid()
					+ new SimpleDateFormat(ZapApiConstants.DATE_FORMAT).format(new Date());
				
			
			if(ZapApiConstants.API_SCAN.equalsIgnoreCase(zapAuthConfig.getScanType())) {
				LOGGER.debug("Api scan is triggered");
				evaluationList = zapApiScanServiceImpl.doAPIScan(zapAuthConfig,contextName, assetProfile, asset);				
			}else {
				LOGGER.debug("Domain scan is triggered");
				LOGGER.debug("process(Asset asset) - [Asset Profile : {}", assetProfile);
				LOGGER.debug("attributes: {}", attributes);
				evaluationList = zapAuthHelper.getEvaluations(zapAuthConfig, contextName, assetProfile, asset);
			}

		} catch (Exception e) {
			
			throw new ZapPluginException(
					String.format("In process(Asset asset) - [Error while processing Asset, %s , Error Message : %s ]",
							asset.getMasterAsset().getIdentifier(), e.getMessage()),
					e);
		} finally {
			// delete context
			zapContext.deleteContext(this.contextName);
			/*
			 * if (scheduler != null) {
			 * LOGGER.info(ZapApiConstants.HEARTBEAT_SHUTDOWN_MESSAGE);
			 * scheduler.shutdown(); }
			 */
		}
		LOGGER.info("Exit process(Asset asset) method - [Asset identifier is - {}]",
				asset.getMasterAsset().getIdentifier());
	}

	@Override
	protected void processAssetStreamEndMessage(StreamMessage streamMessage) {
		LOGGER.info("Inside processAssetStreamEndMessage() method");
		try {

			LOGGER.debug("Total Evaluation List size: {}", evaluationList.size());
			// Construct a message of type RESPONSE_STREAM_START and send it to CE
			responseObserver.onNext(StreamMessage.newBuilder().setType(MessageType.RESPONSE_STREAM_START).build());
			for (Iterator<Evaluation> it = evaluationList.iterator(); it.hasNext();) {
				Evaluation e = it.next();
				responseObserver.onNext(StreamMessage.newBuilder().setType(MessageType.ANALYSER_RESPONSE)
						.setValue(Any.pack(e)).build());
			}
			responseObserver.onNext(StreamMessage.newBuilder().setType(MessageType.RESPONSE_STREAM_END).build());
			LOGGER.debug("RPC Processed. Initiate Cleanup");
		} catch (Exception e) {
			throw new ZapPluginException(
					String.format("Error while processing for other failure on Asset, %s", e.getMessage()), e);
		} 
		LOGGER.info("exit processAssetStreamEndMessage() method");

	}

	@Override
	protected void processAssetStreamStartMessage(StreamMessage streamMessage) {
	}
}