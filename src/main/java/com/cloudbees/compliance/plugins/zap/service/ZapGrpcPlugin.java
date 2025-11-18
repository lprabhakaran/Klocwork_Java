package com.cloudbees.compliance.plugins.zap.service;

import java.util.ArrayList;

import org.lognet.springboot.grpc.GRpcService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;

import com.cloudbees.compliance.plugins.grpc.model.ServiceManifest;
import com.cloudbees.compliance.plugins.grpc.service.v040.AnalyserPlugIn;
import com.cloudbees.compliance.plugins.grpc.service.v040.AuthValidation;
import com.cloudbees.compliance.plugins.grpc.service.v040.DecoratorPlugIn;
import com.cloudbees.compliance.plugins.grpc.service.v040.GrpcPlugIn;
import com.cloudbees.compliance.plugins.grpc.service.v040.MasterPlugIn;
import com.cloudbees.compliance.plugins.grpc.service.v040.PluginAssetDescriptors;
import com.cloudbees.compliance.plugins.zap.auth.model.ApplicationProperties;
import com.cloudbees.compliance.service.v040.AssetRole;
import com.cloudbees.compliance.service.v040.GetManifestRequest;
import com.cloudbees.compliance.service.v040.GetManifestResponse;
import com.cloudbees.compliance.service.v040.Manifest;
import com.cloudbees.compliance.service.v040.Role;

import io.grpc.stub.StreamObserver;

@GRpcService
public class ZapGrpcPlugin extends GrpcPlugIn{

	private static final Logger logger = LoggerFactory.getLogger(ZapGrpcPlugin.class);
	
	@Autowired
	private ApplicationProperties application;
	
	public ZapGrpcPlugin(ObjectFactory<AnalyserPlugIn> plugInObjectFactory, ServiceManifest serviceManifest,
			ObjectFactory<MasterPlugIn> plugInObjectFactoryMaster,
			ObjectFactory<DecoratorPlugIn> plugInObjectFactoryDecorator,
			ObjectFactory<AuthValidation> authValidationFactory,
			ObjectFactory<PluginAssetDescriptors> assetDescriptorsObjectFactory, Environment environment,
			BeanFactory factory) {
		super(plugInObjectFactory, serviceManifest, plugInObjectFactoryMaster, plugInObjectFactoryDecorator,
				authValidationFactory, assetDescriptorsObjectFactory, environment, factory);
		
	}
	
	@Override
    public void getManifest(GetManifestRequest request, StreamObserver<GetManifestResponse> responseObserver) {

    	logger.info("ZapGrpcPlugin.getManifest(). Processing getManifest");
    	Manifest.Builder manifest = Manifest.newBuilder()
				.setUuid(application.getUuid())
				.setName(application.getName())
				.setVersion(application.getVersion());
    	
    	
    	
    	for (ApplicationProperties.AssetRole ar : application.getAssetRoles()) {
    		ArrayList<String> subAttributes = new ArrayList<>();
        	subAttributes.add(ar.getCreateSubAttributes());
        	
			manifest.addAssetRoles(AssetRole.newBuilder()
					.setRole(Role.valueOf(ar.getRole()))
					.setAssetType(ar.getAssetType())
					.setRequiresAssets(ar.getRequiresAssets())
					.setRequiresAttributes(ar.getCreatesAttributes())
					.addAllRequiresSubAttributes(subAttributes));
		}
        responseObserver.onNext(GetManifestResponse.newBuilder()
                .setManifest(manifest)
                .build());
        logger.debug("GetManifest Data in Zap Plugin : {}", manifest);
		logger.info("exit getManifest() in ZAP Plugin");
        responseObserver.onCompleted();
    }

}