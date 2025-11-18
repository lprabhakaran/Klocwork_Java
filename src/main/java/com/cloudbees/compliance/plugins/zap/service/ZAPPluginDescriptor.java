package com.cloudbees.compliance.plugins.zap.service;

import com.cloudbees.compliance.plugins.grpc.service.v040.PluginAssetDescriptors;
import com.cloudbees.compliance.service.v040.GetAssetDescriptorsRequest;
import com.cloudbees.compliance.service.v040.GetAssetDescriptorsResponse;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class ZAPPluginDescriptor extends PluginAssetDescriptors {
    private static final Logger logger = LoggerFactory.getLogger(ZAPPluginDescriptor.class);

    @Override
    public void getAssetDescriptors(GetAssetDescriptorsRequest request,
                                    StreamObserver<GetAssetDescriptorsResponse> responseObserver) {
        logger.info("Inside ZAP getAssetDescriptors()");

        responseObserver.onNext(GetAssetDescriptorsResponse.newBuilder().build());
        responseObserver.onCompleted();
        logger.info("Exit ZAP getAssetDescriptors()");
    }
}
