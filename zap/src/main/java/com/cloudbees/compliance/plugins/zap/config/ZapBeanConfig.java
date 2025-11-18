package com.cloudbees.compliance.plugins.zap.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;

import com.cloudbees.compliance.plugins.rest.client.CustomRestTemplateConfiguration;

import io.github.resilience4j.core.registry.EntryAddedEvent;
import io.github.resilience4j.core.registry.EntryRemovedEvent;
import io.github.resilience4j.core.registry.EntryReplacedEvent;
import io.github.resilience4j.core.registry.RegistryEventConsumer;
import io.github.resilience4j.retry.Retry;

/**
 * Bean Configuration class of Spring
 * 
 */
@Configuration
public class ZapBeanConfig {

	private static final Logger LOGGER = LoggerFactory.getLogger(ZapBeanConfig.class);
	 @Autowired
	 private CustomRestTemplateConfiguration customRestTemplateConfiguration;
	@Bean
	public RegistryEventConsumer<Retry> myRetryRegistryEventConsumer() {

		return new RegistryEventConsumer<Retry>() {
			@Override
			public void onEntryAddedEvent(EntryAddedEvent<Retry> entryAddedEvent) {
				entryAddedEvent.getAddedEntry().getEventPublisher().onEvent(event -> LOGGER.debug(event.toString()));
			}

			@Override
			public void onEntryRemovedEvent(EntryRemovedEvent<Retry> entryRemoveEvent) {
				entryRemoveEvent.getRemovedEntry().getEventPublisher().onEvent(event -> LOGGER.debug(event.toString()));
			}

			@Override
			public void onEntryReplacedEvent(EntryReplacedEvent<Retry> entryReplacedEvent) {
				//This is a overriden method which is not currently used
			}
		};
	}
	
	@Bean(name = "universalRestTemplate")
	@Primary
	public RestTemplate universalRestTemplate() {
		 return customRestTemplateConfiguration.initializeRestTemplate();
	}
	
	@Bean(name = "restTemplate")
	public RestTemplate restTemplate() {
		DefaultUriBuilderFactory defaultUriBuilderFactory = new DefaultUriBuilderFactory();
	      defaultUriBuilderFactory.setEncodingMode(DefaultUriBuilderFactory.EncodingMode.NONE);
	        RestTemplate restTemplate = customRestTemplateConfiguration.initializeRestTemplate();
	        restTemplate.setUriTemplateHandler(defaultUriBuilderFactory);
		return restTemplate;
	}
	
	@Bean
	public HttpHeaders httpHeaders() {
		return new HttpHeaders();
	}

}
