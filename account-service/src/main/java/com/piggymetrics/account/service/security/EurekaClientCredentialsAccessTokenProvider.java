package com.piggymetrics.account.service.security;

import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

public class EurekaClientCredentialsAccessTokenProvider extends ClientCredentialsAccessTokenProvider {
    private RestTemplate eurekaRestTemplate;

    @Override
    protected RestOperations getRestTemplate() {
        if (eurekaRestTemplate != null) {
            setMessageConverters(eurekaRestTemplate.getMessageConverters());
            return eurekaRestTemplate;
        }
        return super.getRestTemplate();
    }

    public void setRestTemplate(RestTemplate restTemplate) {
        this.eurekaRestTemplate = restTemplate;
    }
}
