package com.piggymetrics.account.client;

import com.piggymetrics.account.domain.User;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.security.Principal;

@FeignClient(name = "auth-service")
public interface AuthServiceClient {

	@RequestMapping(method = RequestMethod.POST, value = "/uaa/users", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
	void createUser(User user);

	@RequestMapping(method = RequestMethod.GET, value = "/uaa/users/current", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
	void currentUser();
}
