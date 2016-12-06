package com.securityspringjwt.service;

import org.springframework.security.core.userdetails.UserDetailsService;

public interface CustomUserDetailsService extends UserDetailsService {

	Boolean verifyCredentials(String passwordRequest, String passwordUserDetails);
}
