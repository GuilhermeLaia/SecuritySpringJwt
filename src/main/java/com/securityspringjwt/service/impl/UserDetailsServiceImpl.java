package com.securityspringjwt.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.securityspringjwt.entity.User;
import com.securityspringjwt.repository.UserRepository;
import com.securityspringjwt.security.jwt.JwtUserFactory;
import com.securityspringjwt.service.CustomUserDetailsService;

@Service("com.securityspringjwt.service.CustomUserDetailsService")
public class UserDetailsServiceImpl implements CustomUserDetailsService {

	private static final Logger LOGGER = LoggerFactory.getLogger(UserDetailsServiceImpl.class);
	
	@Autowired
	private UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = null;
		try {
			user = userRepository.findByusername(username);
			if (user == null) {
				throw new UsernameNotFoundException(String.format("No user found with username '%s'.", username));
			} else {
				return JwtUserFactory.create(user);
			}

		} catch (UsernameNotFoundException unfe) {
			LOGGER.error("Error find user by userName", unfe);
			throw unfe;
		} 
	}
	
	
	public Boolean verifyCredentials(String passwordRequest, String passwordUserDetails) {
		return true;
	}

}
