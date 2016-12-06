package com.securityspringjwt.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securityspringjwt.security.config.JwtAuthenticationToken;
import com.securityspringjwt.security.jwt.JwtTokenUtil;
import com.securityspringjwt.security.jwt.pojo.JwtUser;
import com.securityspringjwt.service.CustomUserDetailsService;

public class JwtAuthenticationLoginFilter extends AbstractAuthenticationProcessingFilter {
	
	private static final String AUTH_HEADER_NAME = "Authorization";
	
	private final JwtTokenUtil jwtTokenUtil;
	
	private final CustomUserDetailsService serviceCustomUserDetails;
	
	
	public JwtAuthenticationLoginFilter(String urlMapping, AuthenticationManager authManager, JwtTokenUtil jwtTokenUtil, CustomUserDetailsService serviceCustomUserDetails) {
		super(new AntPathRequestMatcher(urlMapping));
		setAuthenticationManager(authManager);
		this.jwtTokenUtil = jwtTokenUtil;
		this.serviceCustomUserDetails = serviceCustomUserDetails;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		
		if(!request.getMethod().equals("POST")){
			throw new AuthenticationCredentialsNotFoundException("Request method accepted POST");
		}
		final JwtUser user = new ObjectMapper().readValue(request.getReader(), JwtUser.class);
		
		if(user == null){
			throw new AuthenticationServiceException("Error authentication verify yours crendetials");
		}
		final UsernamePasswordAuthenticationToken loginToken = new UsernamePasswordAuthenticationToken(
				user.getUsername(), user.getPassword());
		
		SecurityContextHolder.getContext().setAuthentication(loginToken);
		return loginToken;
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain, Authentication authentication) throws IOException, ServletException {

		// Lookup the complete User object from the database and create an Authentication for it
		final JwtUser authenticatedUser = (JwtUser) serviceCustomUserDetails.loadUserByUsername(authentication.getName());
		
		// generate new token to authenticatedUser
		String token = jwtTokenUtil.generateToken(authenticatedUser, null);
		
		JwtAuthenticationToken userAuthentication = new JwtAuthenticationToken(authenticatedUser, authenticatedUser.getPassword(), token, authenticatedUser.getAuthorities());
		
		// Add the custom token as HTTP header to the response
		response.addHeader(AUTH_HEADER_NAME, token);
		
		// Add the authentication to the Security context
		SecurityContextHolder.getContext().setAuthentication(userAuthentication);
	}
	
}
