package com.securityspringjwt.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.securityspringjwt.exception.JwtTokenMissingException;
import com.securityspringjwt.properties.JwtProperties;
import com.securityspringjwt.security.jwt.JwtTokenUtil;
import com.securityspringjwt.security.jwt.pojo.JwtUser;

public class JwtAuthenticationTokenFilter extends AbstractAuthenticationProcessingFilter {

	private final JwtProperties jwtProperties;

	private final JwtTokenUtil jwtTokenUtil;
	
	private final AuthenticationFailureHandler failureHandler;

	public JwtAuthenticationTokenFilter(String urlMapping, AuthenticationManager authManager, JwtTokenUtil jwtTokenUtil,
			JwtProperties jwtProperties, AuthenticationFailureHandler failureHandler) {
		super(new AntPathRequestMatcher(urlMapping));
		setAuthenticationManager(authManager);
		this.jwtTokenUtil = jwtTokenUtil;
		this.jwtProperties = jwtProperties;
		this.failureHandler = failureHandler;
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		return true;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		String header = request.getHeader(jwtProperties.getHeader());

		if (header == null || !header.startsWith(jwtProperties.getJwtSchema())) {
			try {
				throw new JwtTokenMissingException("No authentication token found in request headers");
			} catch (JwtTokenMissingException jtme) {
				throw jtme;
			}
		}

		String authToken = header.substring(7);

		final JwtUser userAuthenticated = (JwtUser) jwtTokenUtil.getUserDetailsFromToken(authToken);

		if (userAuthenticated == null) {
			throw new AuthenticationServiceException("NO authentication User found in request token");
		}

		//
		return userAuthenticated;
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {

		SecurityContextHolder.getContext().setAuthentication(authResult);

		// As this authentication is in HTTP header, after success we need to
		// continue the request normally
		// and return the response as if the resource was not secured at all
		chain.doFilter(request, response);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		SecurityContextHolder.clearContext();
		failureHandler.onAuthenticationFailure(request, response, failed);
	}

}
