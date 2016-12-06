package com.securityspringjwt.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtTokenMissingException extends AuthenticationException {

	private static final long serialVersionUID = -4027566210266706686L;

	public JwtTokenMissingException(String message){
		super(message);
	}
}
