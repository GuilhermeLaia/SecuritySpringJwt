package com.securityspringjwt.exception;

public class JwtTokenMalformedException extends Exception {
	
	private static final long serialVersionUID = -566522535391389490L;

	public JwtTokenMalformedException(String message){
		super(message);
	}
	
}
