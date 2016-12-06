package com.securityspringjwt.security.config;

import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JwtAuthenticationToken extends UsernamePasswordAuthenticationToken {

	private static final long serialVersionUID = 493136677392946951L;
	
	private String token;

	public JwtAuthenticationToken(Object principal, Object credentials, String token, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
        this.token = token;
    }
	
	public JwtAuthenticationToken(String token){
		super(null, null);
		this.token = token;
	}

    public String getToken() {
        return token;
    }

}
