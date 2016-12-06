package com.securityspringjwt.properties;

import java.io.Serializable;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "security.jwt", ignoreUnknownFields = true)
public class JwtProperties implements Serializable {

	private static final long serialVersionUID = 6318612797823408155L;
	
	private String header;
	private String secret;
	private String jwtSchema;
	private Long expiration;
	
	public String getHeader() {
		return header;
	}
	public void setHeader(String header) {
		this.header = header;
	}
	public String getSecret() {
		return secret;
	}
	public void setSecret(String secret) {
		this.secret = secret;
	}
	public String getJwtSchema() {
		return jwtSchema;
	}
	public void setJwtSchema(String jwtSchema) {
		this.jwtSchema = jwtSchema;
	}
	public Long getExpiration() {
		return expiration;
	}
	public void setExpiration(Long expiration) {
		this.expiration = expiration;
	}
	
}
