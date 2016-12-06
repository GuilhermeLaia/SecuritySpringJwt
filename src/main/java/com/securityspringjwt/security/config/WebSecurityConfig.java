package com.securityspringjwt.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.securityspringjwt.properties.JwtProperties;
import com.securityspringjwt.security.filter.JwtAuthenticationLoginFilter;
import com.securityspringjwt.security.filter.JwtAuthenticationTokenFilter;
import com.securityspringjwt.security.jwt.JwtTokenUtil;
import com.securityspringjwt.service.CustomUserDetailsService;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	private static final String URL_LOGIN_ENTRY_POINT = "/api/login";
	private static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/api/**";
	
	@Autowired 
	private AuthenticationFailureHandler failureHandler;
	
	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	
	@Autowired
	private JwtProperties jwtProperties;
	
	@Autowired
	private CustomUserDetailsService serviceCustomUserDetails;
	
	public WebSecurityConfig() {
		super(true);
	}
	
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
        .csrf().disable() // We don't need CSRF for JWT based authentication
        .exceptionHandling()
        //.authenticationEntryPoint(this.jwtAuthenticationEntryPoint)
        
        .and()
		.servletApi()
		.and()
		.headers()
		.and()
		.authorizeRequests()
        
        /*.and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)*/

        .and()
            .authorizeRequests()
             //allow anonymous resource requests
    		    .antMatchers("/").permitAll()
    		    .antMatchers("/resources/**").permitAll()
    		 //allow Login end-point requests   
                .antMatchers(HttpMethod.POST, URL_LOGIN_ENTRY_POINT).permitAll()
             //H2 Console Dash-board - only for testing
                //.antMatchers("/console").permitAll() 
        .and()
            .authorizeRequests()
                .antMatchers(TOKEN_BASED_AUTH_ENTRY_POINT).authenticated() // Protected API End-points
        .and()
        
        	// custom JSON based authentication by POST of {"username":"<name>","password":"<password>"} which sets the token header upon authentication
     		.addFilterBefore(new JwtAuthenticationLoginFilter(URL_LOGIN_ENTRY_POINT, authenticationManager(), jwtTokenUtil, serviceCustomUserDetails), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(new JwtAuthenticationTokenFilter(TOKEN_BASED_AUTH_ENTRY_POINT, authenticationManager(), jwtTokenUtil, jwtProperties, failureHandler), UsernamePasswordAuthenticationFilter.class);
	
			SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
	}
	
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(serviceCustomUserDetails).passwordEncoder(new BCryptPasswordEncoder());
	}

	@Override
	protected CustomUserDetailsService userDetailsService() {
		return serviceCustomUserDetails;
	}
	
	
}
