package com.securityspringjwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.securityspringjwt.service.CustomUserDetailsService;

@RestController
@Transactional
public class WebserviceController {

	@Autowired
    private CustomUserDetailsService userDetailService;

    @RequestMapping(value = "/api/user/{userName}", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public @ResponseBody ResponseEntity<UserDetails> jsonLogin(@PathVariable String userName) {
    	return new ResponseEntity<UserDetails>(userDetailService.loadUserByUsername(userName), HttpStatus.OK);
    }
	
}
