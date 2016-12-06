package com.securityspringjwt.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import com.securityspringjwt.entity.User;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {
	
	public static final String QUALIFIER = "com.securityspringjwt.repository.UserRepository";

	User findByusername(String userName) throws UsernameNotFoundException;
	
}
