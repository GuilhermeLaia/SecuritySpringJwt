package com.securityspringjwt.application;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableAutoConfiguration
@EnableScheduling
@ComponentScan(basePackages  = "com.securityspringjwt")
@EntityScan(basePackages="com.securityspringjwt")
@EnableJpaRepositories(
        basePackages = "com.securityspringjwt"
    )
public class Application extends SpringApplicationBuilder {
	public static void main(String[] args) {
		 SpringApplication.run(Application.class, args);
	}
}
