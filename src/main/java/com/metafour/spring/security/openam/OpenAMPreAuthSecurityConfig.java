package com.metafour.spring.security.openam;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;

@Configuration
@EnableWebSecurity
//@EnableWebMvcSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled = true, securedEnabled = true, prePostEnabled = true, proxyTargetClass = true)
public class OpenAMPreAuthSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Logger logger = Logger.getLogger(OpenAMPreAuthSecurityConfig.class);

    @Autowired
    private OpenAMPreAuthUserDetailsService userService; // implements AuthenticationUserDetailsService...

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        logger.info("[1] Configuring HttpSecurity...");
        
    	// @formatter:off
        http
        	.sessionManagement()
        		.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        		.and()
            .authorizeRequests()
            	.antMatchers("/", "/login", "/info", "/resources/*").permitAll()
                .antMatchers("/**").authenticated()
                .and()
            .addFilter(preAuthFilter());
	    // @formatter:on
    }
    
    @Autowired
    OpenAMPreAuthUserDetailsService preAuthUserDetailsService;
 
    @Bean
	public Filter preAuthFilter() {
    	OpenAMPreAuthFilter filter = new OpenAMPreAuthFilter();
		filter.setAuthenticationManager(preAuthAuthenticationManager());
		return filter;
	}
	
	@Bean
	protected AuthenticationManager preAuthAuthenticationManager() {

		PreAuthenticatedAuthenticationProvider preAuthProvider= new PreAuthenticatedAuthenticationProvider();
		preAuthProvider.setPreAuthenticatedUserDetailsService(preAuthUserDetailsService);
		
		List<AuthenticationProvider> providers = new  ArrayList<AuthenticationProvider>();
		providers.add(preAuthProvider);
		
		ProviderManager authMan = new ProviderManager(providers);
		return authMan;
	}
}

