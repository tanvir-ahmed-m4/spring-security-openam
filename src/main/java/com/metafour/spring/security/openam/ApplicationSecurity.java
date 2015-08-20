package com.metafour.spring.security.openam;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter;

import com.sun.identity.provider.springsecurity.OpenSSOAuthenticationProvider;
import com.sun.identity.provider.springsecurity.OpenSSOProcessingFilter;

@Configuration
//@EnableWebSecurity
@EnableWebMvcSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled = true, securedEnabled = true, prePostEnabled = true, proxyTargetClass = true)
public class ApplicationSecurity extends WebSecurityConfigurerAdapter {

    private static final Logger logger = Logger.getLogger(ApplicationSecurity.class);

    @Autowired
    private UserService userService; // implements AuthenticationUserDetailsService...

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        logger.info("configure AuthenticationManagerBuilder....");
        PreAuthenticatedAuthenticationProvider paaProvider = new PreAuthenticatedAuthenticationProvider();
        paaProvider.setPreAuthenticatedUserDetailsService(userService);
        auth.authenticationProvider(paaProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        logger.info("configure HttpSecurity...");
        
        List<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>();
        providers.add(new OpenSSOAuthenticationProvider());
        ProviderManager authenticationManager = new ProviderManager(providers);
        
        OpenSSOProcessingFilter openssoFilter = new OpenSSOProcessingFilter();
        openssoFilter.setFilterProcessesUrl("/login");
        
    	// @formatter:off
        http
            .authorizeRequests()
            	.antMatchers("/", "/login", "/info", "/resources/*").permitAll()
                .antMatchers("/**").authenticated()
                .and()
                .addFilterBefore(new MyPreAuthFilter(), J2eePreAuthenticatedProcessingFilter.class)
//                .addFilterBefore(openssoFilter, J2eePreAuthenticatedProcessingFilter.class)
//            .formLogin()
//            	.loginPage("/login")
//            	.and()
            .jee()
                .mappableRoles("user", "USER", 
                		"admin", "ADMIN", 
                		"customer", "CUSTOMER", 
                		"employee", "EMPLOYEE",
                		"manager", "MANAGER",
                		"supervisor", "SUPERVISOR");
	    // @formatter:on
    }
    
//    @Bean
//    public FilterRegistrationBean registration() {
//    	Filter filter = new com.sun.identity.agents.filter.AmAgentFilter();
//        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
//        return registration;
//    }
}

