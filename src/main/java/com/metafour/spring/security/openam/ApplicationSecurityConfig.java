package com.metafour.spring.security.openam;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleMappableAttributesRetriever;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;

import com.sun.identity.agents.filter.AmAgentFilter;

@Configuration
@EnableWebSecurity
//@EnableWebMvcSecurity
//@EnableGlobalMethodSecurity(jsr250Enabled = true, securedEnabled = true, prePostEnabled = true, proxyTargetClass = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Logger logger = Logger.getLogger(ApplicationSecurityConfig.class);

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
    
    @Bean
    public FilterRegistrationBean filterRegistrationBean () {
    	AmAgentFilter amAgentFilter = new com.sun.identity.agents.filter.AmAgentFilter();
        FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        registrationBean.setFilter(amAgentFilter);
        registrationBean.addUrlPatterns("/*");
        registrationBean.setDispatcherTypes(DispatcherType.REQUEST,
        		DispatcherType.INCLUDE, DispatcherType.FORWARD, DispatcherType.ERROR);
        return registrationBean;
    }
    
    @Autowired
    private OpenAmPreAuthUserDetailsService preAuthUserDetailsService; // implements AuthenticationUserDetailsService...
 
    @Bean
    protected Filter preAuthFilter() {
    	OpenAmPreAuthFilter filter = new OpenAmPreAuthFilter();
		filter.setAuthenticationManager(preAuthAuthenticationManager());
    	filter.setAuthenticationDetailsSource(authenticationDetailsSource());
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
	
	@Bean
	protected AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails> authenticationDetailsSource() {
		OpenAmBasedPreAuthenticatedWebAuthenticationDetailsSource detailsSource = new OpenAmBasedPreAuthenticatedWebAuthenticationDetailsSource();
        SimpleMappableAttributesRetriever rolesRetriever = new SimpleMappableAttributesRetriever();
        Set<String> mappableGroups = new HashSet<String>();
        mappableGroups.add("customer");
        mappableGroups.add("employee");
        mappableGroups.add("manager");
        mappableGroups.add("supervisor");
        rolesRetriever.setMappableAttributes(mappableGroups);
        detailsSource.setMappableRolesRetriever(rolesRetriever);
        SimpleAttributes2GrantedAuthoritiesMapper mapper = new SimpleAttributes2GrantedAuthoritiesMapper();
        mapper.setConvertAttributeToUpperCase(true);
        detailsSource.setUserRoles2GrantedAuthoritiesMapper(mapper);

        return detailsSource;
	}
	
}

