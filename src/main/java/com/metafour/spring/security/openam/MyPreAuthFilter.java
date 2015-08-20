package com.metafour.spring.security.openam;

import java.io.IOException;
import java.net.InetAddress;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenID;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.provider.springsecurity.OpenSSOAuthenticationProvider;

//public class MyPreAuthFilter extends J2eePreAuthenticatedProcessingFilter {
public class MyPreAuthFilter extends AbstractPreAuthenticatedProcessingFilter {

	private static final Logger logger = Logger.getLogger(ApplicationSecurity.class);
	
	public MyPreAuthFilter() {
		List<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>();
		PreAuthenticatedAuthenticationProvider paaProvider = new PreAuthenticatedAuthenticationProvider();
		UserService userService = new UserService();
        paaProvider.setPreAuthenticatedUserDetailsService(userService);
        providers.add(paaProvider);
        ProviderManager authenticationManager = new ProviderManager(providers); 
		this.setAuthenticationManager(authenticationManager);
	}
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (logger.isDebugEnabled()) {
            logger.debug("[0] Checking secure context token: " + SecurityContextHolder.getContext().getAuthentication());
        }
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;

    	SSOToken token = null;
		Principal principal = null; 
		try {
			SSOTokenManager manager = SSOTokenManager.getInstance();
			token = manager.createSSOToken(httpRequest);

			if (manager.isValidToken(token)) {
			    //print some of the values from the token.
			    String host = token.getHostName();
			    principal = token.getPrincipal();
			    String authType = token.getAuthType();
			    int level = token.getAuthLevel();
			    InetAddress ipAddress = token.getIPAddress();
			}
			Object aPrincipal = principal == null ? null : principal.getName();
			if (logger.isDebugEnabled()) {
			    logger.debug("[1] MyPreAuthFilter OpenAM principal: " + aPrincipal);
			}
		} catch (SSOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedOperationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

        super.doFilter(request, response, chain);
    }
	
	/**
     * Return the OpenAM user name.
     */
	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {	
		logger.info("[2] do something useful....");

		Object preAuthPrincipal = null;
		
		try {
			SSOTokenManager manager = SSOTokenManager.getInstance();
			SSOToken token = manager.createSSOToken(request);

			if (manager.isValidToken(token)) {
			    //print some of the values from the token.
			    String host = token.getHostName();
			    Principal principal = token.getPrincipal();
			    String authType = token.getAuthType();
			    int level = token.getAuthLevel();
			    InetAddress ipAddress = token.getIPAddress();
			}

			/* Validate the token again, with another method.
			* if token is invalid, this method throws exception
			*/
			manager.validateToken(token);

			// Get the SSOTokenID associated with the token and print it.
			SSOTokenID tokenId = token.getTokenID();
			preAuthPrincipal = tokenId;

			// Set and get some properties in the token.
			token.setProperty("Company", "Sun Microsystems");
			token.setProperty("Country", "USA");
			String name = token.getProperty("Company");
			String country = token.getProperty("Country");

			// Retrieve user profile and print them
			AMIdentity userIdentity = IdUtils.getIdentity(token);
			Map attrs = userIdentity.getAttributes();
			Set groupsSet = (Set) userIdentity.getMemberships(IdType.GROUP);
		    
		} catch (SSOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedOperationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IdRepoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
//        Object aPrincipal = principal == null ? null : principal.getName();
        if (logger.isDebugEnabled()) {
            logger.debug("[3] MyPreAuthFilter OpenAM preAuthPrincipal: " + preAuthPrincipal);
        }
        return preAuthPrincipal;
	}

    /**
     * For J2EE container-based authentication there is no generic way to
     * retrieve the credentials, as such this method returns a fixed dummy
     * value.
     */
	@Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
        return "N/A";
    }
	
}
