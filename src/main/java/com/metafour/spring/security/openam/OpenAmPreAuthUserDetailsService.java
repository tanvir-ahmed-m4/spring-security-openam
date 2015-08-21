package com.metafour.spring.security.openam;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.springframework.security.core.authority.GrantedAuthoritiesContainer;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Service;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdUtils;

@Service
public class OpenAmPreAuthUserDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

	private static final Logger logger = Logger.getLogger(OpenAmPreAuthUserDetailsService.class);
	
	@Override
	public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken preAuthToken)
			throws UsernameNotFoundException {
		logger.info("OpenAM SSOTokenId: " + preAuthToken.getDetails());
		
		String username = "unknown";
		String credential = "N/A";
		List<String> groups = new ArrayList<String>();
		
		try {
			SSOTokenManager manager = SSOTokenManager.getInstance();
			SSOToken token = manager.createSSOToken(preAuthToken.getName());

			/* Validate the token again, with another method.
			* if token is invalid, this method throws exception
			*/
			manager.validateToken(token);

			// Retrieve user profile and print them
			AMIdentity userIdentity = IdUtils.getIdentity(token);
			if (logger.isDebugEnabled()) {
	            logger.debug("User attributes: " + userIdentity.getAttributes());
	        }
			
			// XXX: Make configurable? 
			Principal principal = token.getPrincipal();
			// e.g. id=ftahmed,ou=user,dc=openam,dc=forgerock,dc=org
			username = principal.getName();
			
			Map attrs = userIdentity.getAttributes();
			// e.g. ftahmed
			username = userIdentity.getName();
			
			if (attrs.containsKey("userPassword")) {
				Set passwords = (Set) attrs.get("userPassword");
				if (passwords != null && !passwords.isEmpty()) {
					// e.g. [{SSHA}hV15VpxcTm06P+OGQFgPRFjO8golaEAtlTWmJg==]
//					credential = attrs.get("userPassword").toString();
					for (Object password : passwords) {
						// e.g. {SSHA}hV15VpxcTm06P+OGQFgPRFjO8golaEAtlTWmJg==
						credential = (String) password;
						break; // ignore the rest of the elements 
					}
				}
			}
			
		} catch (SSOException | IdRepoException e) {
            logger.warn("Failed to load details from SSOTokenId: " + preAuthToken.getName(), e);
		}
		
		if (logger.isDebugEnabled()) {
            logger.debug(String.format("Username: %s, Credential: %s, Groups: %s", username, credential, groups));
        }
		
		GrantedAuthoritiesContainer grantedAuthorities = (GrantedAuthoritiesContainer) preAuthToken.getDetails();
		return new User(username, credential, true, true, true, true, grantedAuthorities.getGrantedAuthorities());
	}

}
