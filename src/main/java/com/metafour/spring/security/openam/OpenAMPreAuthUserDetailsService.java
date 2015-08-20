package com.metafour.spring.security.openam;

import java.net.InetAddress;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Service;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenID;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;

@Service
public class OpenAMPreAuthUserDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

	private static final Logger logger = Logger.getLogger(OpenAMPreAuthUserDetailsService.class);
	
	@Override
	public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken preAuthToken)
			throws UsernameNotFoundException {
		logger.info("[5] loadUserDetails PreAuthenticatedAuthenticationToken: " + preAuthToken.getDetails());
		
		String userName = "unidentified";
		String credential = "N/A";
		List<String> roles = new ArrayList<String>();
		
		try {
			SSOTokenManager manager = SSOTokenManager.getInstance();
			SSOToken token = manager.createSSOToken(preAuthToken.getName());

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

			// Set and get some properties in the token.
			token.setProperty("Company", "Sun Microsystems");
			token.setProperty("Country", "USA");
			String name = token.getProperty("Company");
			String country = token.getProperty("Country");

			// Retrieve user profile and print them
			AMIdentity userIdentity = IdUtils.getIdentity(token);
			userName = userIdentity.getName();
			Map attrs = userIdentity.getAttributes();
			
			Set<AMIdentity> groupsSet = (Set<AMIdentity>) userIdentity.getMemberships(IdType.GROUP);
			for (AMIdentity group : groupsSet) {
				roles.add("ROLE_" + group.getName().toUpperCase());
			}
			logger.info("[6] loadUserDetails roles: " + roles); 
		    
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
		
//		return new User(preAuthToken.getName(), "", AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_SUPERVISOR"));
		return new User(userName, credential, AuthorityUtils.createAuthorityList(roles.toArray(new String[0])));
	}

}
