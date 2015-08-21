package com.metafour.spring.security.openam;

import java.net.InetAddress;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenID;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;

public class OpenAmTests {

	// OpenAM SSOTokenID
	private String ssoTokenId;
	
	@Before
	public void setUp() throws Exception {
		ssoTokenId = "AQIC5wM2LY4Sfcy5cJyZ8sPqqFsSfLePuM4zJIiW9OsDb1A.*AAJTSQACMDEAAlNLABQtNjM3MzMyNzYyOTM5NDYzMjA4NQ..*";
	}

	@Test
	public void testSSOTokenDetails() throws SSOException, IdRepoException {
		StringBuffer sb = new StringBuffer();
    	sb.append("SSO Info");
	    SSOTokenManager manager = SSOTokenManager.getInstance();
	    SSOToken token = manager.createSSOToken(ssoTokenId);

	    if (manager.isValidToken(token)) {
	        //print some of the values from the token.
	        String host = token.getHostName();
	        java.security.Principal principal = token.getPrincipal();
	        String authType = token.getAuthType();
	        int level = token.getAuthLevel();
	        InetAddress ipAddress = token.getIPAddress();

	        sb.append("SSOToken host name: " + host);
	        sb.append("\n");
	        sb.append("SSOToken Principal name: " + principal.getName());
	        sb.append("\n");
	        sb.append("Authentication type used: " + authType);
	        sb.append("\n");
	        sb.append("Authentication level: " + level);
	        sb.append("\n");
	        sb.append("IPAddress of the host: " + ipAddress.getHostAddress());
	        sb.append("\n");
	    }

	    /* Validate the token again, with another method.
	    * if token is invalid, this method throws exception
	    */
	    manager.validateToken(token);
	    sb.append("SSO Token validation test succeeded");
	    sb.append("\n");

	    // Get the SSOTokenID associated with the token and print it.
	    SSOTokenID tokenId = token.getTokenID();
	    sb.append("The token id is " + tokenId.toString());
	    sb.append("\n");

	    // Set and get some properties in the token.
	    token.setProperty("Company", "Sun Microsystems");
	    token.setProperty("Country", "USA");
	    String name = token.getProperty("Company");
	    String country = token.getProperty("Country");
	    sb.append("Property: Company: " + name);
	    sb.append("\n");
	    sb.append("Property: Country: " + country);
	    sb.append("\n");

	    // Retrieve user profile and print them
	    AMIdentity userIdentity = IdUtils.getIdentity(token);
	    Map attrs = userIdentity.getAttributes();
	    sb.append("User Attributes: " + attrs);
	    sb.append("\n");
	    for (Object key : attrs.keySet()) {
	    	Object value = attrs.get(key);
	    	sb.append(String.format("(%s => %s): %s => %s", key.getClass().getName(), value.getClass().getName(), key, value));
		    sb.append("\n");
	    }
	    
	    Set<AMIdentity> groupsSet = (Set<AMIdentity>) userIdentity.getMemberships(IdType.GROUP);
	    sb.append("User Groups: " + groupsSet);
	    sb.append("\n");
//	    for (AMIdentity group : groupsSet) {
//	    	sb.append("Group Attributes: " + group.getAttributes());
//		}
	    
        System.out.println(sb.toString());
	}

}
