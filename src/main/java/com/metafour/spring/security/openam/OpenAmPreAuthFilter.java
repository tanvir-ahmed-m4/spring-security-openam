package com.metafour.spring.security.openam;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenID;
import com.iplanet.sso.SSOTokenManager;

public class OpenAmPreAuthFilter extends AbstractPreAuthenticatedProcessingFilter {

	private static final Logger logger = Logger.getLogger(OpenAmPreAuthFilter.class);
	
	/**
     * Returns the OpenAM SSOTokenID
     */
	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {	
		Object principal = null;
		try {
			SSOTokenManager manager = SSOTokenManager.getInstance();
			SSOToken token = manager.createSSOToken(request);

			/* Validate the token again, with another method.
			* if token is invalid, this method throws exception
			*/
			manager.validateToken(token);

			// Get the SSOTokenID associated with the token and print it.
			SSOTokenID tokenId = token.getTokenID();
			principal = tokenId;
		    
		} catch (SSOException | UnsupportedOperationException e) {
			if (logger.isDebugEnabled()) {
	            logger.debug("No OpenAM SSOToken found in request", e);
	        }
		}
		
        if (logger.isDebugEnabled()) {
            logger.debug("OpenAM SSOTokenID: " + principal);
        }
        return principal;
	}

    /**
     * Returns a fixed dummy value.
     */
	@Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
        return "N/A";
    }
	
}
