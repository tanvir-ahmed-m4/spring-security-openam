package com.metafour.spring.security.openam;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.Attributes2GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.MappableAttributesRetriever;
import org.springframework.security.core.authority.mapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.util.Assert;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;

public class OpenAmBasedPreAuthenticatedWebAuthenticationDetailsSource
		implements AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails>,
		InitializingBean {

	protected final Log logger = LogFactory.getLog(getClass());
	
	/**
	 * The role attributes returned by the configured
	 * {@code MappableAttributesRetriever}
	 */
	protected Set<String> openAmGroups;
	protected Attributes2GrantedAuthoritiesMapper openAmGroups2GrantedAuthoritiesMapper = new SimpleAttributes2GrantedAuthoritiesMapper();

	/**
	 * Check that all required properties have been set.
	 */
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(openAmGroups, "No OpenAM groups available");
		Assert.notNull(openAmGroups2GrantedAuthoritiesMapper, "Roles to granted authorities mapper not set");
	}

	/**
	 * Obtains the list of user groups based on the current user's OpenAM group memberships.
	 *
	 * @param request
	 *            the request which should be used to extract the user's groups.
	 * @return The subset of {@code openAmGroups} which applies to the
	 *         current user making the request.
	 */
	protected Collection<String> getUserGroups(HttpServletRequest request) {
		List<String> openAmUserGroups = new ArrayList<String>();
		
		try {
			SSOTokenManager manager = SSOTokenManager.getInstance();
			SSOToken token = manager.createSSOToken(request);

			/* Validate the token again, with another method.
			* if token is invalid, this method throws exception
			*/
			manager.validateToken(token);

			// Retrieve user profile and print them
			AMIdentity userIdentity = IdUtils.getIdentity(token);
			Set groupsSet = userIdentity.getMemberships(IdType.GROUP);
			if (logger.isDebugEnabled()) {
	            logger.debug("Group memberships: " + groupsSet);
	        }
			// TODO: Should I use Set.retainAll()?
			for (AMIdentity group : (Set<AMIdentity>) groupsSet) {
				if (openAmGroups.contains(group.getName())) {
					openAmUserGroups.add(group.getName());
				}
			}
		} catch (SSOException | IdRepoException e) {
			if (logger.isDebugEnabled()) {
	            logger.debug("No OpenAM SSOToken found in request", e);
	        }
		}
		
		return openAmUserGroups;
	}

	/**
	 * Builds the authentication details object.
	 *
	 * @see org.springframework.security.authentication.AuthenticationDetailsSource#buildDetails(Object)
	 */
	public PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails buildDetails(
			HttpServletRequest context) {

		Collection<String> openAmUserGroups = getUserGroups(context);
		Collection<? extends GrantedAuthority> userGas = openAmGroups2GrantedAuthoritiesMapper.getGrantedAuthorities(openAmUserGroups);

		if (logger.isDebugEnabled()) {
			logger.debug("OpenAM user groups [" + openAmUserGroups + "] mapped to Granted Authorities: [" + userGas + "]");
		}

		PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails result = 
				new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(context, userGas);

		return result;
	}

	/**
	 * @param mappableAttributesRetriever
	 *            The MappableAttributesRetriever to use
	 */
	public void setMappableRolesRetriever(MappableAttributesRetriever mappableAttributesRetriever) {
		this.openAmGroups = Collections.unmodifiableSet(mappableAttributesRetriever.getMappableAttributes());
	}

	/**
	 * @param mapper
	 *            The Attributes2GrantedAuthoritiesMapper to use
	 */
	public void setUserRoles2GrantedAuthoritiesMapper(Attributes2GrantedAuthoritiesMapper mapper) {
		openAmGroups2GrantedAuthoritiesMapper = mapper;
	}
}