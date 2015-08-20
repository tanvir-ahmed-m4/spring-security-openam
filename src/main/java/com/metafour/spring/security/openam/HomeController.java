package com.metafour.spring.security.openam;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOTokenManager;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;

import java.util.Map;
import java.util.Set;

import com.iplanet.sso.SSOTokenID;

import java.net.InetAddress;

import javax.servlet.http.HttpServletRequest;


@Controller
public class HomeController {
	
    @RequestMapping("/")
    public String home(Model model) {
        return "home";
    }
    
    @RequestMapping("/login")
    public String login() {
        return "login";
    }

    @RequestMapping("/show")
    public String show(Model model) {
        return "show";
    }
    
    @RequestMapping("/info")
    public @ResponseBody String info(Model model, HttpServletRequest request) throws SSOException, IdRepoException {
    	StringBuffer sb = new StringBuffer();
    	sb.append("<html>");
    	sb.append("<head><title>SSO Info</title></head>");
    	sb.append("<body>");
	    SSOTokenManager manager = SSOTokenManager.getInstance();
	    SSOToken token = manager.createSSOToken(request);

	    if (manager.isValidToken(token)) {
	        //print some of the values from the token.
	        String host = token.getHostName();
	        java.security.Principal principal = token.getPrincipal();
	        String authType = token.getAuthType();
	        int level = token.getAuthLevel();
	        InetAddress ipAddress = token.getIPAddress();

	        sb.append("SSOToken host name: " + host);
	        sb.append("<br/>");
	        sb.append("SSOToken Principal name: " + principal.getName());
	        sb.append("<br/>");
	        sb.append("Authentication type used: " + authType);
	        sb.append("<br/>");
	        sb.append("Authentication level: " + level);
	        sb.append("<br/>");
	        sb.append("IPAddress of the host: " + ipAddress.getHostAddress());
	        sb.append("<br/>");
	    }

	    /* Validate the token again, with another method.
	    * if token is invalid, this method throws exception
	    */
	    manager.validateToken(token);
	    sb.append("SSO Token validation test succeeded");
	    sb.append("<br/>");

	    // Get the SSOTokenID associated with the token and print it.
	    SSOTokenID tokenId = token.getTokenID();
	    sb.append("The token id is " + tokenId.toString());
	    sb.append("<br/>");

	    // Set and get some properties in the token.
	    token.setProperty("Company", "Sun Microsystems");
	    token.setProperty("Country", "USA");
	    String name = token.getProperty("Company");
	    String country = token.getProperty("Country");
	    sb.append("Property: Company: " + name);
	    sb.append("<br/>");
	    sb.append("Property: Country: " + country);
	    sb.append("<br/>");

	    // Retrieve user profile and print them
	    AMIdentity userIdentity = IdUtils.getIdentity(token);
	    Map attrs = userIdentity.getAttributes();
	    sb.append("User Attributes: " + attrs);
	    sb.append("<br/>");
	    
	    Set<AMIdentity> groupsSet = (Set<AMIdentity>) userIdentity.getMemberships(IdType.GROUP);
	    sb.append("User Groups: " + groupsSet);
	    sb.append("<br/>");
//	    for (AMIdentity group : groupsSet) {
//	    	sb.append("Group Attributes: " + group.getAttributes());
//		}
	    
    	sb.append("</body>");
	    sb.append("</html>");

        return sb.toString();
    }
}