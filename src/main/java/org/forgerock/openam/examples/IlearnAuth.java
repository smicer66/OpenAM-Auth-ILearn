/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2011-2013 ForgeRock AS. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 */

package org.forgerock.openam.examples;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.net.URLEncoder;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.security.Principal;
import java.util.Map;
import java.util.ResourceBundle;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;

import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;



public class IlearnAuth extends AMLoginModule
{

    // Name for the debug-log
    private final static String DEBUG_NAME = "IlearnAuth";
    //private final static String url = "http://elearnrestapi.noun.edu.ng/api/FE51E4F9-7763-4708-B7A1-E380F97E907A/ElearnApi/VerifyUserSignOn?matricnumber=nou120811427&password=iamgood";
    private static final String USER_AGENT = "Mozilla/5.0";
    // Name of the resource bundle
    private final static String amAuthIlearnAuth = "amAuthIlearnAuth";

    // User names for authentication logic
    //private final static String USERNAME = "demo";
    private String username_ = null;
    private final static String ERROR_1_NAME = "test1";
    private final static String ERROR_2_NAME = "test2";

    // Orders defined in the callbacks file
    private final static int STATE_BEGIN = 1;
    private final static int STATE_AUTH = 2;
    private final static int STATE_ERROR = 3;
    private static final String ADMIN_USER = "amadmin";
    private static final String ADMIN_PASSWORD = "password";

    private final static Debug debug = Debug.getInstance(DEBUG_NAME);

    private Map options;
    private ResourceBundle bundle;



    public IlearnAuth()
    {
        super();
    }



    @Override
    // This method stores service attributes and localized properties
    // for later use.
    public void init(Subject subject, Map sharedState, Map options)
    {
        if (debug.messageEnabled())
        {
            debug.message("IlearnAuth::init");
        }
        this.options = options;
        bundle = amCache.getResBundle(amAuthIlearnAuth, getLoginLocale());
    }



    @Override
    public int process(Callback[] callbacks, int state) throws LoginException
    {

        if (debug.messageEnabled())
        {
            debug.message("IlearnAuth::process state: " + state);
        }

        switch (state)
        {

            case STATE_BEGIN:
                // No time wasted here - simply modify the UI and
                // proceed to next state
                substituteUIStrings();
                return STATE_AUTH;

            case STATE_AUTH:
                // Get data from callbacks. Refer to callbacks XML file.
                NameCallback nc = (NameCallback) callbacks[0];
                PasswordCallback pc = (PasswordCallback) callbacks[1];
                String username = nc.getName();
                String password = new String(pc.getPassword());
                debug.message("IlearnAuth::username=" + username);
                debug.message("IlearnAuth::password=" + password);

                // First errorstring is stored in "ilearnauth-error-1" property.
                
                
                if (username.equals(ERROR_1_NAME))
                {
                  setErrorText("ilearnauth-error-1");
                  return STATE_ERROR;
                }

                // Second errorstring is stored in "ilearnauth-error-2" property.
                if (username.equals(ERROR_2_NAME))
                {
                  setErrorText("ilearnauth-error-1");
                  return STATE_ERROR;
                }

                Boolean authStatus = authenticateUsers(username, password);
                if(authStatus==Boolean.TRUE)
                {
                	debug.message("ISAuthConstants.LOGIN_SUCCEED = " + ISAuthConstants.LOGIN_SUCCEED);
                	return ISAuthConstants.LOGIN_SUCCEED;
                }

                throw new InvalidPasswordException("password is wrong", username);

            case STATE_ERROR:
            	debug.message("STATE_ERRROR = " + STATE_ERROR);
                return STATE_ERROR;
            default:
            	debug.message("default = ");
                throw new AuthLoginException("invalid state");

        }
    }

    
    
    private Boolean authenticateUsers(String username, String password) {
    	// TODO Auto-generated method stub
    	URL obj;
    	Boolean b = null;
		String charset = "UTF-8";
		
    	try {
    		String url = "http://nounilearnbeta.com/service/user/authenticate";
    		obj = new URL(url);
    		username_ = username;
    		HttpURLConnection con = (HttpURLConnection) obj.openConnection();
    		String query = "userRef="+URLEncoder.encode(username, charset)+"&password="+URLEncoder.encode(password, charset); 
    		// optional default is GET
    		con.setRequestMethod("POST");
     
    		con.setDoOutput(true);
    		//add request header
    		con.setRequestProperty("User-Agent", USER_AGENT);
     
    		DataOutputStream wr = new DataOutputStream(con.getOutputStream());
			wr.writeBytes(query);
			wr.flush();
			wr.close();
			System.out.println("Test 2");
			
			
    		int responseCode = con.getResponseCode();
    		//System.out.println("\nSending 'GET' request to URL : " + url);
    		System.out.println("Response Code : " + responseCode);
     
    		if(responseCode==200)
    		{
    			BufferedReader in = new BufferedReader(
    			        new InputStreamReader(con.getInputStream()));
    			String inputLine;
    			StringBuffer response = new StringBuffer();
    	 
    			while ((inputLine = in.readLine()) != null) {
    				response.append(inputLine);
    			}
    			in.close();
    	 
    			//print result
    			b = Boolean.valueOf(response.toString());
    			if(b!=null && b==Boolean.TRUE)
    			{
    				String token = loginUser(ADMIN_USER, ADMIN_PASSWORD);
    				debug.message("response value = " + token + " for ADMIN_USER: " + ADMIN_USER + " && ADMIN_PASSWORD: " + ADMIN_PASSWORD);
    				
    				if(token!=null)
    					checkForUserExistence(token, username, password); 
    				
    			}else
    			{
    				debug.message("response value = " + response.toString() + " for username: " + username + " && password: " + password);
    			}
    		}else
    		{
    			debug.message("response code = " + responseCode + " for username: " + username + " && password: " + password);
    		}
    	} catch (MalformedURLException e) {
    		// TODO Auto-generated catch block
    		e.printStackTrace();
    	} catch (ProtocolException e) {
    		// TODO Auto-generated catch block
    		e.printStackTrace();
    	} catch (IOException e) {
    		// TODO Auto-generated catch block
    		e.printStackTrace();
    	}
    	return b;
    }

    
    private void checkForUserExistence(String token, String username, String password) 
    {
    	// 	TODO Auto-generated method stub
		String url = "http://ilearntrans.eduplatformsng.com:8080/OpenAM-11.0.0/identity/create?" +
				"admin=" + token +
				"&identity_name=" + username +
				"&identity_attribute_names=cn" +
				"&identity_attribute_values_cn=Test%20User" +
				"&identity_attribute_names=sn" +
				"&identity_attribute_values_sn=User" +
				"&identity_attribute_names=userpassword" +
				"&identity_attribute_values_userpassword=" + (password.length()>7 ? password : (password + "00000000")) + 
				"&identity_realm=%2F" +
				"&identity_type=user";
		debug.message("url = " + url);
		Boolean b = null;
		try
		{
			URL obj = new URL(url);
			HttpURLConnection con = (HttpURLConnection) obj.openConnection();
		 
		// optional default is POST
//		con.setRequestMethod("POST");
//		con.setRequestProperty("iplanetDirectoryPro:", token);
//		con.setRequestProperty("Content-Type","application/json");
//		String data = "'{ \"name\": \""+username+"\", \"userpassword\": \""+password+"\"}'";
//		JSONObject jsonObject = new JSONObject();
//		jsonObject.put("name", username);
//		jsonObject.put("userpassword", password);
//		
// 
//		// Send post request
//		con.setDoOutput(true);
//		OutputStream wr = con.getOutputStream();
//		wr.write(data.getBytes());
//		wr.flush();
//		wr.close();
// 
//		int responseCode = con.getResponseCode();
//		debug.message("\nSending 'POST' request to URL : " + url);
//		debug.message("Post parameters : " + data);
//		debug.message("Response Code : " + responseCode);
// 
//		BufferedReader in = new BufferedReader(
//		        new InputStreamReader(con.getInputStream()));
//		String inputLine;
//		StringBuffer response = new StringBuffer();
// 
//		while ((inputLine = in.readLine()) != null) {
//			response.append(inputLine);
//		}
//		in.close();
//		debug.message("Response = " + response.toString());
		
		
			con.setRequestProperty("User-Agent", USER_AGENT);
			 
			int responseCode = con.getResponseCode();
			debug.message("response code for creating new user ldap = " + responseCode);
			//System.out.println("\nSending 'GET' request to URL : " + url);
			//System.out.println("Response Code : " + responseCode);
	 
			if(responseCode==200)
			{
				BufferedReader in = new BufferedReader(
				        new InputStreamReader(con.getInputStream()));
				String inputLine;
				StringBuffer response = new StringBuffer();
		 
				while ((inputLine = in.readLine()) != null) {
					response.append(inputLine);
				}
				in.close();
		 
				//print result
				debug.message("response value = " + response.toString() + " for username: " + username + " && password: " + password);
			}else
			{
				debug.message("response code = " + responseCode + " for username: " + username + " && password: " + password);
			}
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

    
    
    
    public String loginUser(String adminUser, String adminPassword) {
    	// TODO Auto-generated method stub
    	String url = "http://ilearntrans.eduplatformsng.com:8080/OpenAM-11.0.0/identity/authenticate?username="+adminUser+"&password="+adminPassword;
    	String b = null;
    	try
    	{
    		URL obj = new URL(url);
    		HttpURLConnection con = (HttpURLConnection) obj.openConnection();
    		 
    		// optional default is GET
    		con.setRequestMethod("GET");
    		//add request header
    		con.setRequestProperty("User-Agent", USER_AGENT);
    	
    		int responseCode = con.getResponseCode();
    		//System.out.println("\nSending 'GET' request to URL : " + url);
    		//System.out.println("Response Code : " + responseCode);
    	
    		if(responseCode==200)
    		{
    			BufferedReader in = new BufferedReader(
    			        new InputStreamReader(con.getInputStream()));
    			String inputLine;
    			StringBuffer response = new StringBuffer();
    	 
    			while ((inputLine = in.readLine()) != null) {
    				response.append(inputLine);
    			}
    			in.close();
    	 
    			//print result
    			debug.message("Response ==" + response);
    			String[] respSplit = response.toString().split("=");
    			if(respSplit!=null && respSplit.length==2 && respSplit[0].equals("token.id"))
    			{
    				b = respSplit[1];
    			}
    			else
    			{
    				b = null;
    			}
    			
//    			Boolean b = Boolean.valueOf(response.toString());
//    			
//    			
//    			
//    			if(b!=null && b==Boolean.TRUE)
//    			{
//    				debug.message("response value = " + response.toString() + " for username: " + adminUser + " && password: " + adminPassword);
//    				String token = loginUser(ADMIN_USER, ADMIN_PASSWORD);
//    				checkForUserExistence(token, adminUser);
//    				
//    				
//    				String ldapStr = "http://openam:8080/openam/identity/create?admin={"+adminUser+"}&identity_type=user&identity_name=jdoe&identity_realm=/&identity_attribute_names=userpassword&identity_attribute_values_userpassword=changeme&identity_attribute_names=givenname&identity_attributes_values_givenname=tbd&identity_attribute_names=sn&identity_attributes_values_sn=tbd&identity_attribute_names=cn&identity_attributes_values_cn=tbd";
//    				
//    			}else
//    			{
//    				debug.message("response value = " + response.toString() + " for username: " + adminUser + " && password: " + adminPassword);
//    			}
    		}else
    		{
    			debug.message("response code = " + responseCode + " for username: " + adminUser + " && password: " + adminPassword);
    		}
    	} catch (MalformedURLException e) {
    		// TODO Auto-generated catch block
    		e.printStackTrace();
    	} catch (ProtocolException e) {
    		// TODO Auto-generated catch block
    		e.printStackTrace();
    	} catch (IOException e) {
    		// TODO Auto-generated catch block
    		e.printStackTrace();
    	}
    	return b;
    	
    }




    @Override
    public Principal getPrincipal()
    {
        return new IlearnAuthPrincipal(username_);
    }



    private void setErrorText(String err) throws AuthLoginException
    {
        // Receive correct string from properties and substitute the
        // header in callbacks order 3.
        substituteHeader(STATE_ERROR, bundle.getString(err));
    }



    private void substituteUIStrings() throws AuthLoginException
    {
        // Get service specific attribute configured in OpenAM
        String ssa = CollectionHelper.getMapAttr(options,
                "ilearnauth-service-specific-attribute");

        // Get property from bundle
        String new_hdr = ssa + " "
                + bundle.getString("ilearnauth-ui-login-header");
        substituteHeader(STATE_AUTH, new_hdr);

        Callback[] cbs_phone = getCallback(STATE_AUTH);

        replaceCallback(STATE_AUTH, 0, new NameCallback(bundle
                .getString("ilearnauth-ui-username-prompt")));

        replaceCallback(STATE_AUTH, 1, new PasswordCallback(bundle
                .getString("ilearnauth-ui-password-prompt"), false));
    }

}
