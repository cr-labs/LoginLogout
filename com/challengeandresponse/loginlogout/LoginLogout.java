package com.challengeandresponse.loginlogout;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

/**
 * A Login/Logout lifecycle manager... for use (hardcoded) with db4o.
 * perform login (match user ID with password, create credential, bind it to a session)<br />
 * perform logout (disconenct credential from session)<br />
 * test for valid credential<br />
 * 
*/
public class LoginLogout {
	
	// flags that if present always deny login. If an account is flagged with one of these, login is always denied
	private Hashtable <Character,String> 	denyLoginFlags;
	
	// flags that if present permit login. If no login flags are registered, login is permitted as long as no login denial flags are present.
	private Vector 	<Character>				allowLoginFlags;
	
	/**
	 * No error
	 */
	public static final int		ERROR_NONE					= 0;
	/**
	 * Username not found for an attempted operation on an existing user record
	 */
	public static final int		ERROR_USERNAME_NOT_FOUND 	= ERROR_NONE + 1;
	public static final int		ERROR_EMAIL_NOT_FOUND 		= ERROR_NONE + 2;
	public static final int 	ERROR_PASSWORD_MISMATCH 	= ERROR_NONE + 3;
	public static final int 	ERROR_USERNAME_EXISTS	 	= ERROR_NONE + 4;
	public static final int 	ERROR_EMAIL_EXISTS	 		= ERROR_NONE + 5;
	public static final int		ERROR_INTERNAL				= ERROR_NONE + 6;
	public static final int		ERROR_LOGIN_DENIED_BY_FLAGS_GENERAL	= ERROR_NONE + 7;
	public static final int		ERROR_AUTHENTICATION_REQUIRED = ERROR_NONE+8;
	public static final int		ERROR_INVALID_EMAIL_DOMAIN	= ERROR_NONE+9;
	
	/**
	 */
	public LoginLogout() {
		denyLoginFlags = new Hashtable <Character,String> ();
		allowLoginFlags = new Vector <Character> ();
	}
	
	/**
	 * Add a "deny login" flag.  If an account is flagged with any flag registered with this method, login will be denied
	 * @param flag the flag to set
	 * @param denialReason a String to be appended to the message when login is denied.
	 */
	public void registerDenyLoginFlag(char flag, String denialReason) {
		if (! denyLoginFlags.containsKey(new Character(flag)))
			denyLoginFlags.put(new Character(flag),denialReason);
	}
	
	/**
	 * Add a "allow login" flag.
	 * If no allowLogin flags are registered, login is permitted provided the account has no "deny login" flags on it.
	 * If any allowLogin flags are registered, then the account must be flagged with one of them or login will be denied.
	 */
	public void registerAllowLoginFlag(char flag) {
		if (! allowLoginFlags.contains(new Character(flag)))
			allowLoginFlags.add(new Character(flag));
	}

	
	/**
	 * Check to see if this Credential is allowed to log in. 
	 * @param c the Credential to evaluate
	 * @return null if the account is allowed to log in, or a String complaint explaining the problem if not
	 */
	public String checkLoginFlags(Credential c) {
		if (c == null) 
			return "Credential is NULL";
		// CHECK LOGIN-DENY and LOGIN-ALLOW FLAGS
		Enumeration <Character> e;
		// intersect denyLoginFlags with the flags on the account. If any match, login is denied.
		e = denyLoginFlags.keys();
		while (e.hasMoreElements()) {
			Character dlf = (Character) e.nextElement();
			if (c.hasFlag(dlf))
				return denyLoginFlags.get(dlf)+" "; // padded with " " so a non-null is returned even if the explanatory text for the flag is empty
		}
		
		// if there are any login flags registered, the account must have one or login will be denied
		// if no login flags have been registered, then this check is not performed
		if (allowLoginFlags.size() > 0) {
			e = allowLoginFlags.elements();
			while (e.hasMoreElements())
				if (c.hasFlag((Character) e.nextElement()))
					return null; // match found, ok to log in
			return "Logging in is not permitted.";
		}
		// if fell through, then no errors were trapped by any above steps. return null to signal OK to log in
		return null;
	}

	public static boolean emailDomainExists(String emailAddress) {
		try {
			InetAddress.getByName(emailAddress.substring(emailAddress.indexOf("@")+1));
			return true;
		}
		catch (UnknownHostException uhe) {
			return false;
		}
	}
	

	/**
	 * Check an e-mail address to see it if seems legit
	 * @param emailAddress an e-mail address to evaluate
	 * @return true if if appears to be a valid e-mail address, false otherwise
	 */
	public static boolean emailAddressLooksValid(String emailAddress) {
		if ( (emailAddress.length() < 1) || (emailAddress.indexOf("@") < 1) || (emailAddress.lastIndexOf(".") < emailAddress.lastIndexOf("@")) 
				|| (emailAddress.lastIndexOf(".") ==  emailAddress.length()-1) || (emailAddress.indexOf(" ") > -1))
			return false;
		else
			return true;
	}
	
	
	
	/// TESTING
	public static void main(String[] args) {
		Credential c = new Credential();
		try {
			LoginLogout l = new LoginLogout();
			System.out.println("registering Denied and Allow flags");
			l.registerDenyLoginFlag('d',"Login denied flag is set");
			l.registerAllowLoginFlag('a');

			c.setFlag('a');
			c.setFlag('d');
			c.unsetFlag('d');
			System.out.println("Check login flags: "+l.checkLoginFlags(c));
			System.out.println("Flags: "+c.getPrivilegeTokens());
			System.out.println("Update user record");
			
		}
		catch (Exception e) {
			System.out.println("Exception: "+e.getMessage());
		}
		
		
		
		
	}


	

}
