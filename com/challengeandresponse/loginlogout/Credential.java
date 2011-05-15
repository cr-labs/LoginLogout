package com.challengeandresponse.loginlogout;

import java.util.Arrays;
import java.util.Vector;

public class Credential {

	private	String			username;
	private	String			email;
	private	String			previousEmail; // The previous email before it was changed to the current (for recovery if user changes to a bogus email and can't authenticate
	private	byte[]			passwordHash;
	private	long 			lastLogin;
	private	Vector <Character> 		flags;

	
	/**
	 * Empty constructor should not be used for other than QBE
	 */
	public Credential() {
	}

	
	/**
	 * The usual constructor to use. Puts default values into all fields. 
	 * OR call with userid=null for a completely empty object for use with QBE
	 * @param userid The userID to stuff into the credential (all other fields are given default values) or NULL to get an object with no defaults set for QBE
	 */
	public Credential(String userid)
	throws LoginLogoutException {
		if (userid == null)
			throw new LoginLogoutException("userid cannot be null");
		this.username = userid;
		email = "";
		previousEmail = "";
		passwordHash = null;
		lastLogin = 0;
		flags = new Vector <Character> ();
	}
	
	
	
	/**
	 * Flags are single character symbols, defined within the implementation.
	 * To set a flag, call setFlag with the desired token. If the token is not
	 * present, it will be added to the flags for this Credential. If it is 
	 * already set, no change is made. Tokens are case-sensitive, thus 'a' and 'A'
	 * may represent different flags.
	 * @param flag the flag token to add
	 */
	public void setFlag(char flag) {
		if (! hasFlag(flag))
			flags.add(new Character(flag));
	}
	
	/**
	 * Flags are single character symbols, defined within the implementation.
	 * To set a token, call setPrivilege with the desired token. If the token is
	 * present, it will be removed to the privilegeTokens for this Credential. If it is 
	 * not already set, no change is made. Privilege tokens are case-sensitive, thus 'a' and 'A'
	 * may represent different privileges.
	 * @param flag the privilege token to remove
	 */
	public void unsetFlag(char flag) {
		if (hasFlag(flag))
			flags.remove(new Character(flag));
	}

	/**
	 * This method clears several flags. Useful for maintaining sets of mutually
	 * exclusive flags so that one of them can then be set with assurance that the others are not
	 * @param flags an array of privilege tokens to remove
	 */
	public void unsetFlags(Character[] flags) {
		for (int i = 0; i < flags.length; i++)
			if (hasFlag(flags[i]))
				this.flags.remove(flags[i]);
	}
	
	
	/**
	 * @param flag The flag token to check for
	 * @return true if the Credential has this flag, false otherwise
	 */
	public boolean hasFlag(Character flag) {
		return (flags.contains(flag));
	}
	

	/**
	 * @param flag The flag token to check for
	 * @return true if the Credential has this flag, false otherwise
	 */
	public boolean hasFlag(char flag) {
		return hasFlag(new Character(flag));
	}
	

	public boolean checkPassword(String assertedPassword) {
		try {
			return Arrays.equals(this.passwordHash,Utils.SHA1(assertedPassword));
		}
		catch (Exception e) {
			return false;
		}
	}

	
	
	/**
	 * @param newPassword the plaintext of the new password for this credential
	 */
	public void setPassword(String newPassword)
		throws LoginLogoutException {
		passwordHash = Utils.SHA1(newPassword);
	}
	
	public void touchLastLogin() {
		lastLogin = System.currentTimeMillis();
	}
	
	public long getLastLogin() {
		return lastLogin;
	}
	
	/**
	 * @return the flags on this Credential as a String
	 */
	public String getPrivilegeTokens() {
		return flags.toString() + flags.size();
		
	}
	
	public String getUsername() {
		return username;
	}
	
	public void setUsername(String newname) {
		username = newname;
	}
	

	/**
	 * Get the e-mail address (can only be set through the updateEmail method of LoginLogout
	 * @return the email address on this credential
	 */
	public String getEmail() {
		return email;
	}
	
	public String getPreviousEmail() {
		return previousEmail;
	}
	
	/**
	 * @param newEmail the new email address to change to... previous will be saved to "previousEmail" for safety and possible restoration if new adress fails to authenticate
	 */
	public void changeEmail(String newEmail) {
		previousEmail = email;
		email = newEmail;
	}
	
	/**
	 * @param newEmail the new email address to change to. the old address is not saved.
	 */
	public void setEmail(String newEmail) {
		email = newEmail;
	}
	
	
}
