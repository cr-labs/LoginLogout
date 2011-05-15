package com.challengeandresponse.loginlogout;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utils {

	
	/**
	 * Hash some plaintext using SHA1 and return the byte array of the hashed plaintext
	 * @param plaintext the plaintext to hash
	 * @return the SHA1 hash of the plaintext
	 * @throws LoginLogoutException if the hash could not be generated due to an internal problem such as missing algorithm or invalid text encoding
	 */
	public static byte[] SHA1(String plaintext)
	throws LoginLogoutException {
		final String	HASH_ALGORITHM = "SHA-1";
		final String	TEXT_ENCODING = "iso-8859-1";
		try {
			MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
			md.update(plaintext.getBytes(TEXT_ENCODING), 0, plaintext.length());
			return md.digest();
		}
		catch (NoSuchAlgorithmException nsae) {
			throw new LoginLogoutException("No such algorithm exception:"+HASH_ALGORITHM);
		}
		catch (UnsupportedEncodingException uee) {
			throw new LoginLogoutException("Unsupported encoding exception:"+TEXT_ENCODING);
		}
	}
	
}
