package Sendable;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;

public class SendableHelper {
	
	/**
	 * Creates and returns a Sendable object storing:
	 * 		username
	 * 		password
	 * 		the command "login"
	 * 		iv
	 * username and password are encrypted with the session key
	 * @param username client's username
	 * @param password client's password
	 * @param transformation algorithm, mode and padding of encryption scheme
	 * @param key encryption key
	 * @param commands requests to server -> "login"
	 * @return new Sendable object storing username, password, command to login that user, and iv
	 */
	public static Sendable createLoginSendable(String username, char[] password, boolean rememberUser, String transformation, Key key) {
		String[] command_login = new String[] { "login" };
		Sendable_Data raw_sendable_data = new Sendable_Data(username, password, rememberUser, command_login);
		
		SealedObject sealed_sendable_data = null;
		byte[] iv = null;
		
		try {
			Cipher encryptionCipher = Cipher.getInstance(transformation);
			encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
			sealed_sendable_data = new SealedObject(raw_sendable_data, encryptionCipher);
			iv = encryptionCipher.getIV();
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | IOException e) {
			e.printStackTrace();
		}
		
		return new Sendable(iv, sealed_sendable_data);
	}
	
	/**
	 * Returns a Sendable object containing the request to register a new user, along with additional info
	 * 
	 * @param desiredUsername Future username, if not already taken
	 * @param desiredPassword Future password, if not already taken
	 * @param rememberMe remember the user on this pc
	 * @param transformation algorithm to encrypt
	 * @param key encryption key
	 * 
	 * @return Sendable object containing all info to register new user to be sent to server
	 */
	public static Sendable createRegisterSendable(String desiredUsername, char[] desiredPassword, boolean rememberMe, String transformation, Key key) {
		Sendable_Data raw_sendable_data = new Sendable_Data(desiredUsername, desiredPassword, rememberMe, new String[] {"register"});
		
		SealedObject sealed_sendable_data = null;
		byte[] iv = null;
		
		try {
			Cipher encryptionCipher = Cipher.getInstance(transformation);
			encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
			sealed_sendable_data = new SealedObject(raw_sendable_data, encryptionCipher);
			iv = encryptionCipher.getIV();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		
		return new Sendable(iv, sealed_sendable_data);
	}
	
	/**
	 * Creates a new Sendable, first encrypting the raw Sendable_Data.
	 * @param raw_sendable_data The raw, unencrypted Sendable_Data object
	 * @param transformation Transformation algorithm, mode and padding
	 * @param key Encryption key
	 * @return Sendable object
	 */
	public static Sendable createSendableFromSendable_Data(Sendable_Data raw_sendable_data, String transformation, Key key) {
		SealedObject sealed_sendable_data = null;
		byte[] iv = null;
		
		try {
			Cipher encryptionCipher = Cipher.getInstance(transformation);
			encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
			sealed_sendable_data = new SealedObject(raw_sendable_data, encryptionCipher);
			iv = encryptionCipher.getIV();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		
		return new Sendable(iv, sealed_sendable_data);
	}
	
	/**
	 * Creates a new Sendable object the server sends to the client after
	 * a successful login. Contains all info for the first main screen
	 * 
	 * @param info userful information
	 * @param files The files in the root cloud directory of the newly logged in user
	 * @param transformation Algorithm, mode and padding
	 * @param key Encryption Key
	 * @return new Sendable containing all information after successful login
	 */
	public static Sendable createSuccessfulLoginInfoSendable(String[] info, byte[][] files, String transformation, Key key) {
		Sendable_Data raw_sendable_data = new Sendable_Data(files);
		raw_sendable_data.fillInInfo(info);
		raw_sendable_data.setAuthenticationSuccessful(true);
		
		SealedObject sealed_sendable_data = null;
		byte[] iv = null;
		try {
			Cipher encryptionCipher = Cipher.getInstance(transformation);
			encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
			sealed_sendable_data = new SealedObject(raw_sendable_data, encryptionCipher);
			iv = encryptionCipher.getIV();
		} catch (Exception exception) {
			exception.printStackTrace();
			return null;
		}
		return new Sendable(iv, sealed_sendable_data);
	}
}
