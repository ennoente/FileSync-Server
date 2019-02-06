package Sendable;

import java.io.Serializable;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;

public class Sendable extends Object implements Serializable {

	
	/**
	 * 
	 */
	private static final long serialVersionUID = 5548043651427740370L;
	/**
	 * 
	 */
//	private static final long serialVersionUID = 5548043651427740370L;
	Sendable_IV sendable_IV = null;
	SealedObject sendable_data = null;
	
	public Sendable(Sendable_IV sendable_iv, SealedObject sendable_data) {
		this.sendable_IV = sendable_iv;
		this.sendable_data = sendable_data;
	}
	
	public Sendable(byte[] iv, SealedObject sendable_data) {
		this.sendable_IV = new Sendable_IV(iv);
		this.sendable_data = sendable_data;
	}
	
	private class Sendable_IV implements Serializable {
		
		/**
		 * 
		 */
		private static final long serialVersionUID = -7384805029566922417L;
		/**
		 * 
		 */
//		private static final long serialVersionUID = -7384805029566922417L;
		byte[] iv;
		Sendable_IV(byte[] iv) {
			this.iv = iv;
		}
	}
	
	public SealedObject getSendable_Data() {
		return sendable_data;
	}
	
	public byte[] getIV() {
		return sendable_IV.iv;
	}
	
	public static SealedObject encryptData_Sendable(String transformation, Key key, Sendable_Data sendable_data) {
		Cipher encryptionCipher = null;
		try {
		encryptionCipher = Cipher.getInstance(transformation);
		encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
		return new SealedObject(sendable_data, encryptionCipher);
		} catch (Exception e) {
			System.out.println("Could not create SealedObject from Sendable_Data!");
			e.printStackTrace();
			return null;
		}
	}
	
	public Sendable_Data decrypt(String transformation, Key key) {
		try {
			byte[] iv = getIV();
			Cipher decryptionCipher = Cipher.getInstance(transformation);
			decryptionCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			return (Sendable_Data) getSendable_Data().getObject(decryptionCipher);
		} catch (Exception exception) {
			System.out.println("Failed to decrypt Sendable!");
			exception.printStackTrace();
			return null;
		}
	}
}
