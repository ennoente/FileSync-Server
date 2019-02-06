package Sendable;

import java.io.Serializable;

/**
 * 
 * @author Enno
 *
 */
public class TokenSendable implements Serializable {
	private static final long serialVersionUID = 1566376911793400264L;
	private String username = null;
	private byte[] token = null;

	public TokenSendable(boolean rememberSession, String username, byte[] token) {
		if (rememberSession) {
			this.username = username;
			this.token = token;
		}
	}

	public boolean rememberSession() {
		return username != null && token != null;
	}

	public String getUsername() {
		return this.username;
	}

	public byte[] getToken() {
		return this.token;
	}
}