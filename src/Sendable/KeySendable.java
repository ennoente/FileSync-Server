package Sendable;
import java.io.Serializable;

public class KeySendable implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 735401437969386916L;
	byte[] bytes;

	public KeySendable(byte[] bytes) {
		this.bytes = bytes;
	}
	
	public byte[] getBytes() {
		return bytes;
	}
}
