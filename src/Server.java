import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

public class Server {
//	public static final int ITERATIONS_PASSWORD_HASHING = 1000;
	
	/**
	 * 50 000 is the iteration count used for debugging with the Surface
	 * The RaspberryPi's low hash rate makes 1000 iterations the highest
	 * tolerable count.
	 * Thus, all users' passwords stored on the Surface are hashed with 50 000
	 * iterations, while all passwords stored on the RaspberryPi are hasehd with
	 * 1000 iterations
	 */
	public static final int ITERATIONS_PASSWORD_HASHING = 50000;
//	public static final int ITERATIONS_PASSWORD_HASHING = 150000;
	
	/*
	 * The keylength used for securely hashing and salting passwords of the users.
	 * For hashing, RSA Laboratories' PBKDF2 is used using 50000 iterations (see
	 * @ITERATIONS_PASSWORD_HASHING, a 128-bit salt and 256-bit keylength as outcome. 
	 */
	public static final int KEYLENGTH_PASSWORD_HASHING = 256;
	
	/**
	 * The file storing the Server's private key
	 */
	public static final File FILE_PRIVATE_KEY = new File("private2048.key");
	
	/**
	 * Encryption and decryption algoeithms, not used
	 */
	public static final String AES_ALGORITHM = "AES";
	public static final String RSA_ALGORITH = "RSA";
	
	
	/**
	 * The Transformation algorithm, mode and padding used for encryption
	 * Uses AES, Cipher Block Chaining mode and PKCS5-Padding
	 */
	public static final String TRANSFORMATION_WITH_AES = "AES/CBC/PKCS5Padding";
	
	
	/**
	 * Transformation algorithm, mode and padding for asymmetrical encryption
	 * Algorithm: RSA
	 * Mode: None ('ECB' is a misnomer by Java)
	 * Padding: OAEP (Optimal Asymmetric Encryption Padding)
	 */
	public static final String TRANSFORMATION_WITH_RSA = "RSA/ECB/OAEPPadding";
	
	
	/**
	 * The home directory of the Server
	 * Example path:
	 *  /path/to/user/FileSync 2/.server
	 */
	public static final File FILE_SERVER_HOME_DIRECTORY = new File(System.getProperty("user.home") + File.separator + "FileSync 2" + File.separator + ".server");
	
	
	/**
	 * The root directory pointing to all users
	 * Example path:
	 *  /path/to/user/FileSync 2/.server/users
	 */
	public static final File FILE_USERS_ROOT_DIRECTORY = new File (FILE_SERVER_HOME_DIRECTORY + File.separator + "users");
	
	
	/**
	 * Deprecated
	 */
//	static final File FILE_USERNAMES = new File (FILE_SERVER_HOME_DIRECTORY + File.separator + "usernames.dat");
//	static final File FILE_PASSWORDS = new File (FILE_SERVER_HOME_DIRECTORY + File.separator + "passwords.dat");
//	static final File FILE_SALTS = new File (FILE_SERVER_HOME_DIRECTORY + File.separator + "salts.dat");
	
	
	/**
	 * Cipher used for asymmetrical encryption, see @TRANSFORMATION_WITH_RSA
	 */
	public static Cipher RSA_ENCRYPTION_CIPHER;
	
	
	/**
	 * PrivateKey object storing private key
	 */
	public static PrivateKey PRIVATE_KEY;
	

	/**
	 * ServerSocket object listening for Clients on port 6789
	 */
	ServerSocket server;
	
	
	/**
	 * SecureRandom object, used for salt generation
	 */
	static SecureRandom random;
	

	/**
	 * Started once, the ServerSocket object {@code server} listens for clients
	 * connecting. Once connected to a new client, a new thread with the {@code ConnectionHandler}
	 * Runnable interface is started, completing the handshake, authentication and dialog
	 * 
	 * For handshake protocol, see {@link startHandshale()}
	 * For authentication, see while-loop
	 * For dialog, see {@link startDialog()}
	 *  
	 * @throws Exception If anything goes wrong, destroy thread
	 */
	private Server() throws Exception {
		random = new SecureRandom();
		PRIVATE_KEY = loadPrivateKeyFromFile(FILE_PRIVATE_KEY);
		server = new ServerSocket(6789);
		System.out.println("Server setup.");
		while (true) {
			Socket connection = server.accept();
			System.out.println("_________________________");
			System.out.println("Connected to a new Client.");
			new Thread(new ConnectionHandler(connection)).start();
		}
	}

	/**
	 * Loads the server's private key from the {@code FILE_PRIVATE_KEY} object pointing to the file
	 * storing its key
	 * 
	 * @param file The file storing the private key
	 * @return Server's private key
	 * 
	 * @throws NoSuchAlgorithmException Thrown if JRE does not support PKCS8-Encoding
	 * @throws IOException Thrown if file is not found or cannot be read
	 * @throws InvalidKeySpecException Thrown is problems occour converting bytes into Key
	 */
	private PrivateKey loadPrivateKeyFromFile(File file) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		FileInputStream fis = new FileInputStream(file);
		byte[] bytes = new byte[(int) file.length()];
		fis.read(bytes);
		fis.close();

		PKCS8EncodedKeySpec keySpecs = new PKCS8EncodedKeySpec(bytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(keySpecs);
	}

	/**
	 * Initializes a Cipher object with algorithm, mode, padding and encryption key
	 * 
	 * @param transformation Algorithm, mode and padding, see {@link TRANFORMATION_WITH_AES} and {@link TRANSFORMATION_WIH_RSA}
	 * @param key Encryption key
	 * @return initialized Cipher object
	 */
	Cipher initializeEncryptionCipher(String transformation, Key key) {
		Cipher c = null;
		try {
			c = Cipher.getInstance(transformation);
			c.init(Cipher.ENCRYPT_MODE, key);
		} catch (Exception exception) {
			exception.printStackTrace();
		}
		return c;
	}
	
	/**
	 * Deprecated
	 * @param file
	 * @param data
	 */
	static synchronized void writeToDatabase(File file, String data) {
		try {
			Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file)));
			writer.write(System.lineSeparator() + data);
			writer.flush();
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Starts the server, first method to be called
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			new Server();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
