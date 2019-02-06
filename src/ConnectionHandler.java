import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.nio.channels.NetworkChannel;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import Sendable.Directory;
import Sendable.KeySendable;
import Sendable.Sendable;
import Sendable.SendableHelper;
import Sendable.Sendable_Data;
import Sendable.TokenSendable;

public class ConnectionHandler implements Runnable {
	Socket connection;
	ObjectInputStream input;
	ObjectOutputStream output;

	Cipher encryptionCipher;
	Cipher decryptionCipher_AES;
	Cipher decryptionCipher_RSA;

	SealedObject sealedObject;
	KeySendable keySendable;

	byte[] BYTES_KEY;
	Key SESSION_KEY;

	User user;

	byte[] salt;
	
	File SESSION_COOKIE_FILE;

	public ConnectionHandler(Socket connection) {
		this.connection = connection;
	}

	@Override
	public void run() {
		System.out.println("Thread started for handling the current connection.");

		// Setup necessary Streams
		try {
			input = new ObjectInputStream(connection.getInputStream());
			output = new ObjectOutputStream(connection.getOutputStream());
			System.out.println("Streams setup.");
		} catch (IOException ioException) {
			System.out.println("Failed to setup streams!");
			ioException.printStackTrace();
		}

		// Secure the connection to the Client
		// Listen for Session Key and MAC
		try {
			while ((sealedObject = (SealedObject) input.readObject()) != null) {
				long startOfEncryption = System.currentTimeMillis();
				System.out.println("Received Data from Client. Trying to decrypt...");
				keySendable = (KeySendable) sealedObject.getObject(Server.PRIVATE_KEY);
				BYTES_KEY = keySendable.getBytes();
				long delta = System.currentTimeMillis() - startOfEncryption;
				System.out.println("Successfully read out KeySendable.");
				System.out.println("Decrypting took " + delta + " Miliseconds");
				break;
			}
		} catch (ClassNotFoundException | IOException | InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		// Create @SESSION_KEY from received bytes
		SESSION_KEY = new SecretKeySpec(BYTES_KEY, Server.AES_ALGORITHM);

		// Initialize the encryption cipher with the now known Session Key
		try {
			encryptionCipher = Cipher.getInstance(Server.TRANSFORMATION_WITH_AES);
			encryptionCipher.init(Cipher.ENCRYPT_MODE, SESSION_KEY);

			decryptionCipher_AES = Cipher.getInstance(Server.TRANSFORMATION_WITH_AES);

			decryptionCipher_RSA = Cipher.getInstance(Server.TRANSFORMATION_WITH_RSA);
			decryptionCipher_RSA.init(Cipher.DECRYPT_MODE, Server.PRIVATE_KEY);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException exceptions) {
			exceptions.printStackTrace();
		}
		System.out.println("Encryption Cipher initialized.");

		// Send response to Client
		// Response contains the Session Key, encrypted with the Session Key itself
		KeySendable response_raw = new KeySendable(BYTES_KEY);
		SealedObject response_sealed = null;
		try {
			response_sealed = new SealedObject(response_raw, encryptionCipher);
		} catch (IllegalBlockSizeException | IOException e) {
			e.printStackTrace();
		}

		// Write sealed response to Client
		try {
			output.writeObject(response_sealed);
		} catch (IOException e) {
			e.printStackTrace();
		}

		System.out.println("Success! Listening to Client...");

		user = new User();

		Sendable sendable = null;
		try {
			while ((sendable = (Sendable) input.readObject()) != null) {
				Sendable_Data response = new Sendable_Data();
				response.setAuthenticationSuccessful(false);

				System.out.println("Received Sendable. Reading...");

				Sendable_Data data = decryptSealedDataWithAES(sendable);

				// Contains cookie
				if (data.getCookie() != null) {
					String cookie_username = data.getCookieUsername();
					byte[] cookie_token = data.getCookieToken();

					System.out.println("Cookie session requested for user '" + cookie_username + "'");
					System.out.println("Cookie-token is '" + cookie_token + "'");

					String cookie_username_prefix = cookie_username.substring(0, 3);

					File cookie_dir = new File (Server.FILE_USERS_ROOT_DIRECTORY + File.separator + cookie_username_prefix + File.separator + data.getCookieUsername() + File.separator + "cookies");

					// Cookie directory of this user contains cookies. Check through corresponding token
					if (cookie_dir.listFiles() != null) {
						FileInputStream fis = null;
						ObjectInputStream ois = null;
						for (File f : cookie_dir.listFiles()) {
							fis = new FileInputStream(f);
							ois = new ObjectInputStream(fis);
							Sendable_Data.CookieSendable cookie = (Sendable_Data.CookieSendable) ois.readObject();
							ois.close();
							fis.close();

							// Successful login
							if (Arrays.equals(cookie.getToken(), cookie_token)) {
								System.out.println("Cookie matches up!");

								// set user's root storage folder to 
								user.root_storage_folder = new File (Server.FILE_USERS_ROOT_DIRECTORY + File.separator + cookie_username_prefix + File.separator + cookie_username + File.separator + "storage");
								
								user.name = cookie_username;

								// Delete old cookie
								if (f.delete()) System.out.println("Deleted cookie " + f.getName());
								else System.out.println("Could not delete cookie!");

								// Create new token
								byte[] token = generateToken();

								// authentication successful
								response.setAuthenticationSuccessful(true);

								// send files from user's root storage folder
//								response.fillInFiles(user.getFilesInDir(user.root_storage_folder));
								
								// send files' shells
								response.setFileShells(user.root_storage_folder.listFiles());

								// Create and save new cookie
								response.setCookie(cookie_username, token);
								try {
									SESSION_COOKIE_FILE = new File (cookie_dir + File.separator + "session-" + cookie_dir.listFiles().length);
								} catch (NullPointerException nullPointerException) {
									SESSION_COOKIE_FILE = new File (cookie_dir + File.separator + "session-0");
								}
								FileOutputStream fos = new FileOutputStream(SESSION_COOKIE_FILE);
								ObjectOutputStream oos = new ObjectOutputStream(fos);
								oos.writeObject(response.getCookie());
								oos.flush();
								oos.close();
								fos.flush();
								fos.close();
								
								System.out.println("Wrote new cookie in " + SESSION_COOKIE_FILE.getName());

								// Leave while-loop
								break;
							}
						}
						if (fis != null && ois != null) {
							fis.close();
							ois.close();
						}
					}
					// Encrypt data and send to client
					Sendable login_response = SendableHelper.createSendableFromSendable_Data(response, Server.TRANSFORMATION_WITH_AES, SESSION_KEY);
					output.writeObject(login_response);
					
					// Start dialog if authentication via cookie was successful
					if (response.checkAuthenticationSuccessful())
						try {
//							startDialog()
							new Thread (new DialogHandler()).start();
							System.out.println("Breaking out of cookie / login loop");
							return;
						} catch (Exception exception) {
							exception.printStackTrace();
						}
					
					// No cookie inside Sendable from client
				} else {
					String[] login_commands = data.getCommands();
					String login_username = data.getUsername();
					char[] login_password = data.getPassword();
					boolean rememberUser = data.getRememberUser();

					// username's three letter prefix
					String username_prefix = login_username.substring(0, 3);

					// User's files and directories
					File user_directory		= new File (Server.FILE_USERS_ROOT_DIRECTORY + File.separator + username_prefix + File.separator + login_username);
					File user_password		= new File (user_directory + File.separator + "password");
					File user_salt			= new File (user_directory + File.separator + "salt");
					File user_storage_dir	= new File (user_directory + File.separator + "storage");
					File user_cookies_dir   = new File (user_directory + File.separator + "cookies");
					
					boolean auth_successful = false;
					
					System.out.println("user's dir: '" + user_directory.getAbsolutePath() + "'");

					// If the server should log in or (see else) register
					if (login_commands[0].equals("login")) {
						if (user_directory.exists()) {
							System.out.println("Trying to log in user '" + login_username + "'");
							// Compare entered password with stored password
							byte[] stored_password = new byte[(int) user_password.length()];
							FileInputStream fis = new FileInputStream(user_password);
							fis.read(stored_password);
							fis.close();

							byte[] stored_salt = new byte[(int) user_salt.length()];
							fis = new FileInputStream(user_salt);
							fis.read(stored_salt);
							fis.close();

							byte[] recalculated_password = createSaltedHash(login_password, stored_salt, Server.ITERATIONS_PASSWORD_HASHING, Server.KEYLENGTH_PASSWORD_HASHING);

							if (Arrays.equals(stored_password, recalculated_password)) {
								// Mark successful
								auth_successful = true;
								
								// Set user.name variable accordingly
								user.name = login_username;
								
								// passwords match up
								System.out.println("Passwords match up - successful login!");
								user.root_storage_folder = user_storage_dir;

								// Authentication was a success
								response.setAuthenticationSuccessful(true);
								
								// Send files
//								response.fillInFiles(user.getFilesInDir(user_storage_dir));
								
								// Send files' shells
								response.setFileShells(user.root_storage_folder.listFiles());

								// Create cookie file, if client wishes to
								if (rememberUser) {
									System.out.println("User wants to be remembered. Store cookie file and send copy to client");
									try {
										SESSION_COOKIE_FILE = new File (user_cookies_dir + File.separator + "session-" + user_cookies_dir.listFiles().length);
									} catch (NullPointerException nullPointerException) {
										SESSION_COOKIE_FILE = new File (user_cookies_dir + File.separator + "session-0");
									}

									System.out.println("newCookie-Path:" + SESSION_COOKIE_FILE.getAbsolutePath());

									// Create the cookie file
									SESSION_COOKIE_FILE.createNewFile();

									// Send cookie data to user
									response.setCookie(login_username, generateToken());

									// Save cookie data as a file
									FileOutputStream fos = new FileOutputStream(SESSION_COOKIE_FILE);
									ObjectOutputStream oos = new ObjectOutputStream(fos);
									oos.writeObject(response.getCookie());
									oos.flush();
									oos.close();
									fos.flush();
									fos.close();
									
									System.out.println("Wrote cookie into " + SESSION_COOKIE_FILE.getName());
								}
							} else {
								// Passwords do not match up
								System.out.println("Passwords do not match up. Send failed request response.");
							}
						}

						Sendable login_response = SendableHelper.createSendableFromSendable_Data(response, Server.TRANSFORMATION_WITH_AES, SESSION_KEY);
						output.writeObject(login_response);
						System.out.println("Response to login request sent.");
						
						if (auth_successful) {
							// Start the main dialog with user
							try {
//								startDialog();
								new Thread (new DialogHandler()).start();
								System.out.println("Breaking out of cookie/login loop");
								return;
							} catch (Exception exception) {
								return;
							}
						}
						
					} else if (login_commands[0].equals("register")) {
						System.out.println("Command is to register a new user: '" + login_username + "'");
						System.out.println("Password for new user: '" + new String(login_password) + "'");

						if (user_directory.exists()) {
							System.out.println("Username already exists");
						} else {
							System.out.println("New Username does not exist yet");
							if (user.nameOnlyContainsPermittedCharacters(login_username.toCharArray())) {
								System.out.println("Username clean! Registering...");
								// Create necessary directories
								user_directory.mkdirs();

								// Save hashed password
								if (user_password.createNewFile()) System.out.println("Created password file");
								else System.out.println("Failed to create password file!");
								byte[] hashed_password = createSaltedHash(login_password, Server.ITERATIONS_PASSWORD_HASHING, Server.KEYLENGTH_PASSWORD_HASHING);
								FileOutputStream fos = new FileOutputStream(user_password);
								fos.write(hashed_password);
								fos.flush();
								fos.close();

								// Save salt
								if (user_salt.createNewFile()) System.out.println("Created salt file." + user_salt.getAbsolutePath());
								else System.out.println("Failed to create salt file!" + user_salt.getAbsolutePath());
								fos = new FileOutputStream(user_salt);
								fos.write(salt);
								fos.flush();
								fos.close();

								// Create storage directory
								if (!user_storage_dir.mkdir()) System.out.println("Failed to create storage directory!");
								else System.out.println("Created storage dir at " + user_storage_dir.getAbsolutePath());

								// Create cookie directory
								if (!user_cookies_dir.mkdir()) System.out.println("Failed to create cookies directory!");
								else System.out.println("Created cookies dir at " + user_cookies_dir.getAbsolutePath());
							} else System.out.println("Username NOT clean!");
						}
					}
				}
				sendable = null;
			}
		} catch (SocketException socketException) {
			System.out.println("Client ended the connection or a problem occoured. Closing thread");
		} catch (ClassNotFoundException | IOException e1) {
			e1.printStackTrace();
		}
		System.out.println("Outside of while loop. Closing.");
		return;
	}
	
	/**
	 * The main Dialog taking place after successful authentication
	 * 
	 * The user may now send requests to the server containing commands and corresponding data/information
	 * Commands:
	 * 		user-logout
	 * 		update-directory
	 * 		send-file
	 * 		send-directory
	 * 		save-file
	 * 		save-directory
	 * 		
	 */
//	private void startDialog() {}

	private class User {
		private File root_storage_folder;
		String name;

		/**
		 * Returns true, if and only if the username only contains permitted characters.
		 * The following are <p> permitted </p>:
		 * A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z,
		 * 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -, _
		 * Lower case letters are permitted, too, respectively.
		 * @param username
		 * @return If the username only contains permitted characters
		 */
		private boolean nameOnlyContainsPermittedCharacters(char[] username) {
			char[] permitted_characters = new char[] {
					'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
					'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
					'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
			};

			for (char c : username) {
				if (!checkChar(c, permitted_characters)) return false;
			}

			return true;
		}

		private boolean checkChar(char ch, char[] permittedChars) {
			for (char c : permittedChars) if (c == ch) return true;
			return false;
		}
	}


	private byte[][] getFilesInDir(File dir) {
		byte[][] _files = new byte[dir.listFiles().length][];
		try {
			File[] files = dir.listFiles();

			for (int i = 0; i < files.length; i++) {
				byte[] bytes = new byte[(int) files[i].length()];
				FileInputStream fis = new FileInputStream(files[i]);
				fis.read(bytes);
				fis.close();
				_files[i] = bytes;
			}
		} catch (IOException ioException) {
			ioException.printStackTrace();
			return null;
		}
		return _files;
	}
	
	private byte[] fileToByteArray(File file) {
		try {
			FileInputStream fis = new FileInputStream(file);
			byte[] bytes = new byte[(int) file.length()];
			fis.read(bytes);
			fis.close();
			fis = null;
			return bytes;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		
	}

	private byte[] generateToken() {
		byte[] token = new byte[16];
		Server.random.nextBytes(token);
		return token;
	}

	Sendable_Data decryptSealedDataWithAES(Sendable raw_sendable) {
		try {
			byte[] iv = raw_sendable.getIV();
			Cipher decryptionCipher = Cipher.getInstance(Server.TRANSFORMATION_WITH_AES);
			decryptionCipher.init(Cipher.DECRYPT_MODE, SESSION_KEY, new IvParameterSpec(iv));
			return (Sendable_Data) raw_sendable.getSendable_Data().getObject(decryptionCipher);
		} catch (Exception exception) {
			System.out.println("Failed to decrypt Sendable!");
			exception.printStackTrace();
			return null;
		}
	}

	/**
	 * Will create a random salt automatically
	 * @param password Password to be hashed
	 * @param iterations Iteration count
	 * @param keyLength Key length
	 * @return salted hash of {@code password}
	 */
	private byte[] createSaltedHash(char[] password, int iterations, int keyLength) {
		System.out.println("Creating salt...");
		byte[] salt = new byte[16];
		Server.random.nextBytes(salt);
		System.out.println("Salt created!");
		return createSaltedHash(password, salt, iterations, keyLength);
	}

	private byte[] createSaltedHash(char[] password, byte[] salt, int iterations, int keyLength) {
		this.salt = salt;
		KeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
		SecretKeyFactory secretKeyFactory = null;
		System.out.println("Preperations for hashing done.");
		try {
			System.out.println("Hashing with " + iterations + " iterations...");
			secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			byte[] encoded = secretKeyFactory.generateSecret(keySpec).getEncoded();
			System.out.println("Hashing finished.");
			return encoded;
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private class DialogHandler implements Runnable {
		@Override
		public void run() {
			System.out.println("___ Started Dialog ___");
			Sendable request = null;
			Sendable_Data data;
			
			Sendable response;
			Sendable_Data _data = new Sendable_Data();
			
			try {
				while ((request = (Sendable) input.readObject()) != null) {
					// User sent Sendable object
					
					System.out.println("__ new command __");
					
					// Decrypt
					data = request.decrypt(Server.TRANSFORMATION_WITH_AES, SESSION_KEY);
					
					String destination_dir;
					
					String[] request_commands = data.getCommands();
					switch (request_commands[0]) {
					
					case "user-logout":
						System.out.println("Logging out " + user.name);
						// Logout current user
						
						// Delete cookie
						SESSION_COOKIE_FILE.delete();
						
						_data.fillInInfo(new String[] { "logout-successful" });
						
						System.out.println("Successfully logged out user " + user.name);
						return;
						
					case "update-directory":
						System.out.println("Command: Send new directory to " + user.name);
						
						// TODO Es gibt nen Fehler bei der Umwandlung von File.seperator von WINDOWS
						// TODO auf den File.seperator von LINUX!!
						String newDir_raw = data.getInfo()[0];
//						newDir_raw = newDir_raw.replaceAll("\\", File.separator);
						System.out.println("New dir: '" + newDir_raw + "'");
						
						File newDir = new File (user.root_storage_folder + File.separator + newDir_raw);
						
						System.out.println("Path to new dir is '" + newDir + "'");
						System.out.println("newDir exists: " + newDir.exists());
						System.out.println("newDir is Directory: " + newDir.isDirectory());
						
//						String newDir_path = user.root_storage_folder.getAbsolutePath() + newDir_raw;
						System.out.println("Path to new dir is '" + newDir + "', does it exist: " + newDir.exists() + ", the dir contains " + newDir.listFiles().length + " Files and dirs");
						
						_data.setFileShells(newDir.listFiles());
						break;
						
					case "send-file":
						System.out.println("Command: send file to user " + user.name);
						
						String internalFilePath = data.getInfo()[0];
						
						System.out.println("Path from info: '" + internalFilePath + "'");
						
						File file_to_send = new File (user.root_storage_folder + File.separator + internalFilePath);
						System.out.println("File to send in filesystem: '" + file_to_send.getAbsolutePath() + "', exists: " + file_to_send.exists());
						
						// Fill in file's bytes
						byte[][] files = new byte[1][];
						files[0] = fileToByteArray(file_to_send);
						
						_data.fillInFiles(files);
						break;
						
					case "send-directory":
						System.out.println("Command: send directory to user " + user.name);
						
						String internal_dir_path = data.getInfo()[0];
						System.out.println("Directory path: '" + internal_dir_path + "'");
						
//						File dir_to_send = new File (user.root_storage_folder + File.separator + )
						break;
					case "save-directory":
						System.out.println("Command: save directory for user " + user.name);
						
						destination_dir = data.getInfo()[0];
						System.out.println("Destination for user's dir: " + destination_dir);
						System.out.println("In File-system: " + user.root_storage_folder + File.separator + destination_dir);
						
						Directory dir_from_user = data.getDirectory();
						dir_from_user.saveDirectories(user.root_storage_folder + File.separator + destination_dir);
						
						// Reply
//						_data.setFileShells(user.root_storage_folder.getAbsoluteFile().listFiles());
						_data.setFileShells(new File (user.root_storage_folder.getAbsolutePath() + File.separator + destination_dir).listFiles());
						_data.fillInInfo(new String[] { "directory-upload-successful" });
						break;
					case "save-file":
						System.out.println("Command: save file for user " + user.name);
						
						destination_dir = data.getInfo()[0];
						System.out.println("Destination for user's dir: " + destination_dir);
						System.out.println("In File-system: " + user.root_storage_folder + File.separator + destination_dir);
						
						// Save file
						String file_path = user.root_storage_folder.getAbsolutePath() + data.getInfo()[0];
						String file_name = data.getInfo()[1];
						
						File newFile = new File (file_path + File.separator + file_name);
						
						FileOutputStream fos = new FileOutputStream(newFile);
						fos.write(data.getFiles()[0]);
						fos.flush();
						fos.close();
						
						// Fill in Info to response
						_data.fillInInfo(new String[] { "file-upload-successful" });
						
						// Fill in file shells
						_data.setFileShells(new File(file_path).listFiles());
					}
					
					// Respond
					response = SendableHelper.createSendableFromSendable_Data(_data, Server.TRANSFORMATION_WITH_AES, SESSION_KEY);
					output.writeObject(response);
					System.out.println("Wrote response to Client.");
				}
			} catch (SocketException socketException) {
				System.out.println("Client ended the session or a problem occoured. Shutting down thread.");
			}
			catch (ClassNotFoundException | IOException e) {
//				System.out.println("Exception listening. Socket probably closed. Shutting down Thread");
				e.printStackTrace();
				System.out.println("Shutting down this Thread!");
				return;
			}
			return;
		}
	}
}
