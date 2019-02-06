package Sendable;

import java.io.File;
import java.io.Serializable;

//import Sendable.Sendable_Data.CommandsSendable;

public class Sendable_Data implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 3107165048751013861L;
	/**
	 * 
	 */
//	private static final long serialVersionUID = -7391236951881623186L;
	
	UserpassSendable userpass_sendable;
	CommandsSendable commands_sendable;
	InfoSendable info_sendable;
	CookieSendable cookie_sendable;
	Directory directory_sendable;

	FileShellSendable[] shells;

	public Sendable_Data(String username, char[] password, boolean rememberUser, String[] commands) {
		userpass_sendable = new UserpassSendable(username, password, rememberUser);
		commands_sendable = new CommandsSendable(commands);
	}

	public Sendable_Data(String[] commands, String[] info) {
		commands_sendable = new CommandsSendable(commands);
		info_sendable = new InfoSendable(info);
	}

	public Sendable_Data(byte[][] files) {
		info_sendable = new InfoSendable(files);
	}

	public Sendable_Data() {
	}


	private class UserpassSendable implements Serializable {
		
		/**
		 * 
		 */
		private static final long serialVersionUID = 6934743276038041497L;
		/**
		 * 
		 */
//		private static final long serialVersionUID = 6934743276038041497L;
		String username;
		char[] password;
		boolean rememberUser;
		private UserpassSendable(String username, char[] password, boolean rememberUser) {
			this.username = username;
			this.password = password;
			this.rememberUser = rememberUser;
		}
	}

	private class CommandsSendable implements Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = -6838797504835581303L;
		/**
		 * 
		 */
//		private static final long serialVersionUID = -6838797504835581303L;
		String[] commands;
		private CommandsSendable(String[] commands) {
			this.commands = commands;
		}
	}

	private class InfoSendable implements Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = 8851463384741609227L;
		/**
		 * 
		 */
//		private static final long serialVersionUID = 3244190469543605138L;
		String[] info;
		boolean authenticationSuccessful;
		byte[][] files;
		private InfoSendable(byte[][] files) {
			this.files = files;
		}
		private InfoSendable(boolean authSuccessful) {
			this.authenticationSuccessful = authSuccessful;
		}
		private InfoSendable(String[] info) {
			this.info = info;
		}
	}

	public class FileShellSendable implements Serializable {


		/**
		 * 
		 */
		private static final long serialVersionUID = -7227487487433185112L;
		/**
		 * 
		 */
//		private static final long serialVersionUID = 6495126453599679814L;
		String name;
		long lastModified;
		long size;
		long date_of_upload;
		
		boolean isDirectory;
		boolean dirContainsFiles;

		public FileShellSendable(String name, long lastModified, long size, long date_of_upload) {
			this.name = name;
			this.lastModified = lastModified;
			this.size = size;
			this.date_of_upload = date_of_upload;
		}
		
		public FileShellSendable (String name, long lastModified, long size, long date_of_upload, boolean isDirectory, boolean dirContainsFiles) {
			this (name, lastModified, size, date_of_upload);
			this.isDirectory = isDirectory;
			this.dirContainsFiles = dirContainsFiles;
		}
		
		public String getName() {
			return this.name;
		}
		
		public long getLastModified() {
			return this.lastModified;
		}
		
		public long getSize() {
			return this.size;
		}
		
		public long getUploadDate() {
			return this.date_of_upload;
		}
		
		public boolean isDir() {
			return isDirectory;
		}
		
		public boolean isDirAndContainsFiles() {
			return dirContainsFiles;
		}
	}
	

	public class CookieSendable implements Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = 1566376911793400264L;
		/**
		 * 
		 */
//		private static final long serialVersionUID = 8521438597423448862L;
		private String username = null;
		private byte[] token = null;

		public CookieSendable(boolean rememberSession, String username, byte[] token) {
			if (rememberSession) {
				this.username = username;
				this.token = token;
			}
		}

		public String getUsername() {
			return this.username;
		}

		public byte[] getToken() {
			return this.token;
		}
	}


	/*
	 * Fill in stuff
	 */

	public void fillInUsername(String username) {
		this.userpass_sendable.username = username;
	}

	public void fillInPassword(char[] password) {
		this.userpass_sendable.password = password;
	}

	public void fillInCommands(String[] commands) {
		if (commands_sendable == null) commands_sendable = new CommandsSendable(commands);
		else commands_sendable.commands = commands;
	}

	public void fillInInfo(String[] info) {
		if (info_sendable == null) info_sendable = new InfoSendable(info);
		else info_sendable.info = info;
	}

	public void fillInFiles(byte[][] files) {
		if (info_sendable == null) info_sendable = new InfoSendable(files);
		else info_sendable.files = files;
	}

	// TODO Implement date of upload to method
	public void setFileShells(File[] files) {
		if (files != null) {
			this.shells = new FileShellSendable[files.length];
			for (int i = 0; i < files.length; i++) {
				File f = files[i];
				if (f.isDirectory()) 
					shells[i] = new FileShellSendable(f.getName(), f.lastModified(), f.length(), 0, true, f.listFiles().length > 0);
				else shells[i] = new FileShellSendable(f.getName(), f.lastModified(), f.length(), 0, false, false);
				if (f.isDirectory()) System.out.println(f.getName() + " is dir and contains " + f.listFiles().length + " Files in it");
			}
		}
	}

	public void setAuthenticationSuccessful(boolean successful) {
		if (info_sendable == null) info_sendable = new InfoSendable(successful);
		this.info_sendable.authenticationSuccessful = successful;
	}

	public void setCookie(CookieSendable cookie) {
		this.cookie_sendable = cookie;
	}

	public void setCookie(String cookie_username, byte[] cookie_token) {
		if (cookie_sendable == null) cookie_sendable = new CookieSendable(true, cookie_username, cookie_token);
		else {
			cookie_sendable.username = cookie_username;
			cookie_sendable.token = cookie_token;
		}
	}
	
	public void setDirectory(Directory dir) {
		this.directory_sendable = dir;
	}
	
//	public void setDirectorySendable(File dir) {
//		this.directory_sendable = new DI
//	}

	/*
	 * Read stuff
	 */


	/*
	 * Read from the UserpassSendable object
	 */

	public String getUsername() {
		return userpass_sendable.username;
	}

	public char[] getPassword() {
		return userpass_sendable.password;
	}

	public boolean getRememberUser() {
		return userpass_sendable.rememberUser;
	}

	/*
	 * Read from the CommandSendable object
	 */

	public String[] getCommands() {
		return commands_sendable.commands;
	}

	/*
	 * Read from the InfoSendable object
	 */

	public String[] getInfo() {
		return info_sendable.info;
	}

	public byte[][] getFiles() {
		return info_sendable.files;
	}

	public boolean checkAuthenticationSuccessful() {
		return info_sendable.authenticationSuccessful;
	}

	public boolean rememberSession() {
		return cookie_sendable.username != null && cookie_sendable.token != null;
	}

	public CookieSendable getCookie() {
		return cookie_sendable;
	}

	public String getCookieUsername() {
		return cookie_sendable.username;
	}

	public byte[] getCookieToken() {
		return cookie_sendable.token;
	}
	
	public FileShellSendable[] getFileShells() {
		return shells;
	}
	
	public Directory getDirectory() {
		return this.directory_sendable;
	}
}