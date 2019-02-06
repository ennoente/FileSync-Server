package Sendable;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;

//import Sendable.Sendable_Data.Directory;

public class Directory implements Serializable {
	
		/**
	 * 
	 */
	private static final long serialVersionUID = -4066062837932428086L;
		/**
	 * 
	 */
//	private static final long serialVersionUID = -4066062837932428086L;
	
		public Directory[] subdirectories;
		byte[][] files;
		String[] fileNames;
		String internal_path;
		
		String STORAGE_ROOT;
		String destination_dir_root;
		
		
		public Directory(String root_storage_dir, String internal_path) {
			this.internal_path = internal_path;
			this.STORAGE_ROOT = root_storage_dir;
			setupDirectory(new File (STORAGE_ROOT + File.separator + internal_path));
		}
		
		public void saveDirectories(String destination_dir_root) {
			this.destination_dir_root = destination_dir_root;
			save();
		}
		
		private void save() {
			// Create this directory
			File newDir = new File(destination_dir_root + File.separator + internal_path);
			if (newDir.mkdirs()); //System.out.println("Created dir at " + internal_path);
			else; //System.out.println("Could not create dir at " + newDir);
			
			// Save files in it
			for (int i = 0; i < files.length; i++) {
				try {
					File newFile = new File(destination_dir_root + File.separator + internal_path + File.separator + fileNames[i]);
					newFile.createNewFile();
					FileOutputStream fos = new FileOutputStream(newFile);
					fos.write(files[i]);
					fos.flush();
					fos.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			
			// Go through every subdirectory and do that
			// Every subdirectory will, following the hierarchy,
			// create a subdirectory with the corresponding files
			for (Directory d : subdirectories) d.save();
		}
		
		private void setupDirectory(File dir) {
			int number_of_files = 0;
			int number_of_subdirs = 0;
			
			for (File f : dir.listFiles()) {
//				System.out.println("Current file:" + f.getAbsolutePath());
				if (f.isFile()) number_of_files++;
				else number_of_subdirs++;
			}
			
			files = new byte[number_of_files][];
			fileNames = new String[number_of_files];
			subdirectories = new Directory[number_of_subdirs];
			
			int i = 0;
			int k = 0;
			for (File _f : dir.listFiles()) {
				if (_f.isFile()) {
					files[i] = new byte[(int) _f.length()];
					fileNames[i] = _f.getName();
					try {
						FileInputStream fis = new FileInputStream(_f);
						fis.read(files[i]);
						fis.close();
						i++;
					} catch (IOException e) {
						e.printStackTrace();
					}
				} else {
					// Subdirectory
					subdirectories[k] = new Directory(STORAGE_ROOT, internal_path + File.separator +_f.getName());
					k++;
				}
			}
		}
	}