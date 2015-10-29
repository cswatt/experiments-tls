/**
 * @author Cecilia Watt
 */
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLSocketFactory;

public class Client extends EncryptedHost{
	static SSLSocketFactory ssf;
	Socket client;
	String serverName;
	int port;
	byte[] OK = "OK".getBytes();
	byte[] NOK = "NOK".getBytes();

	public Client(String serverName, int port) throws IOException {
		this.serverName = serverName;
		this.port = port;
		
		//continuously get input
		while(true){
			System.out.print("> ");
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			String input = br.readLine();
			String inpu = input.substring(0, 4);

			if (inpu.equals("put ")){
				parse(input, 'P');
				continue;
			}
			else if (inpu.equals("get ")){
				parse(input, 'G');
				continue;
			}
			else if (inpu.equals("stop")){
				return;
			}
			else {
				System.out.println("Invalid input.");
				continue;
			}
		}
	}
	/**
	 * Check that command line arguments are valid
	 * @param args
	 * @return
	 */
	public static boolean checkArgs(String[] args){
		boolean isValid = true;
		if (args.length < 2){
			System.out.println("Did not supply port number.");
			return false;
		}
		if (!args[1].matches("[0-9]+")){
			System.out.println("Invalid port number");
			return false;
		}
		return isValid;
	}
	/**
	 * Read get/put commands and act based on them
	 * @param s
	 * @param option
	 */
	public void parse(String s, char option){
		String[] tokens = s.split("[ ]+");
		if ((tokens.length < 3) || (tokens.length > 4)){
			System.out.println("Not enough arguments.");
			return;
		}
		if ((!tokens[2].equals("N")) && (!tokens[2].equals("E"))){
			System.out.println("Did not properly specify encryption options.");
			return;
		}
		if ((tokens[2].equals("E")) && (tokens.length < 4)){
			System.out.println("Specified encryption but did not supply a password.");
			return;
		}
		if ((tokens[2].equals("E")) && (tokens[3].length() != 8)){
			System.out.println("Specified encryption but did not supply valid password.");
			return;
		}

		//now some logic
		if (option == 'P'){
			if (tokens.length == 3) put(tokens[1], false, "");
			if (tokens.length == 4) put(tokens[1], true, tokens[3]);
		}
		if (option == 'G'){
			if (tokens.length == 3) get(tokens[1], false, "");
			if (tokens.length == 4) get(tokens[1], true, tokens[3]);
		}
	}

	/**
	 * Request a file from the server, decrypt if appropriate.
	 * @param filename
	 * @param encrypt
	 * @param password
	 */
	public void get(String filename, boolean encrypt, String password) {
		try{
			client = ssf.createSocket(serverName, port);
			send(client.getOutputStream(), "GET");
			send(client.getOutputStream(), filename);
			byte[] flag = read(client.getInputStream());
			if (Arrays.equals(flag, NOK)){
				System.out.println("File retrieval failed.");
				return;
			}
			byte[] data = read(client.getInputStream());
			byte[] sha = read(client.getInputStream());
			if (encrypt){
				data = AES_decrypt(data, password);
			}
			if (verify(data, sha)){
				System.out.println("File verified against hash. Trying to save...");
			}
			else{
				System.out.println("File does not match hash. Was this file encrypted?");
				return;
			}
			save(data, filename);
			client.close();
		} catch (IOException e){
			System.out.println("Server communication failed.");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Decryption error.");
		} catch (InvalidKeyException e) {
			System.out.println("Decryption error.");
		} catch (NoSuchPaddingException e) {
			System.out.println("Decryption error.");
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println("Decryption error. Is your password correct?");
		} catch (IllegalBlockSizeException e) {
			System.out.println("Decryption error. Is your password correct?");
		} catch (BadPaddingException e) {
			System.out.println("Decryption error. Is your password correct?");
		}
	}
	/**
	 * Try to save.
	 * @param data
	 * @param filename
	 */
	public void save(byte[] data, String filename){
		try {
			saveFile(data, "retrieved_from_server", filename);
			System.out.println("Transfer of " + filename + " complete");
		} catch (IOException e) {
			System.out.println("Did not save successfully.");
		}
	}
	/**
	 * Try to send a file to the server
	 * @param filename
	 * @param encrypt
	 * @param password
	 */
	public void put(String filename, boolean encrypt, String password) {
		try{
			client = ssf.createSocket(serverName, port);
			byte[] filedata = loadFile(filename);
			byte[] sha = SHA_256(filedata);
			if (encrypt){
				filedata = AES_encrypt(filedata, password);
			}
			send(client.getOutputStream(), "PUT");
			send(client.getOutputStream(), filename);
			send(client.getOutputStream(), filedata);
			send(client.getOutputStream(), sha);

			// see if it succeded
			byte[] response = read(client.getInputStream());
			if (Arrays.equals(response, OK)){
				System.out.println("Transfer succeeded.");
			}
			else if (Arrays.equals(response, NOK)){
				System.out.println("Transfer failed.");
			}
			client.close();
		} catch (IOException e){
			System.out.println("Server communication failed.");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Encryption error.");
		} catch (InvalidKeyException e) {
			System.out.println("Encryption error.");
		} catch (NoSuchPaddingException e) {
			System.out.println("Encryption error.");
		} catch (IllegalBlockSizeException e) {
			System.out.println("Encryption error.");
		} catch (BadPaddingException e) {
			System.out.println("Encryption error.");
		}
	}

	public static void main(String [] args) {
		//set things
		System.setProperty("javax.net.ssl.keyStore","client_keystore.jks"); 
		System.setProperty("javax.net.ssl.keyStorePassword","123456"); 
		System.setProperty("javax.net.ssl.trustStore", "client_truststore.ts");

		//check that arguments are valid
		if (!checkArgs(args)) return;

		//talk to server
		ssf = (SSLSocketFactory) SSLSocketFactory.getDefault();
		String serverName = args[0];
		int port = Integer.parseInt(args[1]);

		try {
			Client c = new Client(serverName, port);
		} catch (IOException e) {
			System.out.println("Command-line input error.");
		}
	}

}