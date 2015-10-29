import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptedHost extends Thread{
	/**
	 * given a string filename, loads file into byte array
	 * @param filename
	 * @return
	 * @throws IOException
	 */
	public byte[] loadFile(String filename) throws IOException{
		File myFile = new File(filename);
		byte [] output = new byte [(int)myFile.length()];
		FileInputStream fis = new FileInputStream(myFile);
		BufferedInputStream bis = new BufferedInputStream(fis);
		bis.read(output,0,output.length);
		bis.close();
		fis.close();
		return output;
	}
	/**
	 * saves file to disk
	 * @param data
	 * @param filename
	 * @throws IOException
	 */
	public void saveFile(byte[] data, String dir, String filename) throws IOException{
		File directory = new File(dir);
		if (!directory.exists()){
			directory.mkdir();
		}
		FileOutputStream out = new FileOutputStream(dir + "/" + filename);
		out.write(data);
		out.close();
	}
	/**
	 * send byte array via output stream
	 * @param output_stream
	 * @param data
	 * @throws IOException
	 */
	public void send(OutputStream output_stream, byte[] data) throws IOException{
		int data_length = data.length;
		DataOutputStream out_to_server = new DataOutputStream(output_stream);
		out_to_server.writeInt(data_length);
		out_to_server.write(data, 0, data_length);
		out_to_server.flush();
	}
	/**
	 * send string via output stream
	 * @param output_stream
	 * @param string
	 * @throws IOException
	 */
	public void send(OutputStream output_stream, String string) throws IOException{
		String s = string;
		byte[] data = s.getBytes();
		int data_length = data.length;
		DataOutputStream out_to_server = new DataOutputStream(output_stream);
		out_to_server.writeInt(data_length);
		out_to_server.write(data, 0, data_length);
		out_to_server.flush();
	}
	/**
	 * read from input stream
	 * @param input_stream
	 * @return
	 * @throws IOException
	 */
	public byte[] read(InputStream input_stream) throws IOException {
		DataInputStream in_from_host = new DataInputStream(input_stream);
		int data_length = in_from_host.readInt();
		byte[] data = new byte[data_length];
		in_from_host.read(data,0,data_length);
		return data;
	}
	/**
	 * encrypt a byte array with 8-char password
	 * @param input
	 * @param password
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] AES_encrypt(byte[] input, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		byte[] key = stringToKey(password);
		SecretKey sk = new SecretKeySpec(key, 0, key.length, "AES");
		Cipher cipherOut = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipherOut.init(Cipher.ENCRYPT_MODE, sk);
		byte[] encrypted = cipherOut.doFinal(input);
		byte[] iv = cipherOut.getIV();
		byte[] output = new byte[iv.length + encrypted.length];
		System.arraycopy(iv, 0, output, 0, iv.length);
		System.arraycopy(encrypted, 0, output, iv.length, encrypted.length);
		return output;
	}
	/**
	 * given input of ciphertext, key, IV as byte[]
	 * creates a cipher object
	 * creates a SecretKey object from key
	 * creates an IvParameterSpec object from iv
	 * decrypts ciphertext using key and iv
	 * @param input
	 * @param key
	 * @param initVector
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] AES_decrypt(byte[] input, byte[] key, byte[] initVector) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher myCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKey k = new SecretKeySpec(key, 0, key.length, "AES");
		IvParameterSpec iv = new IvParameterSpec(initVector);
		myCipher.init(Cipher.DECRYPT_MODE, k, iv);
		byte[] output = myCipher.doFinal(input);
		return output;
	}
	/**
	 * decrypts with AES but for a bytearray & string password
	 * @param input
	 * @param password
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] AES_decrypt(byte[] input, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] iv = new byte[16];
		System.arraycopy(input, 0, iv, 0, 16);
		int encrypted_length = input.length - 16;
		byte[] encrypted = new byte[encrypted_length];
		System.arraycopy(input, 16, encrypted, 0, encrypted_length);
		byte[] key = stringToKey(password);
		Cipher myCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKey k = new SecretKeySpec(key, 0, key.length, "AES");
		IvParameterSpec _iv = new IvParameterSpec(iv);
		myCipher.init(Cipher.DECRYPT_MODE, k, _iv);
		byte[] output = myCipher.doFinal(encrypted);
		return output;
	}
	/**
	 * converts 8-char password to a Long for seeding an RNG
	 * returns that 16-byte key
	 * @param s
	 * @return
	 */
	public byte[] stringToKey(String s){
		long hashcode = s.hashCode();
		byte[] b = new byte[16];
		Random r = new Random(hashcode);
		r.nextBytes(b);
		return b;
	}
	/**
	 * given input of plaintext as byte[], and a public key
	 * encrypts using RSA and returns ciphertext
	 * @param input
	 * @param publickey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] RSA_encrypt(byte[] input, PublicKey publickey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		Cipher cipherOut = Cipher.getInstance("RSA");
		cipherOut.init(Cipher.ENCRYPT_MODE, publickey);
		byte[] output = cipherOut.doFinal(input);
		return output;
	}
	/**
	 * given input of plaintext as byte[], and a private key
	 * encrypts using RSA and returns ciphertext
	 * @param input
	 * @param privatekey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] RSA_encrypt(byte[] input, PrivateKey privatekey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		Cipher cipherOut = Cipher.getInstance("RSA");
		cipherOut.init(Cipher.ENCRYPT_MODE, privatekey);
		byte[] output = cipherOut.doFinal(input);
		return output;
	}
	/**
	 * decrypts ciphertext using public key
	 * @param input
	 * @param publickey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] RSA_decrypt(byte[] input, PublicKey publickey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		Cipher cipherOut = Cipher.getInstance("RSA");
		cipherOut.init(Cipher.DECRYPT_MODE, publickey);
		byte[] output = cipherOut.doFinal(input);
		return output;
	}
	/**
	 * decrypts ciphertext using private key
	 * @param input
	 * @param privatekey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] RSA_decrypt(byte[] input, PrivateKey privatekey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		Cipher cipherOut = Cipher.getInstance("RSA");
		cipherOut.init(Cipher.DECRYPT_MODE, privatekey);
		byte[] output = cipherOut.doFinal(input);
		return output;
	}
	/**
	 * verify data against hash
	 * @param data
	 * @param sha
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public boolean verify(byte[] data, byte[] sha) throws NoSuchAlgorithmException{
		byte[] sha_data = SHA_256(data);
		if(Arrays.equals(sha_data, sha)) return true;
		else return false;
	}
	/**
	 * given input of plaintext as byte[], hashes using SHA-256
	 * @param input
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public byte[] SHA_256(byte[] input) throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(input);
		byte[] output = md.digest();
		return output;
	}
	/**
	 * loads a private key file
	 * @param keyfile
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public PrivateKey loadPrivate(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(loadFile(keyfile));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}
	/**
	 * loads a public key file
	 * @param keyfile
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public PublicKey loadPublic(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		X509EncodedKeySpec spec = new X509EncodedKeySpec(loadFile(keyfile));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
}
