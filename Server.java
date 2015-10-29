/**
 * @author Cecilia Watt
 */
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.io.*;

import javax.net.ssl.*;

public class Server extends EncryptedHost{
	private SSLServerSocket sslserversocket;
	static char ksPass[] = "123456".toCharArray();
	static char ctPass[] = "123456".toCharArray();
	byte[] PUT = "PUT".getBytes();
	byte[] GET = "GET".getBytes();
	byte[] STOP = "STOP".getBytes();

	public Server(SSLServerSocketFactory ssf, int port) throws IOException{
		sslserversocket = (SSLServerSocket) ssf.createServerSocket(port);
		sslserversocket.setNeedClientAuth(true);
	}

	public void run(){
		while(true){
			System.out.print(".");
			try{
				SSLSocket server = (SSLSocket) sslserversocket.accept();
				byte[] bluh = read(server.getInputStream());
				if (Arrays.equals(bluh, PUT)){
					save(server);
				}
				else if (Arrays.equals(bluh, GET)){
					process_request(server);
				}
				else if (Arrays.equals(bluh, STOP)){
					break;
				}

				server.close();
			} catch (IOException e) {
				e.printStackTrace();
			} 
		}
	}

	/**
	 * Try to save the file and send a failure/success notification
	 * @param server
	 * @throws IOException
	 */
	public void save(SSLSocket server) throws IOException{
		try{
			byte[] filename = read(server.getInputStream());
			String s = new String(filename);
			byte[] data = read(server.getInputStream());
			saveFile(data, "server", s);
			byte[] sha = read(server.getInputStream());
			saveFile(sha, "server", s + ".sha");
			send(server.getOutputStream(), "OK");
		}
		catch (IOException e){
			send(server.getOutputStream(), "NOK");
		}
	}

	/**
	 * Process a "get" request
	 * @param server
	 * @throws IOException
	 */
	public void process_request(SSLSocket server) throws IOException{
		byte[] filename = read(server.getInputStream());
		String s = new String(filename);
		byte[] file = null;
		byte[] sha = null;
		boolean success = true;
		try{
			file = loadFile("server/" + s);
			sha = loadFile("server/" + s + ".sha");
		} catch (IOException e){
			success = false;
		}
		finally{
			if (success){
				send(server.getOutputStream(), "OK");
				send(server.getOutputStream(), file);
				send(server.getOutputStream(), sha);
			}
			else{
				send(server.getOutputStream(), "NOK");
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
		if (args.length < 1){
			System.out.println("Did not supply port number.");
			return false;
		}
		if (!args[0].matches("[0-9]+")){
			System.out.println("Invalid port number");
			return false;
		}
		return isValid;
	}

	public static void main(String [] args){
		//set things
		System.setProperty("javax.net.ssl.trustStore", "server_truststore.ts");

		//check that arguments are valid
		if (!checkArgs(args)) return;

		//prepare to listen
		try{
			KeyStore myKeyStore = KeyStore.getInstance("JKS");
			myKeyStore.load(new FileInputStream("server_keystore.jks"), ksPass);

			KeyManagerFactory myKMF = KeyManagerFactory.getInstance("SunX509");
			myKMF.init(myKeyStore, ctPass);

			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(myKMF.getKeyManagers(), null, null);

			SSLServerSocketFactory ssf = sc.getServerSocketFactory();
			int port = Integer.parseInt(args[0]);
			Thread t = new Server(ssf, port);
			t.start();

		}catch(IOException e){
			System.out.println("The server's keystore was not loaded.");
		} catch (KeyStoreException e) {
			System.out.println("TLS error.");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("TLS error.");
		} catch (CertificateException e) {
			System.out.println("TLS error.");
		} catch (UnrecoverableKeyException e) {
			System.out.println("TLS error.");
		} catch (KeyManagementException e) {
			System.out.println("TLS error.");
		}
	}
}
