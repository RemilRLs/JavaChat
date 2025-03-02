package client;

import java.io.*;
import opencard.core.service.*;
import opencard.core.terminal.*;
import opencard.core.util.*;
import opencard.opt.util.*;


import javax.crypto.Cipher;
import java.math.BigInteger;
import java.net.Socket;
import java.io.*;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.Security;
import java.util.Date;
import java.util.Random;
import java.util.Scanner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TheClient extends Thread {

	// ================= NETWORK COMMUNICATION =================
	private String serverHost = "localhost";
	private int serverPort = 1234;
	private Socket socket;
	private BufferedReader inputNetwork;
	private PrintStream outputNetwork;
	private BufferedReader inputConsole;
	private PrintStream outputConsole;
	private boolean running = true;
	private boolean authenticated = false;


	// ================= SMARTCARD COMMUNICATION =================
	private final static byte CLA_TEST						= (byte)0x90;
	private final static byte INS_GENERATE_RSA_KEY        = (byte)0xF6;
	private final static byte INS_GET_PUBLIC_RSA_KEY      = (byte)0xFE;
	private final static byte INS_RSA_ENCRYPT      		  	= (byte)0xA0;
	private final static byte INS_RSA_DECRYPT         		= (byte)0xA2;
	private final static byte P1_FF 						= (byte)0xFF;

	private final static byte ENCRYPT_FILE_DES = (byte)0x20;
	private final static byte DECRYPT_FILE_DES = (byte)0x21;

	private static final int CHUNK_SIZE = 120;



	private final static byte P1_EMPTY = (byte)0x00;
	private final static byte P2_EMPTY = (byte)0x00;

	private final int SIZE_CHALLENGE = 64;
	private final int DATASIZE = 64; // 64 bytes because for the RSA 512 bits


	private PassThruCardService servClient = null;
	boolean DISPLAY = true;

	private Cipher cRSA_NO_PAD;


	public static void main( String[] args ) throws InterruptedException {
		new TheClient();
	}


	public TheClient() {
		this.serverHost = System.getenv("SERVER_IP");
		this.serverPort = Integer.parseInt(System.getenv("SERVER_PORT"));

		if (serverHost == null) {
			serverHost = "localhost";
		}
		if (serverPort == 0) {
			serverPort = 5050;
		}

		System.out.println("[+] - Connecting to " + serverHost + ":" + serverPort);

		// Init network streams
		initStreams();

		// Init network (connexion between the client and the server)
		startNetwork();


		// Init smartcard (connexion between the client and the smartcard)
		initSmartCard();

		Thread readThread = new Thread(new ServerListener());
		readThread.start();

		listenConsole();


		//test();
		//foo();
	}

	/**
	 * Method to initialize the smartcard
	 */
	private void initSmartCard() {
		try {
			SmartCard.start();
			System.out.println("[+] - Waiting for a Smartcard...");

			CardRequest cr = new CardRequest (CardRequest.ANYCARD,null,null);
			SmartCard sm = SmartCard.waitForCard (cr);

			if(sm != null) {
				System.out.println("[+] - Smartcard inserted\n");
			} else {
				System.out.println("[X] - Did not get a Smartcard");
				System.exit(-1);
			}

			System.out.println("ATR: " + HexString.hexify(sm.getCardID().getATR()));

			try {
				this.servClient = (PassThruCardService)sm.getCardService(PassThruCardService.class, true);
			} catch( Exception e ) {
				System.out.println( e.getMessage() );
			}
			System.out.println("Applet selecting...");

			if( !this.selectApplet() ) {
				System.out.println( "[X] - Wrong card, no applet to select!\n" );
				System.exit( 1 );
			} else
				System.out.println("[+] - Applet successfully selected");
		} catch(Exception e) {
			System.out.println("[X] - Error while initializing Smartcard: " + e.getMessage());
			System.exit(-1);
		}
	}


	private ResponseAPDU sendAPDU(CommandAPDU cmd) {
		return sendAPDU(cmd, true);
	}

	private ResponseAPDU sendAPDU( CommandAPDU cmd, boolean display ) {
		ResponseAPDU result = null;
		try {
			result = this.servClient.sendCommandAPDU( cmd );
			if(display)
				displayAPDU(cmd, result);
		} catch( Exception e ) {
			System.out.println( "Exception caught in sendAPDU: " + e.getMessage() );
			java.lang.System.exit( -1 );
		}
		return result;
	}




	/************************************************
	 * *********** BEGINNING OF TOOLS ***************
	 * **********************************************/


	private String apdu2string( APDU apdu ) {
		return removeCR( HexString.hexify( apdu.getBytes() ) );
	}


	public void displayAPDU( APDU apdu ) {
		System.out.println( removeCR( HexString.hexify( apdu.getBytes() ) ) + "\n" );
	}


	public void displayAPDU( CommandAPDU termCmd, ResponseAPDU cardResp ) {
		System.out.println( "--> Term: " + removeCR( HexString.hexify( termCmd.getBytes() ) ) );
		System.out.println( "<-- Card: " + removeCR( HexString.hexify( cardResp.getBytes() ) ) );
	}


	private String removeCR( String string ) {
		return string.replace( '\n', ' ' );
	}

	/**
	 * Method to create an APDU command.
	 * @param data The data to send to the card.
	 * @param cla The class
	 * @param ins The instruction ID.
	 * @param p1 The parameter 1.
	 * @param p2 The parameter 2.
	 * @return The APDU command in bytes.
	 */
	public static byte[] createAPDUCommandByte(byte[] data, byte cla, byte ins, byte p1, byte p2) {
		int dataLength = data.length;
		byte[] apdu = new byte[5 + dataLength];

		apdu[0] = cla;
		apdu[1] = ins;
		apdu[2] = p1;
		apdu[3] = p2;
		apdu[4] = (byte) dataLength;
		System.arraycopy(data, 0, apdu, 5, dataLength);

		return apdu;
	}

	public static byte[] createAPDUCommand(String strData, byte cla, byte ins, byte p1, byte p2) {
		byte[] dataBytes = strData.getBytes();
		return createAPDUCommandByte(dataBytes, cla, ins, p1, p2);
	}
	/******************************************
	 * *********** END OF TOOLS ***************
	 * ****************************************/


	private boolean selectApplet() {
		boolean cardOk = false;
		try {
			CommandAPDU cmd = new CommandAPDU( new byte[] {
					(byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, (byte)0x0A,
					(byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x62,
					(byte)0x03, (byte)0x01, (byte)0x0C, (byte)0x06, (byte)0x01
			} );
			ResponseAPDU resp = this.sendAPDU( cmd );
			if( this.apdu2string( resp ).equals( "90 00" ) )
				cardOk = true;
		} catch(Exception e) {
			System.out.println( "Exception caught in selectApplet: " + e.getMessage() );
			java.lang.System.exit( -1 );
		}
		return cardOk;
	}

	private byte[] cipherRSA_ECB_NOPAD( byte[] challenge, boolean display ) {
		return cipherGeneric( INS_RSA_ENCRYPT, challenge );
	}


	private byte[] uncipherRSA_ECB_NOPAD( byte[] challenge, boolean display ) {
		return cipherGeneric( INS_RSA_DECRYPT, challenge );
	}

	/**
	 * Method to generate RSA keyy (I don't use it anymore in my code)
	 */
	private void generateRSAKeysFromApplet() {
		byte[] emptyData = new byte[0];

		byte[] apduBytes = createAPDUCommandByte(emptyData, CLA_TEST, INS_GENERATE_RSA_KEY, (byte)0x00, (byte)0x00);
		CommandAPDU cmd = new CommandAPDU(apduBytes);

		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);

		byte[] respBytes = resp.getBytes();
		int lengthWithSW = respBytes.length;
		int respLength = lengthWithSW - 2;
		int sw1 = respBytes[lengthWithSW - 2] & 0xFF;
		int sw2 = respBytes[lengthWithSW - 1] & 0xFF;

		if (sw1 == 0x90 && sw2 == 0x00) {
			System.out.println("[+] - RSA keys have been generated with success");
		} else {
			System.out.println("[X] - Error generating RSA keys. SW: " + Integer.toHexString(sw1) + " " + Integer.toHexString(sw2));
		}
	}

	/**
	 * Ciphergeneric method to cipher, uncipher data
	 * @param typeINS The instruction (cipher or uncipher)
	 * @param challenge The data to cipher or uncipher
	 * @return The result of the operation
	 */
	private byte[] cipherGeneric( byte typeINS, byte[] challenge ) {
		byte[] result = new byte[challenge.length];
		byte[] cmd_ = new byte[challenge.length +6];
		byte[] init = {CLA_TEST, typeINS, P1_FF, P2_EMPTY, (byte) challenge.length};
		System.arraycopy(init, 0, cmd_, 0, init.length);
		System.arraycopy(challenge, (byte)0, cmd_, (byte) 5, (byte)challenge.length);
		cmd_[cmd_.length-1] = (byte) (challenge.length);
		CommandAPDU cmd = new CommandAPDU(cmd_);
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);
		byte[] resp_bytes = resp.getBytes();
		System.out.println( "Response length : " + resp_bytes.length);
		System.arraycopy(resp_bytes, (byte) 0, result, (byte)0, (byte) challenge.length);

		return result;
	}

	/**
	 * Method to get the modulus (I combine that function with getExponent)
	 * @return The modulus
	 */
	private byte[] getModulus() {
		CommandAPDU cmd = new CommandAPDU(new byte[] { (byte)0x90, (byte)0xFE, (byte)0x00, (byte)0x00, (byte)0x00 });
		ResponseAPDU resp = sendAPDU(cmd);
		byte[] response = resp.getBytes();

		int length = response[0] & 0xFF;
		System.out.println("Modulus length from card: " + length);

		byte[] modulus = new byte[length];
		System.arraycopy(response, 1, modulus, 0, length);
		return modulus;
	}

	/**
	 * Method to get the exponent (to construct the public key)
	 * @return The exponent
	 */
	private byte[] getExponent() {

		CommandAPDU cmd = new CommandAPDU(new byte[] { (byte)0x90, (byte)0xFE, (byte)0x00, (byte)0x01, (byte)0x00 });
		ResponseAPDU resp = sendAPDU(cmd);
		byte[] response = resp.getBytes();

		int length = response[0] & 0xFF;
		byte[] exponent = new byte[length];
		System.arraycopy(response, 1, exponent, 0, length);
		return exponent;
	}

	/**
	 * Method to transform a byte array into a string
	 * @param bytes The byte array
	 * @return The string
	 */
	private String bytetoString(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X ", b));
		}
		return sb.toString();
	}


	// ================= FILE SENDING =================

	/**
	 * Method to send a file to a user (close to my function in my project CryptoFile)
	 * @param filePath The path of the file
	 * @param targetUser The user to send the file
	 */

	private void sendFileC(String filePath, String targetUser) {
		File file = new File(filePath);
		if (!file.exists() || !file.isFile()) {
			outputConsole.println("[X] - Error: File does not exist");
			return;
		}

		outputConsole.println("[+] - Preparing for sending file: " + filePath + " for user: " + targetUser);
		sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();

		FileInputStream fileInputStream = null;
		ByteArrayOutputStream encryptedFileStream = null;

		try {
			String encodedFilename = removeNewLines(encoder.encode(file.getName().getBytes()));

			fileInputStream = new FileInputStream(file);
			encryptedFileStream = new ByteArrayOutputStream();


			byte[] bufferIn = new byte[CHUNK_SIZE];
			int contentLen;

			while ((contentLen = fileInputStream.read(bufferIn)) != -1) {
				byte[] dataToSend = new byte[contentLen];
				System.arraycopy(bufferIn, 0, dataToSend, 0, contentLen);


				if (fileInputStream.available() == 0) {
					dataToSend = addPadding(dataToSend, 8);
				}

				byte[] encryptedData = cipherGenericDES(ENCRYPT_FILE_DES, dataToSend);

				if (encryptedData != null && encryptedData.length > 0) {
					encryptedFileStream.write(encryptedData);
				} else {
					outputConsole.println("[X] - Error during encryption of file");
					fileInputStream.close();
					return;
				}
			}

			fileInputStream.close();

			byte[] encryptedFileBytes = encryptedFileStream.toByteArray();
			String encodedContent = removeNewLines(encoder.encode(encryptedFileBytes));

			String message = "/msgTo " + targetUser + " /FILEC|" + encodedFilename + "|" + encodedContent;

			sendServer(message);
			outputConsole.println("[+] - Encrypted file sent successfully");

		} catch (IOException e) {
			outputConsole.println("[X] - Error sending encrypted file: " + e.getMessage());
		}
	}

	/**
	 * Method to encrypt a message for a heavy client withn DES encryption
	 * That the same as my project 'CryptoFile' (almost)
	 * @param plainMessage The message to cipher
	 * @return The encrypted message
	 */
	private String encryptMessage(String plainMessage) {
		try {

			byte[] messageBytes = plainMessage.getBytes("UTF-8");

			ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream();

			int offset = 0;

			while (offset < messageBytes.length) {
				int remaining = messageBytes.length - offset;
				int chunkSize = Math.min(CHUNK_SIZE, remaining);

				byte[] chunk = new byte[chunkSize];
				System.arraycopy(messageBytes, offset, chunk, 0, chunkSize);
				offset += chunkSize;

				// That my last block so I have to add some padding
				if (offset >= messageBytes.length) {
					chunk = addPadding(chunk, 8);
				}

				// For encryption
				byte[] encryptedChunk = cipherGenericDES(ENCRYPT_FILE_DES, chunk);
				if (encryptedChunk == null) {
					outputConsole.println("[X] - Cannot encrypt the chunk");
					return null;
				}
				encryptedStream.write(encryptedChunk);
			}
			byte[] encryptedData = encryptedStream.toByteArray();

			// I don't know why but sun.misc Base64 add some /n and /r so I remove it because it's so buggy
			String encryptedBase64 = new sun.misc.BASE64Encoder().encode(encryptedData).replace("\n", "").replace("\r", "");

			return encryptedBase64;
		} catch (Exception e) {
			outputConsole.println("[X] - Error encrypting message: " + e.getMessage());
			return null;
		}
	}

	/**
	 * Same as the previous method but for the decryption
	 * @param encryptedMessage The message to decrypt
	 * @return The decrypted message
	 */
	private String decryptMessage(String encryptedMessage) {
		try {
			byte[] encryptedData = new sun.misc.BASE64Decoder().decodeBuffer(encryptedMessage);

			ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
			int offset = 0;

			byte[] decryptedChunk = null;

			while (offset < encryptedData.length) {
				int remaining = encryptedData.length - offset;
				int chunkSize = Math.min(CHUNK_SIZE, remaining);
				byte[] chunk = new byte[chunkSize];
				System.arraycopy(encryptedData, offset, chunk, 0, chunkSize);
				offset += chunkSize;


				decryptedChunk = cipherGenericDES(DECRYPT_FILE_DES, chunk);
				if (decryptedChunk == null) {
					outputConsole.println("[X] - Cannot decrypt the chunk");
					return null;
				}

				// Last block so I remove the padding
				if (offset >= encryptedData.length) {
					decryptedChunk = removePadding(decryptedChunk);
					if (decryptedChunk == null) {
						outputConsole.println("[X] - Invalid padding (on the last block)");
						return null;
					}
				}

				decryptedStream.write(decryptedChunk);
			}

			byte[] decryptedBytes = decryptedStream.toByteArray();

			return new String(decryptedBytes, "UTF-8");

		} catch (Exception e) {
			outputConsole.println("[X] - Error decrypting message: " + e.getMessage());
			return null;
		}
	}


	/**
	 * Ciphergeneric for DES (file and message)
	 * @param typeINS The instruction (cipher or uncipher)
	 * @param data The data to cipher or uncipher
	 * @return The result
	 */
	private byte[] cipherGenericDES(byte typeINS, byte[] data) {

		int lc = data.length;
		int le = data.length;


		// I do differently as my previous project 'CryptoFile' because I had status code 0x61 XX (GET RESPONSE)
		// But now I specify the Le in the APDU command
		// TODO : Make a method for that
		byte[] apdu = new byte[6 + lc];
		apdu[0] = CLA_TEST;
		apdu[1] = typeINS;
		apdu[2] = P1_EMPTY;
		apdu[3] = P2_EMPTY;
		apdu[4] = (byte) lc;
		System.arraycopy(data, 0, apdu, 5, lc);
		apdu[5 + lc] = (byte) le;

		CommandAPDU cmd = new CommandAPDU(apdu);
		ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);
		byte[] respBytes = resp.getBytes();


		// I extract the data from the response (without the SW1 and SW2)
		int len = respBytes.length - 2;


		byte[] result = new byte[len];
		System.arraycopy(respBytes, 0, result, 0, len);

		short sw1 = (short) (respBytes[respBytes.length - 2] & 0xFF);
		short sw2 = (short) (respBytes[respBytes.length - 1] & 0xFF);


		if (sw1 != 0x90 || sw2 != 0x00) {
			System.out.println("[X] Error during DES operation. SW=" + Integer.toHexString(sw1) + " " + Integer.toHexString(sw2));

			return null;
		}

		System.out.println("Encrypted block size: " + result.length);
		return result;
	}




	/**
	 * Add padding to the last block
	 * I use PKCS#7 padding in my case
	 * @param data The data to pad
	 * @param blockSize The block size
	 * @return The padded data
	 */
	byte[] addPadding(byte[] data, int blockSize) {
		// Here I calculate the number of bytes that I have to add to the last block
		int paddingSize = blockSize - (data.length % blockSize);

		/**
		 if (paddingSize == 0) { // Perfect multiple
		 paddingSize = blockSize;
		 }
		 */

		byte[] paddedData = new byte[data.length + paddingSize];
		System.arraycopy(data, 0, paddedData, 0, data.length);

		for (int i = data.length; i < paddedData.length; i++) {
			paddedData[i] = (byte) paddingSize;
		}
		return paddedData;
	}

	/**
	 * Remove padding from the last block
	 * @param data The data to depad
	 * @return The unpadded data
	 */
	private byte[] removePadding(byte[] data) {
		if (data.length == 0) {
			return null;
		}

		// Here I get the padding size
		int padSize = data[data.length - 1] & 0xFF;

		// I check if the padding is valid (between 1 and 8 bytes)
		if (padSize < 1 || padSize > 8 || padSize > data.length) {
			return null;
		}

		for (int i = 0; i < padSize; i++) {
			if (data[data.length - 1 - i] != (byte) padSize) {
				return null;
			}
		}


		// I create my data without the padding
		int newLength = data.length - padSize;
		byte[] unpaddedData = new byte[newLength];
		System.arraycopy(data, 0, unpaddedData, 0, newLength);

		return unpaddedData;
	}

	/**
	 * I use this because the sun.misc.Base64Encoder add some /n and /r
	 */
	private String removeNewLines(String base64) {
		return base64.replace("\n", "").replace("\r", "");
	}


	/**
	 * Method that get the challenge and decrypt it
	 * @param challenge64 The challenge in Base64
	 */
	public void handleChallenge(String challenge64) {
		try {
			sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
			sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();

			byte[] challengeCiphered = decoder.decodeBuffer(challenge64);
			System.out.println("[+] - Receive challenge : " + removeNewLines(encoder.encode(challengeCiphered)));

			// I decrypt the challenge with my private key
			byte[] uncipheredChallengeCard = cipherGeneric(INS_RSA_DECRYPT, challengeCiphered);

			if (uncipheredChallengeCard == null) {
				System.out.println("[X] - Error: Cannot decrypt the challenge");
				return;
			}

			System.out.println("[+] - Challenge uncipher : " + removeNewLines(encoder.encode(uncipheredChallengeCard)));

			String responseChallenge = removeNewLines(encoder.encode(uncipheredChallengeCard));

			// I send the response to the server
			sendServer("/challengeResponse " + responseChallenge);
			System.out.println("[+] - Challenge response sent to server: " + responseChallenge);

		} catch (IOException e) {
			System.err.println("Error while handling challenge: " + e.getMessage());
		}
	}

	/**
	 * Function to handle when I receive an encrypted message
	 * @param commandEncryptedMessage The message encrypted
	 */
	private void handleEncryptedIncomingMessage(String commandEncryptedMessage) {
		String[] parts = commandEncryptedMessage.split(" ", 4); // Max 4 parts (/C, sender, type (like private) , messageCipherB64)

		if(parts.length < 3) {
			outputConsole.println("[X] - Invalid encrypted message found...");
		}

		String sender = parts[1];

		if(parts.length == 4 && parts[2].equals("(private)")) { // /C <sender> (private) <message>
			String encryptedMessageBase64 = parts[3];
			String decryptedMessage = decryptMessage(encryptedMessageBase64);

			if(decryptedMessage != null) {
				outputConsole.println("[Private] <" + sender + ">: " + decryptedMessage);
			} else {
				outputConsole.println("[X] - Wrong format");
			}
		} else { // /C <sender> <message>
			String encryptedMessageBase64 = parts[2];
			String decryptedMessage = decryptMessage(encryptedMessageBase64);

			if(decryptedMessage != null) {
				outputConsole.println("<" + sender + ">: " + decryptedMessage);
			} else {
				outputConsole.println("[X] - Wrong format");
			}
		}
	}


	// ================= NETWORK =================

	/**
	 * Method InitStream to initialize stream (user and server
	 */
	private void initStreams() {
		try {
			socket = new Socket(serverHost, serverPort);
			inputNetwork = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			outputNetwork = new PrintStream(socket.getOutputStream());
			inputConsole = new BufferedReader(new InputStreamReader(System.in));
			outputConsole = System.out;
			outputConsole.println("[+] - Connected to " + serverHost + ":" + serverPort);
		} catch (IOException e) {
			System.err.println("[X] - Network init error: " + e.getMessage());
			System.exit(-1);
		}
	}

	/**
	 * Start network and send magic number to confirm that the client is a heavy client
	 */
	void startNetwork() {
		try {
			String serverMessage = inputNetwork.readLine();
			outputConsole.println(serverMessage);

			sendMagic();

		} catch (IOException e) {
			System.err.println("[X] - Network error: " + e.getMessage());
			System.exit(-1);
		}
	}

	private class ServerListener implements Runnable {
		@Override
		public void run() {
			listenNetwork();
		}
	}

	/**
	 * Method to listen what the server send to us
	 * I handle the different type of message
	 */
	private void listenNetwork() {
		try {
			String line;
			while ((line = inputNetwork.readLine()) != null) {
				outputConsole.println(line);

				if (!authenticated && line.contains("[+] - Welcome ")) {
					authenticated = true;
					System.out.println("[+] - Authenticated");
					continue;
				}

				if (line.contains("Please provide your RSA public key in Base64")) {
					sendPublicKey();
				}

				if(line.startsWith("/challenge")) {
					String[] parts = line.split(" ");
					byte[] challenge = new sun.misc.BASE64Decoder().decodeBuffer(parts[1]);
					System.out.println("[+] - Challenge received from server: " + new sun.misc.BASE64Encoder().encode(challenge));

					handleChallenge(parts[1]);
				}

				if (line.contains("/FILEC|")) {
					handleIncomingFile(line);
					continue;
				}

				if (line.startsWith("/C ")) {
					handleEncryptedIncomingMessage(line);
					continue;
				}
			}
		} catch (IOException e) {
			System.err.println("[X] - Error reading from server: " + e.getMessage());
			running = false;
		}
	}

	/**
	 * Send the pubkey to the server (for registration)
	 * I get the modulus and the exponent from the card
	 */
	private void sendPublicKey() {
		try {
			outputConsole.println("[+] - Retrieving public key from smartcard...");
			sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();


			byte[] modulus = getModulus();
			byte[] exponent = getExponent();

			if (modulus == null || exponent == null) {
				outputConsole.println("[X] - Cannot get pubkey");
				return;
			}

			String modulusB64 = encoder.encode(modulus).replace("\n", "").replace("\r", "");
			String exponentB64 = encoder.encode(exponent).replace("\n", "").replace("\r", "");


			String formattedMessage = "/sendPublicKey " + modulusB64 + " " + exponentB64;

			sendServer(formattedMessage);
			outputConsole.println("[+] - Public key sent to server");

		} catch (Exception e) {
			outputConsole.println("[X] - Error sending public key: " + e.getMessage());
		}
	}

	/**
	 * Listen what the user type in the console
	 */
	private void listenConsole() {
		try {
			String userInput;
			boolean shouldQuit = false;

			while (running && (userInput = inputConsole.readLine()) != null) {
				userInput = userInput.trim();

				if (userInput.isEmpty()) {
					continue;
				}

				if(userInput.startsWith("/")) {
					shouldQuit = parseCommand(userInput);
				} else if (authenticated) { // Not a command (message)
					String encryptedMessage = encryptMessage(userInput);
					if (encryptedMessage != null) {
						sendServer("/sendAllC " + encryptedMessage);
						System.out.println("[+] - Encrypted message sent to server");
					} else {
						outputConsole.println("[X] - Error: Cannot encrypt message");
					}
				} else {
					sendServer(userInput);
				}

				if (shouldQuit) {
					break;
				}
			}
		} catch (IOException e) {
			System.err.println("[X] - Console error: " + e.getMessage());
		}
	}

	/**
	 * Function to parse command of the user so begin with '/'
	 * @param command The command
	 * @return True if the user want to quit
	 */
	boolean parseCommand(String command) throws IOException {
		if (command.equalsIgnoreCase("/quit")) {
			outputNetwork.println("/quit");
			outputConsole.println("[*] - You left the chat, goodbye :(");

			try {
				socket.close();
				System.out.println("[+] - Socket has been closed");
			} catch (IOException e) {
				System.err.println("[X] - Error closing socket: " + e.getMessage());
			}
			return true;
		}

		String[] parts = command.split("\\s+", 3);
		String mainCommand = parts[0].toLowerCase();

		if (mainCommand.equals("/sendallc")) {  // Send to everyone a message in cipher (so light client can't read it)
			if (parts.length < 2) {
				outputConsole.println("[X] - Usage: /sendAllC <message>");
			} else if (authenticated) {
				String encryptedMessage = encryptMessage(parts[1]);
				if (encryptedMessage != null) {
					sendServer("/sendAllC " + encryptedMessage);
					System.out.println("[+] - Encrypted message sent to server");
				} else {
					outputConsole.println("[X] - Error: Encryption failed");
				}
			}
		}

		else if (mainCommand.equals("/msgto")) {  // Private message cipher
			if (parts.length < 3) {
				outputConsole.println("[X] - Usage: /msgTo <username> <message>");
			} else if (authenticated) {
				String targetUser = parts[1];
				String privateMessage = parts[2];
				String encryptedMessage = encryptMessage(privateMessage);
				if (encryptedMessage != null) {
					sendServer("/msgTo " + targetUser + " " + encryptedMessage);
					System.out.println("[+] - Encrypted private message sent");
				} else {
					outputConsole.println("[X] - Error: Encryption failed");
				}
			} else {
				sendServer(command);
			}
		}

		else if (mainCommand.equals("/sendfilec")) {  // Encrypted file sending
			if (parts.length < 3) {
				outputConsole.println("[X] - Usage: /sendFileC <file> <user>");
			} else {
				String filePath = parts[1];
				String targetUser = parts[2];
				sendFileC(filePath, targetUser);
			}
		}

		else if (mainCommand.equals("/list") || mainCommand.equals("/help")) {
			sendServer(command);
		}

		else if (mainCommand.equals("/msgall")) {
			if (parts.length < 2) {
				outputConsole.println("[X] - Usage: /msgAll <message>");
			} else {
				sendServer(command);
			}
		}

		else {
			outputConsole.println("[X] - Unknown command: " + mainCommand);
			return false;
		}

		return false;
	}


	/**
	 * Function to handle file incoming from the server
	 * @param line The message that contains the file name and the content
	 */
	private void handleIncomingFile(String line) {
		try {
			sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
			String[] parts = line.split("\\|");

			if (parts.length < 3) {
				outputConsole.println("[X] - Error: Invalid file message format");
				return;
			}

			String encodedFilename = removeNewLines(parts[1]);
			String encodedContent = removeNewLines(parts[2]);


			String decodedFilename = new String(decoder.decodeBuffer(encodedFilename));

			outputConsole.println("[+] - Receiving file: " + decodedFilename);

			byte[] encryptedFile = decoder.decodeBuffer(encodedContent);


			String encryptedFilePath = "encrypted_" + decodedFilename;
			FileOutputStream fileOutputStream = new FileOutputStream(encryptedFilePath);
			fileOutputStream.write(encryptedFile);
			outputConsole.println("[+] - Encrypted file saved as: " + encryptedFilePath);

			fileOutputStream.close();

			decryptFile(encryptedFilePath, "decrypted_" + decodedFilename);


		} catch (IOException e) {
			outputConsole.println("[X] - Error while handling incoming file: " + e.getMessage());
		}
	}

	/**
	 * file decryption
	 * @param inputFilePath The path of the encrypted file
	 * @param outputFilePath The path of the decrypted file
	 */
	private void decryptFile(String inputFilePath, String outputFilePath) {
		FileInputStream fileInStream = null;
		FileOutputStream fileOutStream = null;
		try {
			fileInStream = new FileInputStream(inputFilePath);
			fileOutStream = new FileOutputStream(outputFilePath);

			byte[] bufferIn = new byte[CHUNK_SIZE];
			int contentLen;

			while ((contentLen = fileInStream.read(bufferIn)) != -1) {

				byte[] dataToDecrypt = new byte[contentLen];
				System.arraycopy(bufferIn, 0, dataToDecrypt, 0, contentLen);
				System.out.println("Size of data to decrypt: " + dataToDecrypt.length);

				// I decrypt each block
				byte[] decryptedBlock = cipherGeneric(DECRYPT_FILE_DES, dataToDecrypt);
				if (decryptedBlock == null) {
					System.out.println("[X] Error: Cannot decrypt file block");
					return;
				}

				// I remove the last block padding
				if (fileInStream.available() == 0) {
					byte[] unpaddedBlock = removePadding(decryptedBlock);
					if (unpaddedBlock == null) {
						System.out.println("[X] Error: Cannot remove padding from the last block");
						return;
					}
					fileOutStream.write(unpaddedBlock);
				} else {
					fileOutStream.write(decryptedBlock);
				}
			}

			System.out.println("[+] Decryption done. Output file: " + outputFilePath);
		} catch (IOException e) {
			System.out.println("[X] IO Error: " + e.getMessage());
		}
	}

	/**
	 * To send something to the server
	 * @param message The message to send serv
	 */
	private void sendServer(String message) {
		outputNetwork.println(message);
	}

	/**
	 * To authentify the client as a heavy
	 */
	void sendMagic() {
		try {
			Thread.sleep(500);
			outputNetwork.println("TVRVeElEUXdJREUxTkNBeE5UY2dNVFkySURFME5TQTBNQ0F4TlRJZ01UUXhJREUyTmlBeE5ERT0=");
		} catch (Exception e) {
			System.err.println("[X] - Network error: " + e.getMessage());
			System.exit(-1);
		}
	}
}
