package applet;




import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;




public class TheApplet extends Applet {


	private final static byte CLA_TEST                    = (byte)0x90;
	private final static byte INS_GENERATE_RSA_KEY        = (byte)0xF6;
	private final static byte INS_RSA_ENCRYPT             = (byte)0xA0;
	private final static byte INS_RSA_DECRYPT             = (byte)0xA2;
	private final static byte INS_GET_PUBLIC_RSA_KEY      = (byte)0xFE;
	private final static byte INS_PUT_PUBLIC_RSA_KEY      = (byte)0xF4;

	private final static byte ENCRYPT_FILE_DES			  = (byte)0x20;
	private final static byte DECRYPT_FILE_DES            = (byte)0x21;


	// cipher instances
	private Cipher cRSA_NO_PAD;
	// key objects
	private KeyPair keyPair;
	private Key publicRSAKey, privateRSAKey;

	// cipher key length
	private short cipherRSAKeyLength;

	private Key secretDESKey, secretDES2Key, secretDES3Key;

	static final byte[] theDESKey =
			new byte[] { (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA };


	// RSA Keys section

	// n = modulus

	static final byte[] n = new byte[] {
			(byte) 0xD7 ,(byte) 0x9B ,(byte) 0x99 ,(byte) 0x29 ,(byte) 0x84 ,(byte) 0xB3 ,(byte) 0x5A ,(byte) 0x32 ,(byte) 0xB0 ,(byte) 0x33 ,(byte) 0x3E ,(byte) 0x82 ,(byte) 0x1E ,(byte) 0x3E ,(byte) 0x25 ,(byte) 0x8A ,(byte) 0xA4 ,(byte) 0xF1 ,(byte) 0x19 ,(byte) 0x08 ,(byte) 0xB8 ,(byte) 0x21 ,(byte) 0x7E ,(byte) 0xA7 ,(byte) 0xF6 ,(byte) 0x14 ,(byte) 0x8F ,(byte) 0x09 ,(byte) 0x61 ,(byte) 0x18 ,(byte) 0x03 ,(byte) 0x42 ,(byte) 0x33 ,(byte) 0xC1 ,(byte) 0xE8 ,(byte) 0xE5 ,(byte) 0x5F ,(byte) 0x2E ,(byte) 0x8B ,(byte) 0x0A ,(byte) 0x3E ,(byte) 0xA1 ,(byte) 0xEB ,(byte) 0xA6 ,(byte) 0x85 ,(byte) 0xC6 ,(byte) 0x05 ,(byte) 0xEA ,(byte) 0x5E ,(byte) 0x2F ,(byte) 0x48 ,(byte) 0x5B ,(byte) 0x41 ,(byte) 0xEB ,(byte) 0xAB ,(byte) 0x4A ,(byte) 0x81 ,(byte) 0x91 ,(byte) 0x2F ,(byte) 0x15 ,(byte) 0x96 ,(byte) 0xEF ,(byte) 0xFD ,(byte) 0x39
	};

	// e = public exponent
	static final byte[] e = new byte[] {
			(byte)0x01,(byte)0x00,(byte)0x01
	};

	// d = private exponent
	static final byte[] d = new byte[] {
			(byte) 0x00 ,(byte) 0xCF ,(byte) 0xDF ,(byte) 0x92 ,(byte) 0xF1 ,(byte) 0xF6 ,(byte) 0xA1 ,(byte) 0x3D ,(byte) 0x2B ,(byte) 0x75 ,(byte) 0xBA ,(byte) 0x52 ,(byte) 0x5F ,(byte) 0xFD ,(byte) 0x6C ,(byte) 0x89 ,(byte) 0xA1 ,(byte) 0x7C ,(byte) 0x99 ,(byte) 0x7F ,(byte) 0x3B ,(byte) 0x6A ,(byte) 0xDB ,(byte) 0xD0 ,(byte) 0x53 ,(byte) 0x7B ,(byte) 0xEC ,(byte) 0x22 ,(byte) 0x64 ,(byte) 0x36 ,(byte) 0x9A ,(byte) 0x82 ,(byte) 0x38 ,(byte) 0x01 ,(byte) 0x57 ,(byte) 0xD9 ,(byte) 0x14 ,(byte) 0x76 ,(byte) 0xCE ,(byte) 0xDC ,(byte) 0x65 ,(byte) 0xBE ,(byte) 0x59 ,(byte) 0xB5 ,(byte) 0xF4 ,(byte) 0x46 ,(byte) 0x4C ,(byte) 0x1D ,(byte) 0x33 ,(byte) 0x90 ,(byte) 0x5B ,(byte) 0xCF ,(byte) 0x58 ,(byte) 0x7C ,(byte) 0xA5 ,(byte) 0x58 ,(byte) 0xD6 ,(byte) 0x4E ,(byte) 0x73 ,(byte) 0x01 ,(byte) 0x21 ,(byte) 0xF3 ,(byte) 0xF9 ,(byte) 0xAE ,(byte) 0x01
	};

	boolean
			pseudoRandom, secureRandom,
			SHA1, MD5, RIPEMD160,
			keyDES, DES_ECB_NOPAD, DES_CBC_NOPAD;

	private Cipher
			cDES_ECB_NOPAD_enc, cDES_ECB_NOPAD_dec;

	protected TheApplet() {

		// For DES

		initKeyDES();
		initDES_ECB_NOPAD();

		// For RSA

		publicRSAKey = privateRSAKey = null;
		cRSA_NO_PAD = null;

		cipherRSAKeyLength = KeyBuilder.LENGTH_RSA_512;
		// build RSA pattern keys
		publicRSAKey = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, cipherRSAKeyLength, true);
		privateRSAKey = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, cipherRSAKeyLength, false);
		// initialize RSA public key
		((RSAPublicKey) publicRSAKey).setModulus(n, (short) 0, (short) (cipherRSAKeyLength / 8));
		((RSAPublicKey) publicRSAKey).setExponent(e, (short) 0, (short) e.length);
		// initialize RSA private key
		((RSAPrivateKey) privateRSAKey).setModulus(n, (short) 0, (short) (cipherRSAKeyLength / 8));
		((RSAPrivateKey) privateRSAKey).setExponent(d, (short) 0, (short) (cipherRSAKeyLength / 8));
		// get cipher RSA instance
		cRSA_NO_PAD = Cipher.getInstance((byte) 0x0C, false);

		keyPair = new KeyPair(KeyPair.ALG_RSA, (short) publicRSAKey.getSize());
		keyPair.genKeyPair();
		publicRSAKey = keyPair.getPublic();
		privateRSAKey = keyPair.getPrivate();

		register();

	}


	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		new TheApplet();
	}


	public void process(APDU apdu) throws ISOException {
		if (selectingApplet())
			return ;

		byte[] buffer = apdu.getBuffer();

		if (buffer[ISO7816.OFFSET_CLA] != CLA_TEST)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		switch (buffer[ISO7816.OFFSET_INS]) {
			case INS_GENERATE_RSA_KEY:
				generateRSAKey();
				break;

			case INS_RSA_ENCRYPT:
				RSAEncrypt(apdu);
				break;

			case INS_RSA_DECRYPT:
				RSADecrypt(apdu);
				break;

			case INS_GET_PUBLIC_RSA_KEY:
				getPublicRSAKey(apdu);
				break;

			case INS_PUT_PUBLIC_RSA_KEY:
				putPublicRSAKey(apdu);
				break;

			case ENCRYPT_FILE_DES:
				cipherGeneric(apdu, cDES_ECB_NOPAD_enc, KeyBuilder.LENGTH_DES);
				break;

			case DECRYPT_FILE_DES:
				cipherGeneric(apdu, cDES_ECB_NOPAD_dec, KeyBuilder.LENGTH_DES);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}

	}


	private void initKeyDES() {
		try {
			secretDESKey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
			((DESKey) secretDESKey).setKey(theDESKey, (short) 0);
			keyDES = true;
		} catch (Exception e) {
			keyDES = false;
		}
	}

	private void initDES_ECB_NOPAD() {
		if (keyDES)
			try {
				cDES_ECB_NOPAD_enc = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
				cDES_ECB_NOPAD_dec = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
				cDES_ECB_NOPAD_enc.init(secretDESKey, Cipher.MODE_ENCRYPT);
				cDES_ECB_NOPAD_dec.init(secretDESKey, Cipher.MODE_DECRYPT);
				DES_ECB_NOPAD = true;
			} catch (Exception e) {
				DES_ECB_NOPAD = false;
			}
	}

	void generateRSAKey() {
		keyPair = new KeyPair(KeyPair.ALG_RSA, (short)publicRSAKey.getSize());
		keyPair.genKeyPair();
		publicRSAKey = keyPair.getPublic();
		privateRSAKey = keyPair.getPrivate();
	}

	// RSA Encrypt (with public key)
	void RSAEncrypt(APDU apdu) {
		byte[] buffer = apdu.getBuffer();

		short sizeData = apdu.setIncomingAndReceive(); // I get the length of the data that the user send me.
		// initialize the algorithm with default key
		cRSA_NO_PAD.init(publicRSAKey, Cipher.MODE_ENCRYPT);
		// compute internel test
		//short sizeAfterCipher = cRSA_NO_PAD.doFinal(inC, (short)0, (short)(cipherRSAKeyLength/8), buffer, (short)1); Last one

		// I cipher the data
		short sizeAfterCipher = cRSA_NO_PAD.doFinal(
				buffer,
				ISO7816.OFFSET_CDATA,
				sizeData,
				buffer,
				(short)0
		);

		// compare result with the patern
		//buffer[0] = Util.arrayCompare(buffer, (short)1, cRSAPublicEncResult, (short)0, (short)(cipherRSAKeyLength/8));
		// send difference
		//apdu.setOutgoingAndSend((short)0, (short)1);

		apdu.setOutgoingAndSend((short)0, sizeAfterCipher);
	}


	// RSA Decrypt (with private key)
	void RSADecrypt(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short sizeData = apdu.setIncomingAndReceive();
		// initialize the algorithm with default key
		cRSA_NO_PAD.init( privateRSAKey, Cipher.MODE_DECRYPT );
		// compute internel test
		//cRSA_NO_PAD.doFinal( cRSAPublicEncResult, (short)0, (short)(cipherRSAKeyLength/8), buffer, (short)1 );

		// I decipher the data
		short sizeAfterUncipher = cRSA_NO_PAD.doFinal(
				buffer,
				ISO7816.OFFSET_CDATA,
				sizeData,
				buffer,
				(short)0
		);

		apdu.setOutgoingAndSend((short)0, sizeAfterUncipher);
		// compare result with the patern
		//buffer[0] = Util.arrayCompare( buffer, (short)1, inC, (short)0, (short)(cipherRSAKeyLength/8) );
		// send difference
		//apdu.setOutgoingAndSend( (short)0, (short)1 );
	}

	/**
	 * Function to encrypt or decrypt a file with DES
	 * @param apdu APDU to encrypt or decrypt a fi
	 * @param cipher type of cipher to use (in my case DES)
	 * @param keyLength length of the key
	 *@param cipherMode mode of the cipher (encrypt or decrypt)
	 */
	private void cipherGeneric(APDU apdu, Cipher cipher, short keyLength) {
		byte[] buffer = apdu.getBuffer();

		short bytesReadToCipher = apdu.setIncomingAndReceive();



		short sizeAfterCipher = cipher.doFinal(
				buffer,
				ISO7816.OFFSET_CDATA,
				bytesReadToCipher,
				buffer,                //  Where I put my result (ciphertext)
				(short)0
		);

		apdu.setOutgoingAndSend((short)0, sizeAfterCipher);
	}

	void getPublicRSAKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		// get the element type and length
		byte keyElement = (byte)(buffer[ISO7816.OFFSET_P2] & 0xFF);
		// check correct type (modulus or exponent)
		if((keyElement != 0x00) && (keyElement != 0x01))
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		// check elements request
		if(keyElement == 0) {
			// retrieve modulus
			buffer[0] = (byte)((RSAPublicKey)publicRSAKey).getModulus(buffer, (short)1);
		} else
			// retrieve exponent
			buffer[0] = (byte)((RSAPublicKey)publicRSAKey).getExponent(buffer, (short)1);
		// send the key element
		apdu.setOutgoingAndSend((short)0, (short)((buffer[0] & 0xFF) + 1));
	}


	void putPublicRSAKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		// get the element type and length
		byte keyElement = (byte)(buffer[ISO7816.OFFSET_P1] & 0xFF);
		short publicValueLength = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);
		// check correct type (modulus or exponent)
		if((keyElement != 0x00) && (keyElement != 0x01))
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		// use data in
		apdu.setIncomingAndReceive();
		// initialize RSA public key
		// check elements length for modulus only because exponent is naturaly short
		if(keyElement == 0) {
			// loading modulus
			if(publicValueLength != (short)(cipherRSAKeyLength/8))
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			// initialize modulus
			((RSAPublicKey)publicRSAKey).setModulus(buffer, (short)ISO7816.OFFSET_CDATA, (short)(buffer[ISO7816.OFFSET_LC] & 0xFF));
		} else
			// initialize exponent
			((RSAPublicKey)publicRSAKey).setExponent(buffer, (short)ISO7816.OFFSET_CDATA, (short)(buffer[ISO7816.OFFSET_LC] & 0xFF));
	}


}
