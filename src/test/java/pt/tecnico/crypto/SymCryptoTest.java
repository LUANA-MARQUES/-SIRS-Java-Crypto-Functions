package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.Key;
import javax.crypto.spec.IvParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.junit.jupiter.api.Test;

public class SymCryptoTest {
	/** Plain text to cipher. */
	//private final String plainText = "This is the plain text!";
	private final String plainText = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
	/** Plain text bytes. */
	private final byte[] plainBytes = plainText.getBytes();

	/** Symmetric cryptography algorithm. */
	private static final String SYM_ALGO = "AES";
	/** Symmetric algorithm key size. */
	private static final int SYM_KEY_SIZE = 128;
	/**
	 * Symmetric cipher: combination of algorithm, block processing, and padding.
	 */
	//private static final String SYM_CIPHER = "AES/ECB/PKCS5Padding";  //<--- ECB mode ciphers each block independently.
	private static final String SYM_CIPHER = "AES/CBC/PKCS5Padding"; // <--- CBC (Cipher Block Chaining) ciphers each block of plain data XORed with the previous ciphered data.

	/**
	 * Secret key cryptography test.
	 * 
	 * @throws Exception because test is not concerned with exception handling
	 */
	@Test
	public void testSymCrypto() throws Exception {
		System.out.print("TEST '");
		System.out.print(SYM_CIPHER);
		System.out.println("'");

		System.out.println("Text:");
		System.out.println(plainText);
		System.out.println("Bytes:");
		System.out.println(printHexBinary(plainBytes));

		// get a AES private key
		System.out.println("Generating AES key...");
		KeyGenerator keyGen = KeyGenerator.getInstance(SYM_ALGO);
		keyGen.init(SYM_KEY_SIZE);
		Key key = keyGen.generateKey();
		System.out.print("Key: ");
		System.out.println(printHexBinary(key.getEncoded()));
		// generate a random initialization vector (IV)
		byte[] iv = new byte[16];
		new java.security.SecureRandom().nextBytes(iv);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		iv = keyGen.generateKey().getEncoded();
		System.out.print("IV: ");
		System.out.println(printHexBinary(iv));

		Cipher cipher = Cipher.getInstance(SYM_CIPHER);
		System.out.println(cipher.getProvider().getInfo());


		// encrypt using the key and the plain text
		System.out.println("Ciphering...");
		
		// for ECB mode - get a AES cipher object and print the provider
		// cipher.init(Cipher.ENCRYPT_MODE, key);

		// for CBC mode - get a AES cipher object and print the provider
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		
		byte[] cipherBytes = cipher.doFinal(plainBytes);
		System.out.print("Result: ");
		System.out.println(printHexBinary(cipherBytes));

		// decipher the cipher text using the same key
		System.out.println("Deciphering...");
		//for ECB mode 
		//cipher.init(Cipher.DECRYPT_MODE, key);
		
		// for CBC mode - use the same IV
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		
		byte[] newPlainBytes = cipher.doFinal(cipherBytes);
		System.out.print("Result: ");
		System.out.println(printHexBinary(newPlainBytes));

		System.out.println("Text:");
		String newPlainText = new String(newPlainBytes);
		System.out.println(newPlainText);

		assertEquals(plainText, newPlainText);

		System.out.println();
		System.out.println();
	}
}
