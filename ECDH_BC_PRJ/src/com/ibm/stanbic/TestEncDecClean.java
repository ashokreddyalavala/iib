package com.ibm.stanbic;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
//import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.apache.commons.codec.binary.Base64;

import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class TestEncDecClean {
	private static KeyStore trustStore = null;
	
	public static void main(String[] args) {
		String jksFilePath = "D:\\Certificates\\stanbic-test-keystore.jks";
		
		if(args != null && args.length > 0) {
			jksFilePath = args[0];
		}
		
		String aliasName = "stanbic-test";
		String storePw = "123456";
		String privateKeyPw = "123456";
		
		String data = "ABCD";
		//byte[] encryptedValue = Base64.getEncoder().encode(data.getBytes(StandardCharsets.UTF_8));
	    //String dataBase64 = new String(encryptedValue, StandardCharsets.UTF_8);
		
		
		String dataBase64 = Base64.encodeBase64String(data.getBytes(StandardCharsets.UTF_8));
		
		String enc = null;
		try {
			enc = encryptBase64(jksFilePath, dataBase64, aliasName, storePw);
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("1 encrypted: "+enc);
		
		
		String decrypt = "pbAZPchx0tmM5hxw7i6VWRr8OTJAh1FbkR/OB+LIwm1xy4llY76dlfDO50SBYf+6Qlw2Nh+sVnHm3XFtVysxUt/k/knDr7ZSKFM7DtzI44GzLThCO+yaTtAWxB47pi8z9ub09oQq9trhRcw57v79lfELhtrO+2IDjXViQ+L5iW368z0bU43nfhok21nXs926he2se/Z47mKxV205Zj4tUysezceW40qZ/cBs6KZk0xo3UttYl7JLWdypBj9qhRjOgIq4t5sWyy7l0fp52HoC1XmmmMVE1uf3uhgoEwU54r7rBanWTZkPb53O1TN8rSotbekj5RCc/1h4Dz/Vjq43lbO+qJTg/nDFmOugC0f7J8+XIeitoEEZe+z3cw9MTB77vEdYLrckh3q5+pYnTI9Xe+EE9aDtVDTYVZe88Ll0RA2eKfYUPo2GhHCTYeJFf+8wxzIbbULwCwZJI0TQ8MQ+A/a0THaROm6KPTPDNWV74LnNIBsY9lCsXmxNZzykddhAH4dCOw1U7OR3l4Pwz9hRy4oTi5Qiib9FCZGSCJz1e1jTehHBBiVLa2BD5goH4kl544kU5s9M24jD7/ATlCwu2+qrJRKQ2jjAmAgklPyl7EUqi3p4ZWX283Uex4vvy04We6wovrqeEYL/vG1AJ0YONGkFHc9rN8cdA2mBbb7YYr8=";
		try {
			decrypt = decryptBase64(jksFilePath, decrypt, aliasName, storePw, privateKeyPw);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		//String dataOut = new String(Base64.getDecoder().decode(decrypt.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
		String dataOut = new String(Base64.decodeBase64(decrypt.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
		System.out.println("dataIn: "+data+", \nencrypted: "+enc+",\ndecrypted: "+decrypt+"\ndataOut: "+dataOut);
	}
	
	public static String encryptBase64(String jksFilePath, String toEncrypt, String aliasName, String storePw) {		
		byte[] decodedBytes = Base64.decodeBase64(toEncrypt);		
		byte[] result = encrypt(jksFilePath, decodedBytes, aliasName, storePw);		
	    String original = Base64.encodeBase64String(result);
	    return original;
	}
	
	public static String encrypt(String jksFilePath, String toEncrypt, String aliasName, String storePw)  {
		//registerBouncyCastleIfNeeded();
		
		loadTruststore(storePw, jksFilePath);
		
	    java.security.cert.Certificate cert = null;
	    String encryptedValue = null;
		try {
			cert = trustStore.getCertificate(aliasName);
			Key skeySpec = cert.getPublicKey();
		    
		    Cipher cipher = Cipher.getInstance("RSA");
		    cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		    byte[] encrypted = cipher.doFinal(toEncrypt.getBytes());
		    encryptedValue = Base64.encodeBase64String(encrypted);
		    
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return new String(encryptedValue);
	    
	}

	public static String decryptBase64(String jksFilePath, String encrypted, String aliasName, String storePw, String privateKeyPw)  {		
		//byte[] decodedBytes = Base64.getDecoder().decode(encrypted.getBytes());
		byte[] decodedBytes = Base64.decodeBase64(encrypted);
		byte[] result = null;
		try {
			result = decrypt(jksFilePath, decodedBytes, aliasName, storePw, privateKeyPw);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
	    //byte[] original = Base64.getEncoder().encode(result);
		String original = Base64.encodeBase64String(result);
	    return new String(original);
	}
	
	
	public static byte[] encrypt(String jksFilePath, byte[] toEncrypt, String aliasName, String storePw)  {
		registerBouncyCastleIfNeeded();
		
		loadTruststore(storePw, jksFilePath);
		
	    java.security.cert.Certificate cert;
	    byte[] encryptedValue = null;
		try {
			cert = trustStore.getCertificate(aliasName);
			Key skeySpec = cert.getPublicKey();
		    
		    Cipher cipher = Cipher.getInstance("RSA");
		    cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		    byte[] encrypted = cipher.doFinal(toEncrypt);
		     encryptedValue = encrypted;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
	    return encryptedValue;
	}	

	public static byte[] decrypt(String jksFilePath, byte[] encrypted, String aliasName, String storePw, String privateKeyPw) {
		//registerBouncyCastleIfNeeded();
		
		loadTruststore(storePw, jksFilePath);
		
	    Key skeySpec;
	    byte[] original = null;
		try {
			skeySpec = trustStore.getKey(aliasName, privateKeyPw.toCharArray());
			Cipher cipher = Cipher.getInstance("RSA");
		    cipher.init(Cipher.DECRYPT_MODE, skeySpec);
		    byte[] decodedBytes = encrypted;
		    original = cipher.doFinal(decodedBytes);
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
	    return original;
	}
	

	private static void loadTruststore(String storePw, String jksFilePath) {
		if(trustStore == null) {
//			trustStore = loadKeystoreExternal("Resources/stanbic-test/pki/stanbic-test-keystore.jks", storePw);
			trustStore = loadKeystoreExternal(jksFilePath, storePw);
		}
	}

	//@SuppressWarnings("unused")
	private static KeyStore loadKeystoreInternal(String path, String pw) {
		InputStream jks = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
				
		return processKS(pw, jks);
	}
	
	private static KeyStore loadKeystoreExternal(String path, String pw) {
		KeyStore keyStore = null;
		
		File file = new File(path);
		FileInputStream jks = null;
		try {
			jks = new FileInputStream(file);
			
			keyStore = processKS(pw, jks);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (jks != null)
					jks.close();
			} catch (IOException ex) {
//				ex.printStackTrace();
			}
		}
				
		return keyStore;
	}

	private static KeyStore processKS(String pw, InputStream jks) {
		KeyStore trustStore = null;
		try {
			trustStore = KeyStore.getInstance("JKS");
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		char[] pwdArray = pw.toCharArray();
		try {
			trustStore.load(jks, pwdArray);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NullPointerException e) {
			e.printStackTrace();
		}
		
		return trustStore;
	}

	public static synchronized void registerBouncyCastleIfNeeded() {
	    Provider provider = Security.getProvider("BC");
	    
	    if (provider != null)
	        return;
	    Security.addProvider(new BouncyCastleProvider());
	    provider = Security.getProvider("BC");
	    if (provider == null)
	        throw new IllegalStateException("Registration of BouncyCastleProvider failed!");
	}
	
	
	
	
	private static final String UNICODE_FORMAT = "UTF8";
	public static final String DES_ENCRYPTION_SCHEME = "DES";
	private static Cipher cipher;
	static byte[] keyAsBytes;
	static SecretKey key;
	static String myEncryptionKey = "U5cp5ywS7byc8b75z8uF95swojlrXNX6";
	static String myEncryptionScheme = DES_ENCRYPTION_SCHEME;


	/**
	 * Method To Decrypt An Ecrypted String
	 */
	public static String decryptToken(String encryptedString) {
		
		
		byte[] keyAsBytes;
		SecretKey key;
		String decryptedText = null;
		try {
			
			keyAsBytes = myEncryptionKey.getBytes(UNICODE_FORMAT);
			KeySpec myKeySpec = new DESKeySpec(keyAsBytes);
			SecretKeyFactory mySecretKeyFactory = SecretKeyFactory.getInstance(myEncryptionScheme);
			cipher = Cipher.getInstance(myEncryptionScheme);
			key = mySecretKeyFactory.generateSecret(myKeySpec);
			cipher.init(Cipher.DECRYPT_MODE, key);
			//BASE64Decoder base64decoder = new BASE64Decoder();
			//byte[] encryptedText = base64decoder.decodeBuffer(encryptedString);
			//byte[] encryptedText=Base64.getDecoder().decode(encryptedString);
			byte[] encryptedText = Base64.decodeBase64(encryptedString);
			byte[] plainText = cipher.doFinal(encryptedText);
			decryptedText = bytes2String(plainText);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decryptedText;
	}

	/**
	 * Returns String From An Array Of Bytes
	 */
	private static String bytes2String(byte[] bytes) {
		StringBuffer stringBuffer = new StringBuffer();
		for (int i = 0; i < bytes.length; i++) {
			stringBuffer.append((char) bytes[i]);
		}
		return stringBuffer.toString();
	}
	
	public static String encryptToken(String unencryptedString) {
		String encryptedString = null;
		try {
			keyAsBytes = myEncryptionKey.getBytes(UNICODE_FORMAT);
			KeySpec myKeySpec = new DESKeySpec(keyAsBytes);
			SecretKeyFactory mySecretKeyFactory = SecretKeyFactory.getInstance(myEncryptionScheme);
			cipher = Cipher.getInstance(myEncryptionScheme);
			key = mySecretKeyFactory.generateSecret(myKeySpec);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] plainText = unencryptedString.getBytes(UNICODE_FORMAT);
			byte[] encryptedText = cipher.doFinal(plainText);
			//BASE64Encoder base64encoder = new BASE64Encoder();
			//encryptedString = base64encoder.encode(encryptedText);
			//encryptedString=Base64.getEncoder().encodeToString(encryptedText);
			encryptedString=Base64.encodeBase64String(encryptedText);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encryptedString;
	}
}
