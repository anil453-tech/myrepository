package ENCRYPTION;
import java.io.FileInputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
public class DecryptionCBS {
	public static final int GCM_TAG_LENGTH = 16;
	public static String decrypt(String encryptedData,String pubkeyloc) {
		    String decryptedDta = null;
		try {
			String encryptedSessionKey=encryptedData.split(":")[0].toString();
			String encryptedMetaData=encryptedData.split(":")[1].toString();
			String ivlength = encryptedData.split(":")[2].toString();
			
			String sessionKey=decryptsessionKey(encryptedSessionKey, getPrivateKey(pubkeyloc));
		    decryptedDta=aesDecrypt(java.util.Base64.getDecoder().decode(encryptedMetaData), java.util.Base64.getDecoder().decode(sessionKey) , java.util.Base64.getDecoder().decode(ivlength)) ;
		    System.out.println(decryptedDta);
		} catch (Exception e) {
			// TODO: handle exception
		}
		
		return decryptedDta;
	}
	 public static String decryptsessionKey(String encryptedAESKey, PrivateKey privateKey)
			    throws Exception
			  {
			    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
			    cipher.init(Cipher.DECRYPT_MODE, privateKey);
			    byte[] decordedValue = java.util.Base64.getDecoder().decode(encryptedAESKey);
			    byte[] decValue = cipher.doFinal(decordedValue);
			    String decryptedValue = new String(decValue);
			    return decryptedValue;
			  }
	 public static String aesDecrypt(byte[] cipherText, byte[] decryptkey, byte[] IV) throws Exception
	    {
	        
	        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
	        
	        SecretKeySpec keySpec = new SecretKeySpec(decryptkey, "AES");
	   /*     for (int i = 0; i < IV.length; i++) {
	            System.out.printf("%d ", IV[i]);
	        }*/
	        
	        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
	        
	        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
	        
	        return new String(cipher.doFinal(cipherText));
	    }
	 public static PrivateKey getPrivateKey(String pathtoprivatekey) {
	        PrivateKey pk = null;
	        
	        try {
	            String key = new String(Files.readAllBytes(Paths.get(pathtoprivatekey)), Charset.defaultCharset());
	       String privateKeyPEM = key
	      .replace("-----BEGIN PRIVATE KEY-----", "")
	      .replaceAll(System.lineSeparator(), "")
	      .replace("-----END PRIVATE KEY-----", "")
	     .replaceAll("\\s", "");
	 
	             byte[] encoded =  Base64.getDecoder().decode(privateKeyPEM.getBytes());
	        
	             KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	              PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
	                  pk=keyFactory.generatePrivate(keySpec);

	        } catch (Exception e) {
	            e.printStackTrace();

	        }
	        return pk;
	 }
	 public static void main(String[] args) throws Exception {
		 String metadata="Jw4M1EHN3ksRpPghu7WmCVuvnUs+gxQeb8PoITxsu5ndo0X4gJXSSAVJ6Ko3lPltWyhJF/BCy4tgvCnFqippRaI7drM3mG+Kv6+8R/BeeLGSEQfVhkd/+76/IO9OWprWrBYDcBUWzm7IQeXz5jSeuKtKofOGOSru6NOKYRog7BO614IKr8xtWfEVwgL0lZGu/Lcfqdmr935hzjg+4RCvqxQVqvdtGEJr3kqoFtdFzswuduhvS+JiIb70I1UtH7YUHE5yUvB/DdG31byswmrIR9H1hZxLrRiaXAX8e2Q/n3vQtuMTAjWvyUBbvSK5KKrES/+7meq/PdoK6GJ+aK6JXg==:fEq5sBomlIm0o8ehaIRrZ8ZeBYEk/tjZafh5IOHp+fddvAWRhNR2DrLdjkVnEaquRbPAawkgEY85J1h6VX3DeCKNFaxLvxJ+J+iIFRH4rWY57DBxx14=:tqKFbgECxzn3hWhn";
		 String s2="E:\\TOYOTA_WHATSAPP\\KEYS_PUBLIC_PRIVATE_WHATSAPP\\esbkbl.pem"; 		
		 String decrypteddata = decrypt(metadata,s2);
		 
	 }
	
}
