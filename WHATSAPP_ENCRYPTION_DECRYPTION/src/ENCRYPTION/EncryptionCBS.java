package ENCRYPTION;
import java.io.FileInputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
public class EncryptionCBS {

	public static final int GCM_TAG_LENGTH = 16;
    private static final int SYMMETRIC_KEY_SIZE = 256;
	public static byte[] generateSessionKey() {
		byte[] symmKey = null;
		try {
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(SYMMETRIC_KEY_SIZE);
			SecretKey key = kgen.generateKey();
			 symmKey = key.getEncoded();
			//return symmKey;
		} catch (Exception e) {
			// TODO: handle exception
		}
		return symmKey;
	}
	public static String encrypt(String DATA,String keyFileLocation)  {
		String encryptedData=null;
		try {
			byte[] sessionkey=generateSessionKey();
			byte[] iv = new byte[12];
			SecureRandom srandom = new SecureRandom();
			srandom.nextBytes(iv);
		for (int i = 0; i < iv.length; i++) {
	            System.out.printf("%d ", iv[i]);
	        }
			String encryptedSessionKey=encryptSessionKey(Base64.getEncoder().encodeToString(sessionkey), getPublicKey(keyFileLocation));
			byte[] encryptedMetaData=aesEncrypt(DATA.getBytes(), sessionkey, iv);
			encryptedData=encryptedSessionKey+":"+Base64.getEncoder().encodeToString(encryptedMetaData)+":"+Base64.getEncoder().encodeToString(iv);
		} catch (Exception e) {
			// TODO: handle exception
		}
		System.out.println(encryptedData);
		return encryptedData;
		}
	
	 public static String encryptSessionKey(String plainAESKey, PublicKey publicKey)
			  {
		        String encryptedValue =null;
			   try {
				   Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
				    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
				    byte[] encVal = cipher.doFinal(plainAESKey.getBytes());
				    encryptedValue = Base64.getEncoder().encodeToString(encVal);
			} catch (Exception e) {
				// TODO: handle exception
			}
			    return encryptedValue;
			  }
	 public static byte[] aesEncrypt(byte[] plaintext, byte[] key, byte[] IV) throws Exception
	    {
	        
	        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
	        
	        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
	        
	        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
	        
	        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
	        	        
	        return cipher.doFinal(plaintext);
	    }
	 public static PublicKey getPublicKey(String filePath)  {
	      PublicKey pk =null;;  
	  try{
	        FileInputStream fin = new FileInputStream(filePath);
	        CertificateFactory f = CertificateFactory.getInstance("X.509");
	        X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
	         pk = certificate.getPublicKey();
	     
	         }catch (Exception e) {
				e.printStackTrace();
				
			}
	    return pk;

}
	 public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, Exception {
		 String actualdata ="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" + 
					"<FIXML xsi:schemaLocation=\"http://www.finacle.com/fixml RetCustMod.xsd\" xmlns=\"http://www.finacle.com/fixml\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\r\n" + 
					"<Header>\r\n" + 
					"<RequestHeader>\r\n" + 
					"<MessageKey>\r\n" + 
					"<RequestUUID>Req_15336222629177</RequestUUID>\r\n" + 
					"<ServiceRequestId>RetCustInq</ServiceRequestId>\r\n" + 
					"<ServiceRequestVersion>10.2</ServiceRequestVersion>\r\n" + 
					"<ChannelId>CRM</ChannelId>\r\n" + 
					"<LanguageId></LanguageId>\r\n" + 
					"</MessageKey>\r\n" + 
					"<RequestMessageInfo>\r\n" + 
					"<BankId>01</BankId>\r\n" + 
					"<TimeZone></TimeZone>\r\n" + 
					"<EntityId></EntityId>\r\n" + 
					"<EntityType></EntityType>\r\n" + 
					"<ArmCorrelationId></ArmCorrelationId>\r\n" + 
					"<MessageDateTime>2018-07-07T11:41:02.914</MessageDateTime>\r\n" + 
					"</RequestMessageInfo>\r\n" + 
					"<Security>\r\n" + 
					"<Token>\r\n" + 
					"<PasswordToken>\r\n" + 
					"<UserId></UserId>\r\n" + 
					"<Password></Password>\r\n" + 
					"</PasswordToken>\r\n" + 
					"</Token>\r\n" + 
					"<FICertToken></FICertToken>\r\n" + 
					"<RealUserLoginSessionId></RealUserLoginSessionId>\r\n" + 
					"<RealUser></RealUser>\r\n" + 
					"<RealUserPwd></RealUserPwd>\r\n" + 
					"<SSOTransferToken></SSOTransferToken>\r\n" + 
					"</Security>\r\n" + 
					"</RequestHeader>\r\n" + 
					"</Header>\r\n" + 
					"<Body>\r\n" + 
					"<RetCustInqRequest>\r\n" + 
					"<RetCustInqRq>\r\n" + 
					"<CustId>311106571</CustId>\r\n" + 
					"</RetCustInqRq>\r\n" + 
					"<RetCustInq_CustomData/>\r\n" + 
					"</RetCustInqRequest>\r\n" + 
					"</Body>\r\n" + 
					"</FIXML>";
		  String certicatepath="E:\\Toyota_What'sApp\\KEYS_PUBLIC_PRIVATE_WHATSAPP\\esbkblpublic.cer";
		 String Metadata = encrypt(actualdata ,certicatepath);
}
}
