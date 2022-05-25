package EncodeDecode;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
public class Generate_Signature {


public static String getSignatute(String data,String pvtpath){

	  Signature sign;
	  String Sign =null;
	try {
		  PrivateKey private_key = getPrivateKey(pvtpath);
		sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(private_key);
		sign.update(data.getBytes());
		byte[] signdata = sign.sign();
		Sign =org.apache.commons.codec.binary.Base64.encodeBase64String(signdata);
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (InvalidKeyException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (SignatureException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (InvalidKeySpecException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
		System.out.println(Sign);
	return Sign;
}
public static PublicKey getPublicKey(String keypath) throws CertificateException, IOException{
	FileInputStream fis = new FileInputStream(keypath);
	 BufferedInputStream bis = new BufferedInputStream(fis);

	 CertificateFactory cf = CertificateFactory.getInstance("X.509");

	 while (bis.available() > 0) {
	    Certificate cert = cf.generateCertificate(bis);
	    return cert.getPublicKey();
	 }
	 bis.close();
	return null;}

public static PrivateKey getPrivateKey(String keypath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
	String key = new String(Files.readAllBytes(Paths.get(keypath)),
			Charset.defaultCharset());
	String privateKeyPEM = key
			.replace("-----BEGIN PRIVATE KEY-----", "")
			.replaceAll(System.lineSeparator(), "")
			.replace("-----END PRIVATE KEY-----", "")
			.replaceAll("\\s", "");
	//byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
	byte[] decoded = org.apache.commons.codec.binary.Base64.decodeBase64(privateKeyPEM.getBytes());
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
    KeyFactory kf = KeyFactory.getInstance("RSA");

    return kf.generatePrivate(keySpec);
}
public static String  verifySignature(String signdata,String data,String certpath){
	PublicKey pub;
	String result = null;
	try {
		pub = getPublicKey(certpath);
		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initVerify(pub);
		sign.update(data.getBytes());

		Boolean verify = sign.verify(org.apache.commons.codec.binary.Base64.decodeBase64(signdata));
		if (verify)
			result =data;
		else
			result = "Signature not verified";
	} catch (CertificateException | IOException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
   System.out.println(result);
	return result;
}

   public static void main(String args[]) 
   {
	String data="Hello world";
	String pvtpath="C:\\Users\\SSC\\Downloads\\Pronteffcert-privkey.pem";
	getSignatute(data,pvtpath);
	String signdata="BCOCxjB6jY8OhHSz4RUjVr6fLNMwgxk5eAXoPM5196AYQ4F23UMrquZ23B4DHVzEDRG516TiF0MYskt/2e3ZNum+i6GgDyw6YRL8P/1aY8RAywn1moEwDOzF/RkgnMA0qjipNmVzd07BXLNiQHJ9QLbtEmmvIv7xDRCcIxuhlsp8XrARCtkwqlgDShl53827h7ZU6BfwxqqWZ3kzctv0P5+bIpfTIlh9jAZlDW8udVE8rGUD53Cy9ripL3TWJfB+l6aYjzavYqfkqfzzrakcLOhYA7fEjOgGQu+X3+IM5Aw2Nu1bvyivLe/iCt27cIFfQReA9fj9d4EctXo6TIQ/kg==";
	String data1="Hello world";
	String certpath="C:\\Users\\SSC\\Downloads\\Pronteffcert-sscert.pem";
	verifySignature(signdata,data1,certpath);
}
}
