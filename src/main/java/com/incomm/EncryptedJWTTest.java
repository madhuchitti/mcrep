package com.incomm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

import org.apache.camel.Exchange;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.impl.DefaultExchange;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.ByteUtil;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

public class EncryptedJWTTest {

	public static void runJWTTest() throws Exception {
		Date now = new Date();
		generatePublicKey();
		JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder().issuer("https://openid.net").subject("alice")
				.audience(Arrays.asList("https://app-one.com", "https://app-two.com"))
				.expirationTime(new Date(now.getTime() + 1000 * 60 * 10)) // expires
																			// in
																			// 10
																			// minutes
				.notBeforeTime(now).issueTime(now).jwtID(UUID.randomUUID().toString()).build();

		 System.out.println(jwtClaims.toJSONObject());

		// Produces
		// {
		// "iss" : "https:\/\/openid.net",
		// "sub" : "alice",
		// "aud" : [ "https:\/\/app-one.com" , "https:\/\/app-two.com" ],
		// "exp" : 1364293137871,
		// "nbf" : 1364292537871,
		// "iat" : 1364292537871,
		// "jti" : "165a7bab-de06-4695-a2dd-9d8d6b40e443"
		// }

		// Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);

		// Create the encrypted JWT object
		EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

		// Create an encrypter with the specified public RSA key
		RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) loadPublicKey());

		// Do the actual encryption
		jwt.encrypt(encrypter);

		// Serialise to JWT compact form
		String jwtString = jwt.serialize();

		System.out.println(jwtString);
		// Produces
		//
		// eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.K52jFwAQJH-
		// DxMhtaq7sg5tMuot_mT5dm1DR_01wj6ZUQQhJFO02vPI44W5nDjC5C_v4p
		// W1UiJa3cwb5y2Rd9kSvb0ZxAqGX9c4Z4zouRU57729ML3V05UArUhck9Zv
		// ssfkDW1VclingL8LfagRUs2z95UkwhiZyaKpmrgqpKX8azQFGNLBvEjXnx
		// -xoDFZIYwHOno290HOpig3aUsDxhsioweiXbeLXxLeRsivaLwUWRUZfHRC
		// _HGAo8KSF4gQZmeJtRgai5mz6qgbVkg7jPQyZFtM5_ul0UKHE2y0AtWm8I
		// zDE_rbAV14OCRZJ6n38X5urVFFE5sdphdGsNlA.gjI_RIFWZXJwaO9R.oa
		// E5a-z0N1MW9FBkhKeKeFa5e7hxVXOuANZsNmBYYT8G_xlXkMD0nz4fIaGt
		// uWd3t9Xp-kufvvfD-xOnAs2SBX_Y1kYGPto4mibBjIrXQEjDsKyKwndxzr
		// utN9csmFwqWhx1sLHMpJkgsnfLTi9yWBPKH5Krx23IhoDGoSfqOquuhxn0
		// y0WkuqH1R3z-fluUs6sxx9qx6NFVS1NRQ-LVn9sWT5yx8m9AQ_ng8MBWz2
		// BfBTV0tjliV74ogNDikNXTAkD9rsWFV0IX4IpA.sOLijuVySaKI-FYUaBy
		// wpg

		// Parse back
		jwt = EncryptedJWT.parse(jwtString);

		// Create a decrypter with the specified private RSA key
		RSADecrypter decrypter = new RSADecrypter((PrivateKey) loadPrivateKey());

		// Decrypt
		jwt.decrypt(decrypter);

		// Retrieve JWT claims
		System.out.println(jwt.getHeader());
		System.out.println(jwt.getJWTClaimsSet().getIssuer());
		System.out.println(jwt.getJWTClaimsSet().getSubject());
		System.out.println(jwt.getJWTClaimsSet().getAudience().size());
		System.out.println(jwt.getJWTClaimsSet().getExpirationTime());
		System.out.println(jwt.getJWTClaimsSet().getNotBeforeTime());
		System.out.println(jwt.getJWTClaimsSet().getIssueTime());
		System.out.println(jwt.getJWTClaimsSet().getJWTID());
	}

	public static void generatePublicKey() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Key pub = kp.getPublic();
		Key pvt = kp.getPrivate();
		String outFile = "RSA";
		FileOutputStream out = new FileOutputStream(outFile + ".key");
		out.write(pvt.getEncoded());
		out.close();

		out = new FileOutputStream(outFile + ".pub");
		out.write(pub.getEncoded());
		out.close();
	}
	
	public static PrivateKey loadPrivateKey() throws Exception {
		Path path = Paths.get("RSA.key");
		byte[] bytes = Files.readAllBytes(path);

		/* Generate private key. */
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey pvt = kf.generatePrivate(ks);
		return pvt;
	}
	
	public static PublicKey loadPublicKey() throws Exception  {
		Path path = Paths.get("RSA.pub");
		byte[] bytes = Files.readAllBytes(path);

		/* Generate public key. */
		X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pub = kf.generatePublic(ks);
		
		return pub;
	}
	
	public static void runJWETest() throws Exception {
		
		 	AesKey key = new AesKey(ByteUtil.randomBytes(16));

	        Exchange marshallExchange = new DefaultExchange(new DefaultCamelContext());
	        marshallExchange.getIn().setHeader(Key.class.getName(), key);
	        marshallExchange.getIn().setHeader(JweHeaderConstants.ALGORITHM_HEADER_VALUE, KeyManagementAlgorithmIdentifiers.A128KW);
	        marshallExchange.getIn().setHeader(JweHeaderConstants.ENCRYPTION_METHOD_HEADER_PARAMETER, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);

	        
	        String jsonRequest = "{\"request\":\"REQUEST\"}";

	        ByteArrayOutputStream stream = new ByteArrayOutputStream();

	        PayloadEncryptionDataFormat format = new PayloadEncryptionDataFormat();
	        format.marshal(marshallExchange, jsonRequest, stream);
	        System.out.println(stream.toString());
	        Exchange unmarshalExchange = new DefaultExchange(new DefaultCamelContext());
	        unmarshalExchange.getIn().setHeader(Key.class.getName(), key);

	        String jsonResponse = (String)format.unmarshal(unmarshalExchange, new ByteArrayInputStream(stream.toByteArray()));

	        System.out.println(jsonResponse);
	        
	}
	public static void main(String[] args) throws Exception {
		runJWETest();
	}
}
