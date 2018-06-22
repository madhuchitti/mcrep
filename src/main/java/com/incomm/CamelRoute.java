package com.incomm;

import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

@Component
public class CamelRoute extends RouteBuilder {
	// Public Key FileName
	final String keyFileName = "TestCert.asc";

	// Private Key FileName
	final String keyFileNameSec = "secret.asc";

	// Keyring Userid Used to Encrypt
	final String keyUserid = "mchitti";

	// Private key password
	final String keyPassword = "Welcome123";
	
			
	@Override
	public void configure() throws Exception {

		        /*from("stream:in")
		          .multicast().to("direct:original", "direct:encrypt");

		        // Save the original input
		        from("direct:original")
		          .to("file:C:\\Users\\mchitti\\Desktop\\crypto?fileName=original.txt");*/

		        // Encrypts and saves the input
		        from("file://src/test/crypto?fileName=original.txt")
		          .marshal().pgp(keyFileName, keyUserid)
		          .multicast()
		          .to("direct:unencrypt", "file://src/test/crypto?fileName=encrypted.txt");

		        // Decrypts and saves the output
		        from("direct:unencrypt")
		          .unmarshal().pgp(keyFileNameSec, keyUserid, keyPassword)
		          .to("file://src/test/crypto?fileName=unencrypted.txt");

		
		
	}
}
