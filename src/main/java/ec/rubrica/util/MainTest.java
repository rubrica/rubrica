/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.util;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

public class MainTest {

	private BigInteger MOD = new BigInteger(
			"140856527624169758155266609875822408186807831378223569790643331193151564473910345400612983370548755182344718662027736933911257629244027675295840042132172758852914373620713654392238899886794432458073765705880240894185691519747991750040840873301941630038320664301838611097286260514917435195256996475776001521197");
	private BigInteger EXP = new BigInteger("65537");

	public static void main(String[] args) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		KeyPair keyPair = generator.generateKeyPair();
		System.out.println(keyPair.getPublic());
		System.out.println(keyPair.getPrivate());

		byte[] plaintext = "Este es un secreto!".getBytes();
		byte[] cypherText = encrypt(keyPair.getPublic(), plaintext);
		byte[] plaintext2 = decrypt(keyPair.getPrivate(), cypherText);

		System.out.println(new String(cypherText));
		System.out.println(new String(plaintext2));
	}

	private static byte[] encrypt(PublicKey pubKey, byte[] plaintext) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			return cipher.doFinal(plaintext);
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	private static byte[] decrypt(PrivateKey privKey, byte[] cyphertext) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privKey);
			return cipher.doFinal(cyphertext);
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	private PublicKey hardCodedKey(BigInteger mod, BigInteger exp) {
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
		KeyFactory keyFactory = null;
		PublicKey rsaKey = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			rsaKey = keyFactory.generatePublic(keySpec);
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return rsaKey;
	}
}