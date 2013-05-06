/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.pdf.tsa;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

import com.itextpdf.text.error_messages.MessageLocalization;
import com.itextpdf.text.log.Logger;
import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;

/**
 * Implementacion de TSAClient que permite establecer un Policy OID para su
 * utilizacion. Extiende de TSAClientBouncyCastle.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class TSAClientBouncyCastleWithOid extends TSAClientBouncyCastle
		implements TSAClient {

	/** The Logger instance. */
	private static final Logger LOGGER = LoggerFactory
			.getLogger(TSAClientBouncyCastleWithOid.class);

	private String policy;

	public TSAClientBouncyCastleWithOid(String url) {
		super(url, null, null, DEFAULTTOKENSIZE, DEFAULTHASHALGORITHM);
	}

	public TSAClientBouncyCastleWithOid(String url, String username,
			String password) {
		super(url, username, password, 4096, DEFAULTHASHALGORITHM);
	}

	public TSAClientBouncyCastleWithOid(String url, String policy) {
		super(url, null, null, 4096, DEFAULTHASHALGORITHM);
		this.policy = policy;
	}

	/**
	 * Gets Policy OID of TSA request.
	 * 
	 * @param policy
	 */
	public String getPolicy() {
		return policy;
	}

	/**
	 * Sets Policy OID of TSA request.
	 * 
	 * @param policy
	 */
	public void setPolicy(String policy) {
		this.policy = policy;
	}

	/**
	 * Se reimplementa este metodo para establecer un OID mediante el metodo
	 * tsqGenerator.setReqPolicy()
	 */
	public byte[] getTimeStampToken(byte[] imprint) throws IOException,
			TSPException {
		byte[] respBytes = null;
		// Setup the time stamp request
		TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
		tsqGenerator.setCertReq(true);

		// Se agrega una PID Policy:
		if (policy != null && policy.length() > 0) {
			tsqGenerator.setReqPolicy(new ASN1ObjectIdentifier(policy));
		}

		BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
		TimeStampRequest request = tsqGenerator.generate(
				new ASN1ObjectIdentifier(DigestAlgorithms
						.getAllowedDigests(getDigestAlgorithm())), imprint,
				nonce);
		byte[] requestBytes = request.getEncoded();

		// Call the communications layer
		respBytes = getTSAResponse(requestBytes);

		// Handle the TSA response
		TimeStampResponse response = new TimeStampResponse(respBytes);

		// validate communication level attributes (RFC 3161 PKIStatus)
		response.validate(request);
		PKIFailureInfo failure = response.getFailInfo();
		int value = (failure == null) ? 0 : failure.intValue();
		if (value != 0) {
			// @todo: Translate value of 15 error codes defined by
			// PKIFailureInfo to string
			throw new IOException(MessageLocalization.getComposedMessage(
					"invalid.tsa.1.response.code.2", tsaURL,
					String.valueOf(value)));
		}
		// @todo: validate the time stap certificate chain (if we want
		// assure we do not sign using an invalid timestamp).

		// extract just the time stamp token (removes communication status info)
		TimeStampToken tsToken = response.getTimeStampToken();
		if (tsToken == null) {
			throw new IOException(MessageLocalization.getComposedMessage(
					"tsa.1.failed.to.return.time.stamp.token.2", tsaURL,
					response.getStatusString()));
		}
		tsToken.getTimeStampInfo(); // to view details
		byte[] encoded = tsToken.getEncoded();

		// Update our token size estimate for the next call (padded to be safe)
		this.tokenSizeEstimate = encoded.length + 32;
		return encoded;
	}

	/**
	 * Se reimplementa este metodo para establecer un OID mediante el metodo
	 * tsqGenerator.setReqPolicy()
	 */
	public byte[] getTimeStampToken54(byte[] imprint) throws IOException,
			TSPException {
		byte[] respBytes = null;
		// Setup the time stamp request
		TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
		tsqGenerator.setCertReq(true);

		// Se agrega una PID Policy:
		if (policy != null && policy.length() > 0) {
			tsqGenerator.setReqPolicy(new ASN1ObjectIdentifier(policy));
		}

		BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
		TimeStampRequest request = tsqGenerator.generate(
				new ASN1ObjectIdentifier(DigestAlgorithms
						.getAllowedDigests(digestAlgorithm)), imprint, nonce);
		byte[] requestBytes = request.getEncoded();

		// Call the communications layer
		respBytes = getTSAResponse(requestBytes);

		// Handle the TSA response
		TimeStampResponse response = new TimeStampResponse(respBytes);

		// validate communication level attributes (RFC 3161 PKIStatus)
		response.validate(request);
		PKIFailureInfo failure = response.getFailInfo();
		int value = (failure == null) ? 0 : failure.intValue();
		if (value != 0) {
			// @todo: Translate value of 15 error codes defined by
			// PKIFailureInfo to string
			throw new IOException(MessageLocalization.getComposedMessage(
					"invalid.tsa.1.response.code.2", tsaURL,
					String.valueOf(value)));
		}
		// @todo: validate the time stap certificate chain (if we want
		// assure we do not sign using an invalid timestamp).

		// extract just the time stamp token (removes communication status info)
		TimeStampToken tsToken = response.getTimeStampToken();
		if (tsToken == null) {
			throw new IOException(MessageLocalization.getComposedMessage(
					"tsa.1.failed.to.return.time.stamp.token.2", tsaURL,
					response.getStatusString()));
		}
		TimeStampTokenInfo tsTokenInfo = tsToken.getTimeStampInfo(); // to view
																		// details
		byte[] encoded = tsToken.getEncoded();

		LOGGER.info("Timestamp generated: " + tsTokenInfo.getGenTime());

		// QUITAR COMENTARIO:
		// if (tsaInfo != null) {
		// tsaInfo.inspectTimeStampTokenInfo(tsTokenInfo);
		// }
		// Update our token size estimate for the next call (padded to be safe)
		this.tokenSizeEstimate = encoded.length + 32;
		return encoded;
	}
}