/*
 * Copyright 2009-2017 Rubrica
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package io.rubrica.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HttpClient {

	private static final Logger logger = Logger.getLogger(HttpClient.class.getName());

	private static final String SSL_CONTEXT = "SSL";
	private static final String HTTPS = "https";
	private static final HostnameVerifier DEFAULT_HOSTNAME_VERIFIER = HttpsURLConnection.getDefaultHostnameVerifier();
	private static final SSLSocketFactory DEFAULT_SSL_SOCKET_FACTORY = HttpsURLConnection.getDefaultSSLSocketFactory();
	private static final boolean DISABLE_SSL_CHECKS = true;

	private static final TrustManager[] DUMMY_TRUST_MANAGER = new TrustManager[] { new X509TrustManager() {
		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) {
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) {
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	} };

	private static final HostnameVerifier ALL_HOSTNAME_VERIFIER = new HostnameVerifier() {
		@Override
		public boolean verify(String hostname, SSLSession session) {
			return true;
		}
	};

	public HttpClient() {
	}

	public byte[] download(String urlString) throws IOException {
		if (urlString == null) {
			throw new IllegalArgumentException("La URL a leer no puede ser nula");
		}

		URL url = new URL(urlString);

		if (DISABLE_SSL_CHECKS && url.getProtocol().equals(HTTPS)) {
			try {
				disableSslChecks();
			} catch (Exception e) {
				logger.warning(
						"No se ha podido ajustar la confianza SSL, es posible que no se pueda completar la conexion: "
								+ e);
			}
		}

		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.connect();

		int resCode = conn.getResponseCode();
		String statusCode = Integer.toString(resCode);
		logger.fine("Recibido: " + resCode + ": " + conn.getResponseMessage());

		if (statusCode.startsWith("4") || statusCode.startsWith("5")) {
			if (url.getProtocol().equals(HTTPS)) {
				enableSslChecks();
			}
			throw new HttpError(resCode, conn.getResponseMessage(), urlString);
		}

		try (InputStream is = conn.getInputStream()) {
			byte[] data = Utils.getDataFromInputStream(is);

			if (DISABLE_SSL_CHECKS && url.getProtocol().equals(HTTPS)) {
				enableSslChecks();
			}

			return data;
		}
	}

	public static void disableSslChecks() throws NoSuchAlgorithmException, KeyManagementException {
		SSLContext sc = SSLContext.getInstance(SSL_CONTEXT);
		sc.init(null, DUMMY_TRUST_MANAGER, new SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		HttpsURLConnection.setDefaultHostnameVerifier(ALL_HOSTNAME_VERIFIER);

		// Disable SNI
		System.setProperty("jsse.enableSNIExtension", "false");
	}

	/**
	 * Habilita las comprobaciones de certificados en conexiones SSL
	 * dej&aacute;ndolas con su comportamiento por defecto.
	 */
	public static void enableSslChecks() {
		HttpsURLConnection.setDefaultSSLSocketFactory(DEFAULT_SSL_SOCKET_FACTORY);
		HttpsURLConnection.setDefaultHostnameVerifier(DEFAULT_HOSTNAME_VERIFIER);
	}
}

class HttpError extends IOException {

	private static final long serialVersionUID = -5234088987681090845L;

	private int responseCode;
	private String responseDescription;

	/**
	 * Crea una excepci&oacute;n de error de conexi&oacute;n HTTP.
	 * 
	 * @param resCode
	 *            C&oacute;digo HTTP de respuesta.
	 */
	HttpError(int resCode) {
		super("Error en conexion HTTP con codigo de respuesta " + resCode);
		this.responseCode = resCode;
		this.responseDescription = null;
	}

	/**
	 * Crea una excepci&oacute;n de error de conexi&oacute;n HTTP.
	 * 
	 * @param resCode
	 *            C&oacute;digo HTTP de respuesta.
	 * @param resDescription
	 *            Descripci&oacute;n del error.
	 * @param url
	 *            URL a la que se intent&oacute; conectar.
	 */
	public HttpError(int resCode, String resDescription, String url) {
		super("Error en conexion HTTP con codigo de respuesta " + resCode + " y descripcion '" + resDescription
				+ "' para la direccion: " + url);
		this.responseCode = resCode;
		this.responseDescription = resDescription;
	}

	/**
	 * Obtiene el c&oacute;digo HTTP de respuesta.
	 * 
	 * @return C&oacute;digo HTTP de respuesta.
	 */
	public int getResponseCode() {
		return this.responseCode;
	}

	/**
	 * Obtiene la descripci&oacute;n del error HTTP.
	 * 
	 * @return Descripci&oacute;n del error HTTP.
	 */
	public String getResponseDescription() {
		return this.responseDescription;
	}
}