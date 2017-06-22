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

package io.rubrica.sign.ooxml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import io.rubrica.core.Util;

/**
 * Resuelve referencias dentro del Zip de un documento OOXML.
 */
public class OOXMLURIDereferencer implements URIDereferencer {

	private byte[] ooxml;

	private URIDereferencer baseUriDereferencer;

	private static final Logger logger = Logger.getLogger(OOXMLURIDereferencer.class.getName());

	OOXMLURIDereferencer(byte[] ooxml) {
		if (null == ooxml) {
			throw new IllegalArgumentException("El OOXML es nulo");
		}
		this.baseUriDereferencer = XMLSignatureFactory.getInstance().getURIDereferencer();
		this.ooxml = ooxml.clone();
	}

	@Override
	public Data dereference(URIReference uriReference, XMLCryptoContext context) throws URIReferenceException {
		if (null == uriReference) {
			throw new IllegalArgumentException("La referencia no puede ser nula");
		}

		if (null == context) {
			throw new IllegalArgumentException("El contexto de firma no puede ser nulo");
		}

		String uri = uriReference.getURI();

		try {
			uri = URLDecoder.decode(uri, "UTF-8");
		} catch (final UnsupportedEncodingException e) {
			logger.warning("No se puede decodificar la URI '" + uri + "': " + e);
		}

		try (final InputStream dataInputStream = findDataInputStream(uri);) {
			if (null == dataInputStream) {
				return this.baseUriDereferencer.dereference(uriReference, context);
			}

			byte[] data = Util.getDataFromInputStream(dataInputStream);
			dataInputStream.close();
			return new OctetStreamData(new ByteArrayInputStream(data), uri, null);
		} catch (final IOException e) {
			throw new URIReferenceException("Error de I/O: " + e, e);
		}
	}

	private InputStream findDataInputStream(String uri) throws IOException {
		String entryName;

		if (uri.startsWith("/")) {
			entryName = uri.substring(1); // remove '/'
		} else {
			entryName = uri;
		}

		if (-1 != entryName.indexOf('?')) {
			entryName = entryName.substring(0, entryName.indexOf('?'));
		}

		ZipInputStream ooxmlZipInputStream = new ZipInputStream(new ByteArrayInputStream(this.ooxml));
		ZipEntry zipEntry;

		while (null != (zipEntry = ooxmlZipInputStream.getNextEntry())) {
			if (zipEntry.getName().equals(entryName)) {
				return ooxmlZipInputStream;
			}
		}

		return null;
	}
}