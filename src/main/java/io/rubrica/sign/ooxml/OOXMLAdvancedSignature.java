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

import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import es.uji.crypto.xades.jxades.security.xml.WrappedKeyStorePlace;
import es.uji.crypto.xades.jxades.security.xml.XmlWrappedKeyInfo;
import es.uji.crypto.xades.jxades.security.xml.XAdES.SignaturePolicyIdentifierImpl;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdES_EPES;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XMLAdvancedSignature;
import io.rubrica.xml.Utils;

final class OOXMLAdvancedSignature extends XMLAdvancedSignature {

	private byte[] ooXmlDocument;

	private OOXMLAdvancedSignature(XAdES_EPES xades, byte[] ooXmlPackage) {
		super(xades);
		this.ooXmlDocument = ooXmlPackage.clone();
	}

	static OOXMLAdvancedSignature newInstance(XAdES_EPES xades, byte[] ooXmlPackage) throws GeneralSecurityException {
		xades.setSignaturePolicyIdentifier(new SignaturePolicyIdentifierImpl(true));
		OOXMLAdvancedSignature result = new OOXMLAdvancedSignature(xades, ooXmlPackage);
		result.setDigestMethod(xades.getDigestMethod());
		result.setXadesNamespace(xades.getXadesNamespace());
		return result;
	}

	void sign(X509Certificate[] certChain, PrivateKey privateKey, String signatureMethod, List<?> refsIdList,
			String signatureIdPrefix) throws MarshalException, GeneralSecurityException, XMLSignatureException {

		List<?> referencesIdList = new ArrayList<>(refsIdList);

		if (WrappedKeyStorePlace.SIGNING_CERTIFICATE_PROPERTY.equals(getWrappedKeyStorePlace()) && certChain != null
				&& certChain.length > 0) {
			this.xades.setSigningCertificate(certChain[0]);
		}

		addXMLObject(marshalXMLSignature(this.xadesNamespace, this.signedPropertiesTypeUrl, signatureIdPrefix,
				referencesIdList,
				Arrays.asList( // En OOXML las SignedProperties se canonicalizan
						Utils.getDOMFactory().newTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
								(TransformParameterSpec) null))));

		XMLSignatureFactory fac = getXMLSignatureFactory();

		List<Reference> documentReferences = getReferences(referencesIdList);
		String keyInfoId = getKeyInfoId(signatureIdPrefix);
		documentReferences.add(fac.newReference("#" + keyInfoId, getDigestMethod()));

		this.signature = fac
				.newXMLSignature(
						fac.newSignedInfo(
								fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
										(C14NMethodParameterSpec) null),
								fac.newSignatureMethod(signatureMethod, null), documentReferences),
						newKeyInfo(certChain, keyInfoId), getXMLObjects(), getSignatureId(signatureIdPrefix),
						getSignatureValueId(signatureIdPrefix));

		this.signContext = new DOMSignContext(privateKey,
				this.baseElement != null ? this.baseElement : getBaseDocument());
		this.signContext.putNamespacePrefix(XMLSignature.XMLNS, this.xades.getXmlSignaturePrefix());
		this.signContext.putNamespacePrefix(this.xadesNamespace, this.xades.getXadesPrefix());
		this.signContext.setURIDereferencer(new OOXMLURIDereferencer(this.ooXmlDocument));

		this.signature.sign(this.signContext);
	}

	private KeyInfo newKeyInfo(X509Certificate[] certChain, String keyInfoId) throws KeyException {
		KeyInfoFactory keyInfoFactory = getXMLSignatureFactory().getKeyInfoFactory();
		List<X509Certificate> x509DataList = new ArrayList<>();
		if (!XmlWrappedKeyInfo.PUBLIC_KEY.equals(getXmlWrappedKeyInfo())) {
			for (final X509Certificate cert : certChain) {
				x509DataList.add(cert);
			}
		}
		List<XMLStructure> newList = new ArrayList<>();
		newList.add(keyInfoFactory.newKeyValue(certChain[0].getPublicKey()));
		newList.add(keyInfoFactory.newX509Data(x509DataList));
		return keyInfoFactory.newKeyInfo(newList, keyInfoId);
	}
}