/*
 * Copyright 2009-2018 Rubrica
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

import java.awt.Dimension;
import java.awt.GraphicsEnvironment;
import java.awt.Toolkit;
import java.util.LinkedList;
import java.util.List;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import io.rubrica.util.OsUtils;

class OOXMLOfficeObjectHelper {

	private static final String MS_DIGITAL_SIGNATURE_SCHEMA = "http://schemas.microsoft.com/office/2006/digsig";
	private static final String NAMESPACE_SPEC_NS = "http://www.w3.org/2000/xmlns/";

	private OOXMLOfficeObjectHelper() {
		// No permitimos la instanciacion
	}

	static XMLObject getOfficeObject(String nodeId, XMLSignatureFactory fac, Document document, String signatureId,
			String signatureComments, String address1, String address2, String sigType) {

		List<XMLStructure> objectContent = new LinkedList<>();

		// ************************************************************************************
		// ************************************************************************************
		// ********************** SIGNATURE INFO V1
		// *******************************************

		Element signatureInfoV1Element = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "SignatureInfoV1");
		signatureInfoV1Element.setAttributeNS(NAMESPACE_SPEC_NS, "xmlns", MS_DIGITAL_SIGNATURE_SCHEMA);

		// ******************************************************************************
		// *********************** Metadatos vacios
		// *************************************
		signatureInfoV1Element.appendChild(document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "SetupID"));
		signatureInfoV1Element.appendChild(document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "SignatureText"));
		signatureInfoV1Element.appendChild(document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "SignatureImage"));

		// ********************** Fin Metadatos vacios
		// **********************************
		// ******************************************************************************

		// ******************************************************************************
		// **************** Metadatos adicionales V1
		// ************************************

		if (signatureComments != null) {
			Element signatureCommentsElement = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA,
					"SignatureComments");
			signatureCommentsElement.setTextContent(signatureComments);
			signatureInfoV1Element.appendChild(signatureCommentsElement);
		}

		if (OsUtils.isWindows()) {
			Element windowsVersionElement = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "WindowsVersion");
			windowsVersionElement.setTextContent(System.getProperty("os.version"));
			signatureInfoV1Element.appendChild(windowsVersionElement);
		}

		// Indicamos firma generada con Office 16
		Element officeVersionElement = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "OfficeVersion");
		officeVersionElement.setTextContent("16.0");
		signatureInfoV1Element.appendChild(officeVersionElement);
		Element applicationVersionElement = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "ApplicationVersion");
		applicationVersionElement.setTextContent("16.0");
		signatureInfoV1Element.appendChild(applicationVersionElement);

		GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();

		Element monitorsElement = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "Monitors");
		monitorsElement.setTextContent(Integer.toString(ge.getScreenDevices().length));
		signatureInfoV1Element.appendChild(monitorsElement);

		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();

		Element horizontalResolutionElement = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA,
				"HorizontalResolutionElement");
		horizontalResolutionElement.setTextContent(Integer.toString(screenSize.width));
		signatureInfoV1Element.appendChild(horizontalResolutionElement);

		Element verticalResolutionElement = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA,
				"VerticalResolutionElement");
		verticalResolutionElement.setTextContent(Integer.toString(screenSize.height));
		signatureInfoV1Element.appendChild(verticalResolutionElement);

		Element colorDepthElement = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "ColorDepth");
		colorDepthElement.setTextContent(Integer.toString(ge.getScreenDevices()[0].getDisplayMode().getBitDepth()));
		signatureInfoV1Element.appendChild(colorDepthElement);

		// Proveedor de firma por defecto

		Element signatureProviderId = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "SignatureProviderId");
		signatureProviderId.setTextContent("{00000000-0000-0000-0000-000000000000}");
		signatureInfoV1Element.appendChild(signatureProviderId);

		signatureInfoV1Element
				.appendChild(document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "SignatureProviderUrl"));

		Element signatureProviderDetails = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA,
				"SignatureProviderDetails");
		signatureProviderDetails.setTextContent("9");
		signatureInfoV1Element.appendChild(signatureProviderDetails);

		if (sigType != null && !sigType.isEmpty()) {
			Element signatureType = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "SignatureType");
			signatureType.setTextContent(sigType);
			signatureInfoV1Element.appendChild(signatureType);
		}

		// **************** Fin Metadatos adicionales V1
		// ********************************
		// ******************************************************************************

		// ************** FIN SIGNATURE INFO V1
		// ***********************************************
		// ************************************************************************************
		// ************************************************************************************

		// ************************************************************************************
		// ************************************************************************************
		// ************** SIGNATURE INFO V2
		// ***************************************************

		Element signatureInfoV2Element = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "SignatureInfoV2");
		signatureInfoV2Element.setAttributeNS(NAMESPACE_SPEC_NS, "xmlns", MS_DIGITAL_SIGNATURE_SCHEMA);

		if (address1 != null) {
			Element address1Element = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "Address1");
			address1Element.setTextContent(address1);
			signatureInfoV2Element.appendChild(address1Element);
		}

		if (address2 != null) {
			Element address2Element = document.createElementNS(MS_DIGITAL_SIGNATURE_SCHEMA, "Address2");
			address2Element.setTextContent(address2);
			signatureInfoV2Element.appendChild(address2Element);
		}

		// ************** FIN SIGNATURE INFO V2
		// ***********************************************
		// ************************************************************************************
		// ************************************************************************************

		// El nodo idOfficeV1Details agrupa tanto a SignatureInfoV1 como a
		// SignatureInfoV2

		List<XMLStructure> signatureInfoContent = new LinkedList<>();
		signatureInfoContent.add(new DOMStructure(signatureInfoV1Element));
		signatureInfoContent.add(new DOMStructure(signatureInfoV2Element));

		SignatureProperty signatureInfoSignatureProperty = fac.newSignatureProperty(signatureInfoContent,
				"#" + signatureId, "idOfficeV1Details");

		List<SignatureProperty> signaturePropertyContent = new LinkedList<>();
		signaturePropertyContent.add(signatureInfoSignatureProperty);
		SignatureProperties signatureProperties = fac.newSignatureProperties(signaturePropertyContent, null);
		objectContent.add(signatureProperties);

		return fac.newXMLObject(objectContent, nodeId, null, null);
	}
}