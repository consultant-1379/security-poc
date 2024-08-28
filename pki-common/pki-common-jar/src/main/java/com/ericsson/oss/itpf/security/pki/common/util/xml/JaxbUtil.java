/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.common.util.xml;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.xml.bind.*;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.MarshalException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.UnmarshalException;

/**
 * This class will provide the utility methods to do marshaling and unmarshaling of XML.
 * 
 * @author xnagsow
 *
 */
public class JaxbUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(JaxbUtil.class);

    private JaxbUtil() {

    }

    /**
     * This method is used to marshal java xml object to the XML Dom Document object.
     * 
     * @param javaXMLTobeMarshled
     *            xml which need to be marshaled to Document for generating attached signature XML document.
     * @param document
     *            is the XML Dom Document object
     * @throws MarshalException
     *             is thrown when failed o marshal the data into document.
     */
    public static <T> Document getXML(final T classT) throws MarshalException {
        final Document document = DOMUtil.getDocumentFromDocumentFactory();
        try {
            final JAXBContext contextObj = JAXBContext.newInstance(classT.getClass());
            final Marshaller marshallerObj = contextObj.createMarshaller();
            marshallerObj.marshal(classT, document);
        } catch (JAXBException jAXBException) {
            LOGGER.error("Failed to marshal java object to document {}", jAXBException.getMessage());
            throw new MarshalException(ErrorMessages.FAILED_TO_MARSHALL, jAXBException);
        }
        return document;
    }

    /**
     * This method is used to unmarshal XML Dom Document object to the java xml object.
     * 
     * @param rootXML
     *            name of the class which extends the AbstractRootXML.
     * @param document
     *            Document which need to be unmarshaled into a Java XML object (AbstractRootXML).
     * @return Unmarshaled Java XML object for the specified class T.
     * @throws UnmarshalException
     *             is thrown when failed to unmarshal the document.
     */
    public static <T> T getObject(final Document document, final Class<T> classT) throws UnmarshalException {
        T object = null;

        try {
            final JAXBContext jaxbContext = JAXBContext.newInstance(classT);

            final Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
            object = classT.cast(jaxbUnmarshaller.unmarshal(document));

        } catch (JAXBException jAXBException) {
            LOGGER.error("Failed to unmarshal document to java XML object {}", jAXBException);
            throw new UnmarshalException(ErrorMessages.FAILED_TO_UNMARSHALL, jAXBException);
        }
        return (T) object;
    }

    /**
     * This method is used to get the X509Certificate from the Document object
     * 
     * @param document
     *            XML Document of which the signature is to be validated.
     * @return X509Certificate returns the X509Certificate object
     * @throws IOException
     *             In the event of corrupted data, or an incorrect structure.
     * @throws CertificateException
     *             If the Certificate conversion is unable to be made.
     */
    public static X509Certificate getX509CertificateFromDocument(final Document document) throws IOException, CertificateException {
        final NodeList nodeListcert = document.getElementsByTagName("X509Certificate");
        final String base64Certificate = nodeListcert.item(0).getFirstChild().getTextContent();
        final X509CertificateHolder certHolder = new X509CertificateHolder(Base64.decode(base64Certificate));
        final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
        return cert;
    }
}
