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

import java.io.*;

import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DOMException;

public class DOMUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(DOMUtil.class);

    private DOMUtil() {

    }

    /**
     * This method will convert and return a Document object from the byte array.
     * 
     * @param byteArray
     *            is signed XML byte array which is to be converted to XML Document
     * @return XML Document which is built from the signed XML byte array
     * @throws DOMException
     *             is thrown when failed to build or parse a Document object.
     */
    public static Document getDocument(final byte[] byteArray) throws DOMException {

        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        Document document = null;
        InputStream is = null;
        try {
            final DocumentBuilder builder = factory.newDocumentBuilder();
            is = new ByteArrayInputStream(byteArray);
            document = builder.parse(is);
        } catch (IOException iOException) {
            LOGGER.error(ErrorMessages.IO_EXCEPTION, iOException);
            throw new DOMException(ErrorMessages.IO_EXCEPTION, iOException);

        } catch (ParserConfigurationException parserConfigurationException) {
            LOGGER.error(ErrorMessages.FAILED_TO_BUILD_DOCUMENT, parserConfigurationException);
            throw new DOMException(ErrorMessages.FAILED_TO_BUILD_DOCUMENT, parserConfigurationException);

        } catch (SAXException sAXException) {
            LOGGER.error(ErrorMessages.FAILED_TO_PARSE, sAXException);
            throw new DOMException(ErrorMessages.FAILED_TO_PARSE, sAXException);
        } finally {
            closeInputStream(is);
        }
        return document;
    }

    /**
     * @param is
     */
    private static void closeInputStream(final InputStream is) throws DOMException {
        if (is != null) {
            try {
                is.close();
            } catch (IOException iOException) {
                LOGGER.error(ErrorMessages.IO_EXCEPTION, iOException);
                throw new DOMException(ErrorMessages.IO_EXCEPTION, iOException);
            }
        }
    }

    /**
     * This method will return byte array from the Document object.
     * 
     * @param document
     *            XML Document which is to be converted to byte Array
     * @return byte format of signed XML Document
     * @throws DOMException
     *             is thrown when failed to convert byte array into Document.
     */
    public static byte[] getByteArray(final Document document) throws DOMException {
        byte[] byteArray = null;
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            final StreamResult result = new StreamResult(bos);
            final Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(document), result);
            byteArray = bos.toByteArray();

        } catch (TransformerException e) {
            LOGGER.error(ErrorMessages.INTERNAL_ERROR, " while converting the document into byte array.");
            throw new DOMException(ErrorMessages.INTERNAL_ERROR + " while converting the document into byte array.", e);
        } finally {
            closeOutputStream(bos);
        }
        return byteArray;
    }

    /**
     * @param bos
     */
    private static void closeOutputStream(final ByteArrayOutputStream bos) throws DOMException {
        try {
            bos.close();
        } catch (IOException iOException) {
            LOGGER.error(ErrorMessages.IO_EXCEPTION, iOException);
            throw new DOMException(ErrorMessages.IO_EXCEPTION, iOException);
        }
    }

    /**
     * This method will return a Document object from DocumentBuilderFactory.
     * 
     * @return XML Document Object
     * @throws DOMException
     *             is thrown when failed to build Document object.
     */
    public static Document getDocumentFromDocumentFactory() throws DOMException {
        Document document = null;
        try {
            final DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
            final DocumentBuilder documentBuilder = documentFactory.newDocumentBuilder();
            document = documentBuilder.newDocument();
        } catch (ParserConfigurationException parserConfigurationException) {
            LOGGER.error(ErrorMessages.INTERNAL_ERROR, parserConfigurationException);
            throw new DOMException(ErrorMessages.INTERNAL_ERROR, parserConfigurationException);
        }
        return document;
    }
}
