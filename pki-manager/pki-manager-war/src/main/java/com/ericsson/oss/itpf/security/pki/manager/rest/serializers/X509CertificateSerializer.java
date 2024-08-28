/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.rest.serializers;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

/**
 * A serializer for writing an X509Certificate to JSON string.
 * 
 * @author xhemgan
 * @version 1.1.30
 * 
 */
public class X509CertificateSerializer extends JsonSerializer<X509Certificate> {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509CertificateSerializer.class);
    /**
     * Method to serialize values of type this serializer handles. i.e., X509Certificate.
     * 
     * @param certificate
     *            X509Certificate in JSON string that should be serialized
     * @param generator
     *            Generator used to output resulting Json content
     * @param provider
     *            Provider that can be used to get serializers for serializing Objects value contains, if any.
     * 
     * @throws IOException
     *             when any I/O operation fails
     * @throws JsonProcessingException
     *             when any failure occurs in processing JSON content
     */
    public void serialize(final X509Certificate certificate, final JsonGenerator generator, final SerializerProvider provider) throws IOException, JsonProcessingException {

        try {
            generator.writeObject(certificate.getEncoded());
        } catch (final CertificateEncodingException e) {
            LOGGER.debug("Illegal Arugment Exception occured ", e);
            throw new IllegalArgumentException(e.getMessage());
        }
    }

}
