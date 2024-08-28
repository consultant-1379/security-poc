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

import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

/**
 * A serializer for writing a trusted CA i.e, a {@link CAEntity} to JSON string comprising of its ID and name.
 * 
 * @author xhemgan
 * @version 1.2.4
 * 
 */
public class TrustedCASerializer extends JsonSerializer<CAEntity> {

    private final static String ID = "id";
    private final static String NAME = "name";

    /**
     * Method to serialize values of type this serializer handles. i.e., CAEntity.
     * 
     * @param caEntity
     *            CA Entity in JSON string that should be serialized
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
    public void serialize(final CAEntity caEntity, final JsonGenerator generator, final SerializerProvider provider) throws IOException, JsonProcessingException {
        generator.writeStartObject();
        generator.writeNumberField(ID, caEntity.getCertificateAuthority().getId());
        generator.writeStringField(NAME, caEntity.getCertificateAuthority().getName());
        generator.writeEndObject();
    }
}
