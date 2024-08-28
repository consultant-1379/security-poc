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

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

/**
 * Class that registers serializer for {@link Algorithm} class
 * 
 * @author tcspred
 * 
 */
public class KeyGenerationAlgorithmSerializer extends JsonSerializer<Algorithm> {

    private final static String ID = "id";
    private final static String NAME = "name";
    private final static String KEY_SIZE = "keySize";

    /**
     * Method to serialize values of type this serializer handles. i.e., Algorithm.
     * 
     * @param algorithm
     *            algorithm in JSON string that should be serialized
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
    public void serialize(final Algorithm algorithm, final JsonGenerator generator, final SerializerProvider provider) throws IOException, JsonProcessingException {
        generator.writeStartObject();

        generator.writeNumberField(ID, algorithm.getId());
        generator.writeStringField(NAME, algorithm.getName());
        generator.writeNumberField(KEY_SIZE, algorithm.getKeySize());

        generator.writeEndObject();
    }
}
