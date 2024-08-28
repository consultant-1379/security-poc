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
package com.ericsson.oss.itpf.security.pki.manager.rest.serializers;

import java.io.IOException;

import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

/**
 * Class that registers serializer for {@link AbstractProfile} class
 * 
 * @author tcsgoma
 * 
 */
public class AbstractProfileFetchSerializer extends JsonSerializer<AbstractProfile> {

    /**
     * Method to serialize values of type this serializer handles. i.e., AbstractProfile.
     * 
     * @param abstractProfile
     *            abstract profile in JSON string that should be serialized
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
    @Override
    public void serialize(final AbstractProfile abstractProfile, final JsonGenerator generator, final SerializerProvider provider) throws IOException, JsonProcessingException {
        generator.writeStartObject();
        generator.writeNumberField("id", abstractProfile.getId());
        generator.writeStringField("type", abstractProfile.getType().toString());
        generator.writeStringField("name", abstractProfile.getName());
        generator.writeStringField("status", abstractProfile.isActive() ? "active" : "inactive");
        generator.writeEndObject();
    }

}
