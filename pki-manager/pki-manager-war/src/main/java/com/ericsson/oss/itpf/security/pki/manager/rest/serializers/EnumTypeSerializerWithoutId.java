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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

/**
 * A serializer for writing an enum to JSON string comprising of enum value along with its type.
 * 
 * @author tcspred
 * @version 1.1.30
 * 
 */
public class EnumTypeSerializerWithoutId<T> extends JsonSerializer<T> {

    private static final Logger LOGGER = LoggerFactory.getLogger(EnumTypeSerializerWithoutId.class);

    /**
     * Method to serialize values of type this serializer handles. i.e., Enum type.
     * 
     * @param T
     *            enum in JSON string that should be serialized
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
    public void serialize(final T value, final JsonGenerator generator, final SerializerProvider provider) throws IOException, JsonProcessingException {

        Method getNameMethod;
        String type = null;

        try {
            getNameMethod = value.getClass().getMethod("getName");

            type = (String) getNameMethod.invoke(value);

        } catch (final NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            LOGGER.debug("Illegal Arugment exception occured ", e);
            throw new IllegalArgumentException(e.getMessage());
        }

        generator.writeStartObject();
        generator.writeStringField("type", type);
        generator.writeStringField("value", "");
        generator.writeEndObject();
    }

}
