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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

/**
 * A de-serializer for converting a JSON string of revocation reason to {@link RevocationReason} object.
 * 
 * @author tcssarb
 * 
 */
public class RevocationReasonDeserializer extends JsonDeserializer<RevocationReason> {

    private static final Logger LOGGER = LoggerFactory.getLogger(RevocationReasonDeserializer.class);
    /**
     * Method to deserialize JSON content into the value type this serializer handles i.e., RevocationReason.
     * 
     * @param jsonParser
     *            Parser used for reading JSON content
     * @param context
     *            Context that can be used to access information about this deserialization activity
     * 
     * @return the deserialized RevocationReason object
     * 
     * @throws IOException
     *             when any I/O operation fails
     */
    @Override
    public RevocationReason deserialize(final JsonParser parser, final DeserializationContext context) throws IOException {
        if (parser != null) {
            try {
                return RevocationReason.fromValue(parser.getText());
            } catch (final IllegalArgumentException ie) {
                LOGGER.debug("Illegal Arugment Exception occured ", ie);
                return RevocationReason.getNameByValue(parser.getValueAsInt());
            }
        }
        return null;
    }

}
