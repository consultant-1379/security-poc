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

import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

/**
 * A serializer for writing a a {@link TrustProfile} to JSON string with selective fields.
 * 
 * @author xhemgan
 * @version 1.2.4
 * 
 */
public class TrustProfileSerializer extends JsonSerializer<TrustProfile> {

    private final static String ID = "id";
    private final static String NAME = "name";
    private final static String ACTIVE = "active";
    private final static String INTERNAL_CAS = "internalCAs";

    /**
     * Method to serialize values of type this serializer handles. i.e., TrustProfile.
     * 
     * @param trustProfile
     *            trust profile in JSON string that should be serialized
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
    public void serialize(final TrustProfile trustProfile, final JsonGenerator generator, final SerializerProvider provider) throws IOException, JsonProcessingException {
        generator.writeStartObject();
        generator.writeNumberField(ID, trustProfile.getId());
        generator.writeStringField(NAME, trustProfile.getName());
        generator.writeBooleanField(ACTIVE, trustProfile.isActive());
        generator.writeFieldName(INTERNAL_CAS);
        generator.writeStartArray();
        for (final TrustCAChain trustCAChain : trustProfile.getTrustCAChains()) {
            generator.writeStartObject();
            generator.writeBooleanField("isChainRequired", trustCAChain.isChainRequired());
            generator.writeObjectFieldStart("CAEntity");
            generator.writeFieldName(ID);
            generator.writeNumber(trustCAChain.getInternalCA().getCertificateAuthority().getId());
            generator.writeFieldName(NAME);
            generator.writeString(trustCAChain.getInternalCA().getCertificateAuthority().getName());
            generator.writeEndObject();
            generator.writeEndObject();
        }
        generator.writeEndArray();
        generator.writeEndObject();
    }
}