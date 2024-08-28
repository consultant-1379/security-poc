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
import java.util.*;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;

/**
 * A de-serializer for converting a JSON string of Trust Profile to {@link TrustProfile} object.
 * 
 * @author xhemgan
 * @version 1.2.4
 * 
 */
public class TrustProfileDeserializer extends JsonDeserializer<TrustProfile> {

    private final static String ID = "id";
    private final static String NAME = "name";
    private final static String ACTIVE = "active";
    private final static String INTERNAL_CAS = "internalCAs";

    /**
     * Method to deserialize JSON content into the value type this serializer handles i.e., TrustProfile.
     * 
     * @param jsonParser
     *            Parser used for reading JSON content
     * @param context
     *            Context that can be used to access information about this deserialization activity
     * 
     * @return the deserialized TrustProfile object
     * 
     * @throws IOException
     *             when any I/O operation fails
     * @throws JsonProcessingException
     *             when any failure occurs in processing JSON content
     */
    @Override
    public TrustProfile deserialize(final JsonParser jsonParser, final DeserializationContext context) throws IOException, JsonProcessingException {
        final TrustProfile trustProfile = new TrustProfile();

        final ObjectCodec objectCodec = jsonParser.getCodec();
        final JsonNode jsonNode = objectCodec.readTree(jsonParser);
        final JsonNode idNode = jsonNode.get(ID);
        long id = 0;
        if (idNode != null && !idNode.isNull()) {
            id = idNode.asLong();
        }
        trustProfile.setId(id);
        final JsonNode nameNode = jsonNode.get(NAME);
        String name = null;
        if (nameNode != null && !nameNode.isNull()) {
            name = nameNode.asText();
        }
        trustProfile.setName(name);
        final JsonNode activeNode = jsonNode.get(ACTIVE);
        final boolean active = activeNode.asBoolean();
        trustProfile.setActive(active);
        final JsonNode array = jsonNode.get(INTERNAL_CAS);
        if (array.isArray()) {
            final Iterator<JsonNode> iterator = array.elements();
            final List<TrustCAChain> trustCAChains = new ArrayList<TrustCAChain>();
            while (iterator.hasNext()) {
                final JsonNode node = iterator.next();
                final JsonNode caNode = node.get("CAEntity");
                final TrustCAChain trustCAChain = new TrustCAChain();
                final CAEntity caEntity = new CAEntity();
                final CertificateAuthority certificateAuthority = new CertificateAuthority();

                trustCAChain.setChainRequired(node.get("isChainRequired").asBoolean());
                certificateAuthority.setName(caNode.get(NAME).asText());
                caEntity.setCertificateAuthority(certificateAuthority);
                trustCAChain.setInternalCA(caEntity);
                trustCAChains.add(trustCAChain);
            }
            trustProfile.setTrustCAChains(trustCAChains);
        }
        return trustProfile;
    }

}
