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
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.profilemanagement.entityprofile;

import java.util.ArrayList;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ExtendedKeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching the Key purpose ids in certificate profile of given id .
 * 
 * @author xhemgan
 * @version 1.1.30
 * 
 */
@Path("/1.0/certprofilekeypurposeid")
public class CertProfileKeyPurposeIdResource {

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    @Inject
    private Logger logger;

    @Inject
    private CommonUtil commonUtil;

    /**
     * This method lists the {@link KeyPurposeId} in {@link CertificateProfile} of given id .
     * 
     * @param certProfileId
     *            ID of the certificate profile from which KeyPurposeIds should be fetched.
     * 
     * @return a JSON Array containing the list of KeyPurposeIds.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/fetch/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch(@PathParam("id") final int certProfileId) throws JsonProcessingException {

        logger.debug("Fetching the keyUsageTypes from certificate profile with ID {}.", certProfileId);

        final ExtendedKeyUsage extendedKeyUsage = commonUtil.getCertificateExtension(certProfileId, ExtendedKeyUsage.class);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.EXTENDED_KEY_USAGE_TYPE_MAPPER);

        String result = null;

        if (extendedKeyUsage == null || ValidationUtils.isNullOrEmpty(extendedKeyUsage.getSupportedKeyPurposeIds())) {
            result = mapper.writeValueAsString(new ArrayList<KeyPurposeId>());
        } else {
            result = mapper.writeValueAsString(extendedKeyUsage.getSupportedKeyPurposeIds());
        }

        logger.debug("keyUsageTypes fetched. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }
}
