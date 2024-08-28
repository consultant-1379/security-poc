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
import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching supported SubjectAltNameFieldTypes in certificate profile of given id .
 * 
 * 
 * @author xhemgan
 * @version 1.1.30
 * 
 */
@Path("/1.0/certprofilesubjectaltnamefieldtype")
public class CertProfileSubjectAltNameFieldTypeResource {

    @Inject
    private Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    @Inject
    private CommonUtil commonUtil;

    /**
     * This method lists the {@link SubjectAltNameFieldType} in {@link CertificateProfile} of given id .
     * 
     * @param certProfileId
     *            ID of the certificate profile from which SubjectAltNameFieldTypes should be fetched.
     * 
     * @return a JSON Array containing the list of SubjectAltNameFieldTypes.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/fetch/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch(@PathParam("id") final int certProfileId) throws JsonProcessingException {

        logger.debug("Fetching the SubjectAltNameFieldTypes from certificate profile with ID {}.", certProfileId);

        final SubjectAltName subjectAltName = commonUtil.getCertificateExtension(certProfileId, SubjectAltName.class);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.SUBJECT_ALT_NAME_EXTENSION_MAPPER);

        String result = null;

        if (subjectAltName == null || ValidationUtils.isNullOrEmpty(subjectAltName.getSubjectAltNameFields())) {
            result = mapper.writeValueAsString(new ArrayList<SubjectAltNameFieldType>());
        } else {
            final List<SubjectAltNameFieldType> subjectAltNameFieldTypes = getSupportedSubjectAltNameFieldTypes(subjectAltName);
            result = mapper.writeValueAsString(subjectAltNameFieldTypes);
        }

        logger.debug("SubjectAltNameFieldTypes fetched. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }

    private List<SubjectAltNameFieldType> getSupportedSubjectAltNameFieldTypes(final SubjectAltName subjectAltName) {
        final List<SubjectAltNameField> subjectAltNameFields = subjectAltName.getSubjectAltNameFields();
        final List<SubjectAltNameFieldType> subjectAltNameFieldTypes = new ArrayList<SubjectAltNameFieldType>();

        for (final SubjectAltNameField subjectAltNameField : subjectAltNameFields) {
            subjectAltNameFieldTypes.add(subjectAltNameField.getType());
        }

        return subjectAltNameFieldTypes;
    }
}
