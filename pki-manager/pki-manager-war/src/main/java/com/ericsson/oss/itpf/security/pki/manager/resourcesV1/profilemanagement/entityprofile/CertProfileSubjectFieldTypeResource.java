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

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching supported SubjectFieldTypes in certificate profile of given id .
 * 
 * @author tcspred
 */
@Path("/1.0/certprofilesubjectfieldtype")
public class CertProfileSubjectFieldTypeResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method lists the {@link SubjectFieldType} in {@link CertificateProfile} of given id .
     * 
     * @param certProfileId
     *            ID of the certificate profile from which SubjectFieldTypes should be fetched.
     * 
     * @return a JSON Array containing the list of SubjectFieldTypes.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/fetch/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch(@PathParam("id") final int certProfileId) throws JsonProcessingException {

        logger.debug("Fetching the SubjectFieldTypes from certificate profile with ID {}.", certProfileId);

        final List<SubjectFieldType> subjectFieldTypes = getSupportedSubjectFieldTypes(certProfileId);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.SUBJECT_CAPABILITIES_MAPPER);

        final String result = mapper.writeValueAsString(subjectFieldTypes);

        logger.debug("SubjectFieldTypes fetched. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }

    private List<SubjectFieldType> getSupportedSubjectFieldTypes(final int id) {
        CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setId(id);

        certificateProfile = pkiManagerEServiceProxy.getProfileManagementService().getProfile(certificateProfile);

        final Subject subjectCapabilities = certificateProfile.getSubjectCapabilities();
        final List<SubjectField> subjectFields = subjectCapabilities.getSubjectFields();
        final List<SubjectFieldType> subjectFieldTypes = new ArrayList<SubjectFieldType>();

        for (final SubjectField subjectField : subjectFields) {
            subjectFieldTypes.add(subjectField.getType());
        }

        return subjectFieldTypes;
    }
}
