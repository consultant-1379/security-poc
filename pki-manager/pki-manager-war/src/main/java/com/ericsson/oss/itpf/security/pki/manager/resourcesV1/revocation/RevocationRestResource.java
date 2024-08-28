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
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.revocation;

import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;



import java.io.IOException;
import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.json.JSONException;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.rest.helpers.RevocationRestResourceHelper;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.CommonUtil;
import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * This Rest Service has methods which are used to support Revocation operations from UI Interface.
 * 
 * @author xbensar
 * 
 */
@Path("/1.0/")
public class RevocationRestResource {

    @Inject
    private Logger logger;
    @Inject
    PKIManagerEServiceProxy pkiManagerEServiceProxy;
    @Inject
    private RevocationRestResourceHelper revocationRestResourceHelper;
    @Inject
    CommonUtil commonUtil;

    /**
     * This method is used to revoke all the valid Certificates of the given CA Entity.
     * 
     * @param caEntityRevocationInfoJSON
     *            It consists of entityName and revocationReason
     * @return Response is the rest response which contains JSON {@link RevocationStatusDTO} Object.
     * 
     */
    @Path("/entities/caentity/revocation")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeCAEntity(final String caEntityRevocationInfoJSON) {
        logger.debug("revokeCAEntity method in RevocationRestService class");
        Response response = null;

        try {
            final EntityRevocationInfoDTO entityRevocationInfoDTO = commonUtil.getRevocationInfoDTO(EntityRevocationInfoDTO.class, caEntityRevocationInfoJSON);
            if (entityRevocationInfoDTO.getEntityName() == null || entityRevocationInfoDTO.getRevocationReason() == null) {
                logger.error("Error while preparing the entityRevocationInfoDTO. Invalid input.");
                return Response.status(INTERNAL_SERVER_ERROR).entity("Error while preparing the entityRevocationInfoDTO. Invalid input.").build();
            }
            final List<RevocationStatusDTO> revocationStatusDTOs = revocationRestResourceHelper.getRevokeStatusDTOList(entityRevocationInfoDTO, EntityType.CA_ENTITY);
            response = commonUtil.produceJsonResponse(revocationStatusDTOs);
        } catch (final IOException e) {
            logger.debug("Error occured while preparing the revocationStatusDTO in revokeCAEntity method ", e);
            logger.error("Error while preparing the revocationStatusDTO.");
            return Response.status(INTERNAL_SERVER_ERROR).entity("Error while preparing the revocationStatusDTO.").build();
        }

        logger.debug("End of revokeCAEntity method in RevocationRestService class");
        return response;
    }

    /**
     * This method is used to revoke all the valid Certificates of the given Entity.
     * 
     * @param entityRevocationInfoJSON
     *            It consists of entityName and revocationReason
     * @return Response is the rest response which contains JSON {@link RevocationStatusDTO} Object.
     *
     */
    @Path("/entities/entity/revocation")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeEntity(final String entityRevocationInfoJSON) {
        logger.debug("revokeEntity method in RevocationRestService class");
        Response response = null;

        try {

            final EntityRevocationInfoDTO entityRevocationInfoDTO = commonUtil.getRevocationInfoDTO(EntityRevocationInfoDTO.class, entityRevocationInfoJSON);
            if (entityRevocationInfoDTO.getEntityName() == null || entityRevocationInfoDTO.getRevocationReason() == null) {
                logger.error("Error while preparing the entityRevocationInfoDTO. Invalid input.");
                return Response.status(INTERNAL_SERVER_ERROR).entity("Error while preparing the entityRevocationInfoDTO. Invalid input.").build();
            }
            final List<RevocationStatusDTO> revocationStatusDTOs = revocationRestResourceHelper.getRevokeStatusDTOList(entityRevocationInfoDTO, EntityType.ENTITY);
            response = commonUtil.produceJsonResponse(revocationStatusDTOs);

        } catch (final IOException e) {
            logger.debug("Error occured while preparing the revocationStatusDTO in revokeEntity method ", e);
            logger.error("Error while preparing the revocationStatusDTO.");
            return Response.status(INTERNAL_SERVER_ERROR).entity("Error while preparing the revocationStatusDTO.").build();
        }

        logger.debug("End of revokeEntity method in RevocationRestService class");
        return response;
    }

    /**
     * This method is used to revoke CA Certificates which are identified with the given CertificateRevocationInfoDTO's
     * 
     * @param caCertificateRevocationInfoJSON
     *            It has serialNumber, subject, issuer and revocation reason
     * @return Response is the rest response which contains JSON {@link RevocationStatusDTO} Object.
     *
     */
    @Path("/certificates/caentity/revocation")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeCAEntityCertificates(final String caCertificateRevocationInfoJSON) {
        logger.debug("revokeCAEntityCertificates method in RevocationRestService class");
        Response response = null;

        try {
            final List<CertificateRevocationInfoDTO> certificateRevocationInfoDTOList = commonUtil.getRevocationInfoDTOList(CertificateRevocationInfoDTO.class, caCertificateRevocationInfoJSON);
            if (certificateRevocationInfoDTOList.isEmpty()) {
                logger.error("Error while preparing the certificateRevocationInfoDTO. Invalid input.");
                return Response.status(INTERNAL_SERVER_ERROR).entity("Error while preparing the certificateRevocationInfoDTO. Invalid input.").build();
            }
            final List<RevocationStatusDTO> revocationStatusDTOs = revocationRestResourceHelper.getRevokeStatusDTOList(certificateRevocationInfoDTOList, EntityType.CA_ENTITY);
            response = commonUtil.produceJsonResponse(revocationStatusDTOs);
        } catch (final JSONException e) {
            logger.debug("Error occured while preparing the revocationStatusDTO in revokeCAEntityCertificates method ", e);
            logger.error("Error while preparing the revocationStatusDTO. Invalid input.");
            return Response.status(INTERNAL_SERVER_ERROR).entity("Error while preparing the revocationStatusDTO. Invalid input.").build();
        } catch (final IOException e) {
            logger.debug("Error occured while preparing the revocationStatusDTO in revokeCAEntityCertificates method ", e);
            logger.error("Error while preparing the revocationStatusDTO.");
            return Response.status(INTERNAL_SERVER_ERROR).entity("Error while preparing the revocationStatusDTO.").build();
        }

        logger.debug("End of revokeCAEntityCertificates method in RevocationRestService class");
        return response;
    }

    /**
     * This method is used to revoke Entity Certificates which are identified with the given CertificateRevocationInfoDTO's
     * 
     * @param certificateRevocationInfoDTO
     *            It contains serialNumber,subject,issuer and revocation reason
     * @return Response is the rest response which contains JSON {@link RevocationStatusDTO} Object.
     *
     */
    @Path("/certificates/entity/revocation")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeEntityCertificates(final String entityCertificateRevocationInfoJSON) {
        logger.debug("revokeEntityCertificates method in RevocationRestService class");
        Response response = null;

        try {
            final List<CertificateRevocationInfoDTO> certificateRevocationInfoDTOList = commonUtil.getRevocationInfoDTOList(CertificateRevocationInfoDTO.class, entityCertificateRevocationInfoJSON);
            if (certificateRevocationInfoDTOList.isEmpty()) {
                logger.error("Error while preparing the certificateRevocationInfoDTO. Invalid input.");
                return Response.status(INTERNAL_SERVER_ERROR).entity("Error while preparing certificateRevocationInfoDTO. Invalid input.").build();
            }
            final List<RevocationStatusDTO> revocationStatusDTOs = revocationRestResourceHelper.getRevokeStatusDTOList(certificateRevocationInfoDTOList, EntityType.ENTITY);
            response = commonUtil.produceJsonResponse(revocationStatusDTOs);
        } catch (final JSONException e) {
            logger.debug("Error occured while preparing the revocationStatusDTO in revokeEntityCertificates method ", e);
            logger.error("Error while preparing the revocationStatusDTO. Invalid input.");
            return Response.status(INTERNAL_SERVER_ERROR).entity("Error while preparing the revocationStatusDTO. Invalid input.").build();
        } catch (final IOException e) {
            logger.debug("Error occured while preparing the revocationStatusDTO in revokeEntityCertificates method ", e);
            logger.error("Error while preparing the revocationStatusDTO.");
            return Response.status(INTERNAL_SERVER_ERROR).entity("Error while preparing the revocationStatusDTO.").build();
        }

        logger.debug("End of revokeEntityCertificates method in RevocationRestService class");
        return response;
    }

    /**
     * This method returns list of available revocationReasons.
     * 
     * @return a JSON Array containing the supported revocation reason.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/revocationreasons")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRevocationReasons() throws JsonProcessingException {

        logger.debug("Fetching the RevocationReasons");

        final String result = commonUtil.getRevocationReasons();

        logger.debug("RevocationReasons fetched. {}", result);

        return Response.status(Status.OK).entity(result).build();

    }
}
