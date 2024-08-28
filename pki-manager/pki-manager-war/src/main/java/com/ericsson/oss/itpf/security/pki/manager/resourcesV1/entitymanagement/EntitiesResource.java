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
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.entitymanagement;

import java.io.File;

import java.io.IOException;
import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.ReIssueType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.CAReIssueInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.CSRBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityCertificateOperationsHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.validator.input.InputValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.rest.common.KeyStoreHelper;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for re-key,re-new and revoke {@link Entity}, {@link CAEntity} objects.
 */
@Path("/1.0/")
public class EntitiesResource {

    @Inject
    PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private Logger logger;

    @Inject
    InputValidator filterValidation;

    @Inject
    EntityCertificateOperationsHelper entityCertificateOperationsHelper;

    @Inject
    CSRBuilder cSRBuilder;

    @Inject
    CommonUtil commonUtil;

    @Inject
    KeyStoreHelper keyStoreHelper;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method is for reissuing CA certificate with/without revocation.
     *
     * @param caReissueDTO
     *            The String which contains the necessary information for reissue.
     * @return a response object containing success/error message.
     * @throws IOException
     * @throws JsonProcessingException
     */
    @POST
    @Path("/entities/caentity/reissue")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response reissueCACertificate(final String caReissueInfo) throws JsonProcessingException, IOException {

        logger.debug("Reissue of CA {}", caReissueInfo);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.CAENTITY_REISSUE_MAPPER);

        final CAReissueDTO caReissueDTO = mapper.reader(CAReissueDTO.class).readValue(caReissueInfo);

        filterValidation.validateCAReissueDTO(caReissueDTO);

        final ReIssueType reIssueType = caReissueDTO.getReIssueType();

        final CAReIssueInfo caReIssueInfo = new CAReIssueInfo();
        caReIssueInfo.setName(caReissueDTO.getName());
        caReIssueInfo.setRevocationReason(caReissueDTO.getRevocationReason());

        final boolean revoke = caReissueDTO.getRevocationReason() != null ? true : false;
        final boolean rekey = caReissueDTO.isRekey();
        final boolean renew = !rekey;

        if (revoke && rekey) {
            pkiManagerEServiceProxy.getCaCertificateManagementService().rekeyCertificate(caReIssueInfo, reIssueType);
        } else if (revoke && renew) {
            pkiManagerEServiceProxy.getCaCertificateManagementService().renewCertificate(caReIssueInfo, reIssueType);
        } else if (rekey) {
            pkiManagerEServiceProxy.getCaCertificateManagementService().rekeyCertificate(caReissueDTO.getName(), reIssueType);
        } else if (renew) {
            pkiManagerEServiceProxy.getCaCertificateManagementService().renewCertificate(caReissueDTO.getName(), reIssueType);
        }

        logger.debug("Reissue of CA {} completed successfully", caReissueDTO.getName());

        return Response.status(Status.OK).entity(com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util.Constants.RE_ISSUE_COMPLETED).build();
    }

    /**
     * This method is for reissuing (rekey) entity certificate with/without revocation.
     *
     * @param entityReissueInfo
     *            The string which contains the necessary information for reissue.
     * @return download able file with certificate/s in given format
     * @throws IOException
     * @throws JsonProcessingException
     */

    // TODO: URl will be changed as part of TORF-103002.
    @POST
    @Path("/entities/entity/reissue")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response reissueEntityCertificate(final String entityReissueInfo) throws JsonProcessingException, IOException {

        logger.debug("Reissuing (rekey) Entity certificate  {}", entityReissueInfo);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_REISSUE_MAPPER);

        final EntityReissueDTO entityReissueDTO = mapper.reader(EntityReissueDTO.class).readValue(entityReissueInfo);

        filterValidation.validateEntityReissueDTO(entityReissueDTO);

        String resourceName = null;
        final String entityName = entityReissueDTO.getName();

        if (entityReissueDTO.getRevocationReason() != null) {
            pkiManagerEServiceProxy.getRevocationService().revokeEntityCertificates(entityName, entityReissueDTO.getRevocationReason(), null);
        }

        resourceName = entityCertificateOperationsHelper.rekeyEndEntityCertificate(entityReissueDTO);
        final File file = new File(Constants.TMP_DIR + Constants.FILE_SEPARATOR + resourceName);

        final Response response = Response.ok(commonUtil.getStreamingOutput(file), MediaType.APPLICATION_OCTET_STREAM).header("Content-Disposition", "attachment; filename=\"" + file.getName() + "\"")
                .build();

        if (file.exists()) {
            file.delete();
        }
        logger.debug("Successfully reissued certificate/s and given for download in {} format.", entityReissueDTO.getFormat());

        return response;
    }

    /**
     * This method is for reissuing (renew) entity certificate with/without revocation.
     *
     * This service must convert base64 encoded CSR data into DER encoded data and creates pkcs10CertificationRequest, The download starts directly after the certificate is generated successfully.
     *
     * @param keyStoreFileInfo
     *            String containing enityName, CSR base64 encoded data, chain to include full CA chain or not and download format and the password for jks download and revocationReason for revoke the
     *            end entity certificate or not.
     *
     * @throws IOException
     *             thrown in the event of corrupted data, or an incorrect structure.
     */

    // TODO: URl will be changed as part of TORF-103002.
    @POST
    @Path("/entities/reissue/csrupload")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response reissueCertificateWithCSR(final String keyStoreFileInfo) throws IOException {

        logger.debug("Reissuing (renew) Entity certificate {} ", keyStoreFileInfo);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.REISSUE_WITH_CSR_MAPPER);

        final KeyStoreFileDTO keyStoreFileDTO = mapper.reader(KeyStoreFileDTO.class).readValue(keyStoreFileInfo);

        filterValidation.validateFileDTO(keyStoreFileDTO);

        final byte[] data = Base64.decode(keyStoreFileDTO.getData());
        final CertificateRequest certificateRequest = cSRBuilder.generateCSR(new String(data));

        if (keyStoreFileDTO.getRevocationReason() != null) {
            pkiManagerEServiceProxy.getRevocationService().revokeEntityCertificates(keyStoreFileDTO.getName(), keyStoreFileDTO.getRevocationReason(),
                    null);
        }

        final Certificate certificate = pkiManagerEServiceProxy.getEntityCertificateManagementService().renewCertificate(keyStoreFileDTO.getName(), certificateRequest);
        final List<Certificate> certificates = entityCertificateOperationsHelper.getEntityCertificateChain(keyStoreFileDTO.getName(), keyStoreFileDTO.isChain(), certificate);

        final KeyStoreInfo keyStoreInfo = keyStoreHelper.createKeyStoreInfo(keyStoreFileDTO.getName(), keyStoreFileDTO.getFormat(), keyStoreFileDTO.getPassword(), keyStoreFileDTO.getName());
        final String resourceName = keyStoreHelper.createKeyStore(keyStoreInfo, certificates);

        final File file = new File(Constants.TMP_DIR + Constants.FILE_SEPARATOR + resourceName);
        final Response response = Response.ok(commonUtil.getStreamingOutput(file), MediaType.APPLICATION_OCTET_STREAM).header("Content-Disposition", "attachment; filename=\"" + file.getName() + "\"")
                .build();

        if (file.exists()) {
            file.delete();
        }
        logger.debug("Successfully reissued certificate/s and given for download in {} format.", keyStoreFileDTO.getFormat());

        return response;
    }

}
