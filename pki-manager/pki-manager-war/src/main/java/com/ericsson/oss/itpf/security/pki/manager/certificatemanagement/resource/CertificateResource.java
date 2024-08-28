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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.resource;

import static com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util.Constants.*;
import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.CERTIFCATE_DOWNLOAD_FAILED;
import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.UNEXPECTED_ERROR;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.util.*;

import javax.ejb.EJB;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.filter.CertificateBasicDetailsDTO;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.filter.CertificateResponseDTO;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.CertificateResourceHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util.FilterMapper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.validator.input.InputValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.rest.exception.InvalidArgumentException;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.CertificateManagementServiceLocal;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.CommonUtil;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectWriter;

/**
 * Rest service for count , get and list the certificates.
 */
@Path("/")
public class CertificateResource {

    @EJB
    private CertificateManagementServiceLocal certificateManagementServiceLocal;

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;


    @Inject
    private ObjectMapperUtil objectMapperUtil;

    @Inject
    private Logger logger;

    @Inject
    private FilterMapper filterMapper;

    @Inject
    CommonUtil commonUtil;

    @Inject
    CertificateResourceHelper certificateResourceHelper;

    @Inject
    InputValidator filterValidation;

    @Inject
    FileUtility fileUtility;

    /**
     * This method is to apply the filter data and count the no of certificate rows matching with the filters based on the values set in {@link FilterDTO} object .
     * 
     * @param filterDTO
     *            The {@link FilterDTO} containing the filter data like subjectDN,entityType,expiryDateFrom,expiryDateTo,status and issuer.
     * 
     * @return JSON long object in Response.
     * 
     */
    @POST
    @Path("certificatelist/count")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response count(final FilterDTO filterDTO) throws InvalidArgumentException {

        logger.debug(" Retrieving certificates count ");

        long count = 0;

        if (filterValidation.validateFilterDTO(filterDTO)) {
            count = certificateManagementServiceLocal.getCertificateCount(filterMapper.toCertificateFilter(filterDTO));
        }

        logger.debug(" Certificate count {}", count);

        return Response.status(Status.OK).entity(count).build();
    }

    /**
     * This method is apply the filter data and fetch all the certificates matching with the filters based on the values set in {@link CertificateDTO} object.
     * 
     * @param certificateDTO
     *            The {@link CertificateDTO} containing filter data like offset,limit and filterDTO object which contains subjectDN,entityType,expiryDateFrom,expiryDateTo,status and issuer.
     * 
     * @return a JSON Array String containing the certificates.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @POST
    @Path("certificatelist/fetch")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch(final CertificateDTO certificateDTO) throws JsonProcessingException, InvalidArgumentException {

        logger.debug(" Fetching certificates ");

        final List<CertificateBasicDetailsDTO> certificateBasicDetailsList = new ArrayList<CertificateBasicDetailsDTO>();
        List<Certificate> certificates = new ArrayList<Certificate>();

        if (filterValidation.validate(certificateDTO)) {
            certificates = certificateManagementServiceLocal.getCertificates(filterMapper.toCertificateFilter(certificateDTO));
        }

        for (final Certificate certificate : certificates) {
            final CertificateBasicDetailsDTO certificateBasicDetailsDTO = certificateResourceHelper.getCertificateBasicDetailsList(certificate);
            certificateBasicDetailsList.add(certificateBasicDetailsDTO);
        }

        final Set<String> ignoreProperties = certificateResourceHelper.getIgnoredProperties(FETCH_RESPONSE_IGNORED_FIELDS);
        final ObjectWriter writer = objectMapperUtil.getCertficateSerializerMapper(ignoreProperties);
        final String result = writer.writeValueAsString(certificateBasicDetailsList);

        logger.debug("Certificate list  {}", result);

        return Response.status(Status.OK).entity(result).build();
    }

    /**
     * This method loads the certificate detail summary based on the values set in {@link certificateId} .
     * 
     * @param certificateId
     *            The id is certificateID
     * 
     * @return a JSON Array String containing the certificate details.
     * 
     * @throws CertificateParsingException
     *             thrown when any problem occurs while parsing the certificate.
     * 
     * @throws IOException
     *             thrown when any I/O errors occur.
     */
    @GET
    @Path("certificatelist/load/{id}")
    @Produces("application/json")
    public Response load(@PathParam("id") final String certificateId) throws CertificateParsingException, IOException {

        logger.debug(" Retrieving certificate details with id {} ", certificateId);

        String result = null;

        final Long[] certificateIds = new Long[] { Long.valueOf(certificateId) };

        final List<Certificate> certificates = certificateManagementServiceLocal.getCertificates(filterMapper.toCertificateFilterForLoad(certificateIds));

        if (certificates.size() > 0) {
            final Certificate certificate = certificates.get(0);
            final CertificateResponseDTO certificateResponseFilter = certificateResourceHelper.getCertificateResponse(certificate);

            final Set<String> ignoredProperties = certificateResourceHelper.getIgnoredProperties(LOAD_RESPONSE_IGNORED_FIELDS);
            final Set<String> extensionsFilterProperties = new HashSet<String>();
            final ObjectWriter writer = objectMapperUtil.getCertficateSerializerMapper(ignoredProperties, extensionsFilterProperties);

            result = writer.writeValueAsString(certificateResponseFilter);
        }

        logger.debug("Certificate details  {}", result);

        return Response.status(Status.OK).entity(result).build();
    }

    /**
     * This service must implement single/multiple certificate downloads.
     * 
     * @param downloadDTO
     *            DownloadDTO contains the attribute certificateIds to get the certificates and type to return a certificate with the given type/extension.
     * @return certificate with the given type/extension for single certificate. tar.gz files containing all the selected certificates each one with the given type/extension for multiple certificates.
     * @throws CertificateServiceException
     *             Thrown in case key store generation failures.
     */
    @POST
    @Path("certificate/download")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response download(final DownloadDTO downloadDTO) throws CertificateServiceException, InvalidArgumentException {

        logger.debug(" Download Certificate with the given id {}" + downloadDTO.getCertificateIds());
        File responseFile = null;
        try {

            filterValidation.validateDownloadDTO(downloadDTO);
            final List<Certificate> certList = certificateManagementServiceLocal.getCertificates(filterMapper.toCertificateFilter(downloadDTO));

            if (!certList.isEmpty()) {

                final File[] files = certificateResourceHelper.createKeyStoreForCertificates(downloadDTO, certList);

                if (certList.size() > 1) {
                    final String zipFilePath = Constants.TMP_DIR + Constants.FILE_SEPARATOR + CERTIFICATE_ZIP_FILE_NAME + System.currentTimeMillis() + CERTIFICATE_ZIP_FILE_EXTENSION;
                    responseFile = fileUtility.createArchiveFile(files, zipFilePath);
                    logger.debug("created {} tar.gz file containing all the selected certificates each one with the given type/extension" + responseFile.getName());
                    fileUtility.deleteFiles(files);
                } else {
                    responseFile = files[0];
                    logger.debug("Created certificate with the given type/extension {}" , responseFile);
                }
            }

            final Response response = Response.ok(commonUtil.getStreamingOutput(responseFile), MediaType.APPLICATION_OCTET_STREAM)
                    .header("Content-Disposition", "attachment; filename=\"" + responseFile.getName() + "\"").build();
            return response;
        } catch (IOException ioException) {
            logger.error(UNEXPECTED_ERROR, ioException);
            throw new CertificateServiceException(UNEXPECTED_ERROR + ioException.getMessage());
        } catch (final Exception exception) {
            logger.error(CERTIFCATE_DOWNLOAD_FAILED, exception);
            throw new CertificateServiceException(CERTIFCATE_DOWNLOAD_FAILED + exception.getMessage());
        } finally {
            if (responseFile != null) {
                responseFile.delete();
            }
        }
    }

    /**
     * This method is for summary of certificates issued by selected ca entity matching with the values set in {@link CertificateDTO} object .
     * 
     * @param certificateSummaryDTO
     *            The {@link CertificateSummaryDTO} containing the fields entityName and entityType.
     * 
     * @return JSON array object in Response.
     * @throws JsonProcessingException
     * 
     */
    @POST
    @Path("/certificatesummary/fetch")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response load(final CertificateSummaryDTO certSummaryDTO) throws JsonProcessingException {

        logger.info(" Retrieving certificate summary ");

        List<Certificate> certificates;
        final List<CertificateBasicDetailsDTO> certificateBasicDetailsList = new ArrayList<CertificateBasicDetailsDTO>();

        if (certSummaryDTO.getType() == EntityType.CA_ENTITY) {
            certificates = pkiManagerEServiceProxy.getCaCertificateManagementService().listCertificates_v1(certSummaryDTO.getName(), CertificateStatus.values());
        } else {
            certificates = pkiManagerEServiceProxy.getEntityCertificateManagementService().listCertificates_v1(certSummaryDTO.getName(), CertificateStatus.values());
        }

        certificateResourceHelper.getLatestCertificatesForSummary(certificates);

        for (final Certificate certificate : certificates) {
            final CertificateBasicDetailsDTO certificateBasicDetailsDTO = certificateResourceHelper.getCertificateBasicDetailsList(certificate);
            certificateBasicDetailsList.add(certificateBasicDetailsDTO);
        }

        final Set<String> ignoreProperties = certificateResourceHelper.getIgnoredProperties(CERTIFICATE_SUMMARY_RESPONSE_IGNORED_FIELDS);

        final ObjectWriter writer = objectMapperUtil.getCertficateSerializerMapper(ignoreProperties);

        final String result = writer.writeValueAsString(certificateBasicDetailsList);

        logger.debug("Certificates Summary  {}", result);

        return Response.status(Status.OK).entity(result).build();
    }
}
