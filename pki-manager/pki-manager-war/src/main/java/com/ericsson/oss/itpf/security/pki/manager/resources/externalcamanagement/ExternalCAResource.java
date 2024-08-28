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
package com.ericsson.oss.itpf.security.pki.manager.resources.externalcamanagement;

import java.io.ByteArrayInputStream;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util.Base64Reader;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.helper.CRLDownloader;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * Rest service for loading, updating and saving a {@link ExtCA}.
 * 
 * 
 */
@Path("/extca")
public class ExternalCAResource {

    @Inject
    private Logger logger;

    @Inject
    PKIManagerEServiceProxy pkiManagerEServiceProxy;


    /**
     * This method loads the {@link ExtCA} with given ID.
     * 
     * @param id
     *            ID of the CA entity to be fetched.
     * 
     * @return CAEntity object with the given ID.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/load/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response load(@PathParam("id") final int id) throws JsonProcessingException {

        logger.debug("Fetching External CA with ID {}.", id);

        return Response.status(Status.OK).build();
    }

    /**
     * This methods creates the given {@link ExtCA}
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     * @throws IOException
     *             thrown when any I/O errors occur.
     * 
     */
    @POST
    @Path("/save")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response save(final String caEntityJSON) throws JsonProcessingException, IOException {

        logger.debug("Save ExtCA certificate ");

        return Response.status(Status.OK).build();

    }

    /**
     * This methods updates the given {@link ExtCA}
     * 
     * @param parameters
     *            String urlPath.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     * @throws IOException
     *             thrown when any I/O errors occur.
     * 
     */
    @PUT
    @Path("/update/url/{name}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response update(@PathParam("name") final String extCAname, final String urlPath) throws JsonProcessingException, IOException {

        if (extCAname == null || extCAname.isEmpty()) {

            return Response.status(Status.INTERNAL_SERVER_ERROR).build();
        }
        if (urlPath == null) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).build();
        }
        logger.debug("Updating External CA {}.", extCAname);

        final ExternalCRLInfo crl = new ExternalCRLInfo();

        crl.setUpdateURL(urlPath);
        try {
            final URL url = new URL(urlPath);
            final X509CRL x509CRL = CRLDownloader.getCRLFromURL(url);
            crl.setX509CRL(new X509CRLHolder(x509CRL.getEncoded()));
        } catch (final CRLException e) {
            logger.debug("Error occured while updating Certificate Revocation List ", e);
            return Response.status(Status.INTERNAL_SERVER_ERROR).build();
        } catch (MalformedURLException ex) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).build();
        }
        try {
            pkiManagerEServiceProxy.getExtCACRLManagementService().addExternalCRLInfo(extCAname, crl);
        } catch (final MissingMandatoryFieldException e) {
            logger.debug("Error occured due to missing mandatory field in External CRL Info ", e);
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        } catch (final ExternalCRLException e) {
            logger.debug("Error occured while updating CRL Info to External CRL ", e);
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        } catch (final ExternalCANotFoundException e) {
            logger.debug("Error occured while updating CRL Info as External CA not found ", e);
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        } catch (final ExternalCredentialMgmtServiceException e) {
            logger.debug("Error occured while updating External Credentials ", e);
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        } catch (final Exception e) {
            logger.debug("Error occured in update External CA ", e);
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        }

        logger.debug("Successfully updated External CA {}.", extCAname);

        return Response.status(Status.OK).build();
    }

    /**
     * This methods updates the given {@link ExtCA}
     * 
     * @param parameters
     *            CRL file InputStream.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     * @throws IOException
     *             thrown when any I/O errors occur.
     * 
     */
    @PUT
    @Path("/update/crlfile/{name}")
    @Consumes(MediaType.APPLICATION_OCTET_STREAM)
    public Response updateByCrlFile(@PathParam("name") final String extCAname, final InputStream is) throws JsonProcessingException, IOException {

        if (extCAname == null) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).build();
        }
        if (is == null) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).build();
        }
        logger.debug("Updating External CA {}.", extCAname);

        final ExternalCRLInfo crl = new ExternalCRLInfo();
        try {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            final X509CRL x509CRL = (X509CRL) certificateFactory.generateCRL(is);
            crl.setX509CRL(new X509CRLHolder(x509CRL.getEncoded()));
        } catch (final CRLException | CertificateException e) {
            logger.debug("Error occured while updating Certificate using CRL File ", e);
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        }
        try {
            pkiManagerEServiceProxy.getExtCACRLManagementService().addExternalCRLInfo(extCAname, crl);
        } catch (final MissingMandatoryFieldException e) {
            logger.debug("Error occured due to missing mandatory field in External CRL Info using CRL file ", e);
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        } catch (final ExternalCRLException e) {
            logger.debug("Error occured while updating CRL Info to External CRL using CRL file ", e);
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        } catch (final ExternalCANotFoundException e) {
            logger.debug("Error occured while updating CRL Info as External CA not found using the CRL file ", e);
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        } catch (final ExternalCredentialMgmtServiceException e) {
            logger.debug("Error occured while updating External Credentials using CRL file ", e);
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        } catch (final Exception e) {
            logger.debug("Error occured while updating External CA certificate using CRL file ", e);
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        }

        logger.debug("Successfully updated External CA {}.", extCAname);

        return Response.status(Status.OK).build();
    }

    /**
     * This methods imports the given certificate related to the ExtCA name
     * 
     * @param parameters
     *            octect stream .
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     * @throws IOException
     *             thrown when any I/O errors occur.
     * 
     */
    @PUT
    @Path("/import/{name}/{isissueravailable}")
    @Consumes(MediaType.APPLICATION_OCTET_STREAM)
    public Response extCAImport(@PathParam("name") String extCAname, final @PathParam("isissueravailable") String isIssuerAvailable, final InputStream is) throws JsonProcessingException, IOException {
        if (is == null) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).build();
        }

        logger.info("Importing External CA {}.", extCAname);

        final Base64Reader br = new Base64Reader();

        Certificate pemCertificate = null;
        try {
            pemCertificate = br.getCertificate(is);
        } catch (final com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException e) {
            logger.debug("Error occured in Certificate {}", e);
            logger.info("Certificate Exception {}", e.getMessage());
            return Response.status(Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
        if (pemCertificate == null) {
            logger.info("pemCertificate NULL.");
            return Response.status(Status.INTERNAL_SERVER_ERROR).build();
        }

        CertificateFactory certFactory;
        X509Certificate certificate = null;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
            final InputStream inputStream = new ByteArrayInputStream(pemCertificate.getEncoded());
            certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
        } catch (final java.security.cert.CertificateException e) {
            logger.debug("Error occured while generating the Certificate ", e);
            logger.info("Certificate Exception {}", e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        }

        if (extCAname == null || extCAname.isEmpty()) {
            extCAname = certificate.getSubjectDN().getName();
        }
        try {

            if (Boolean.valueOf(isIssuerAvailable)) {
                pkiManagerEServiceProxy.getExtCaCertificateManagementService().importCertificate(extCAname, certificate, false);
            } else {
                pkiManagerEServiceProxy.getExtCaCertificateManagementService().forceImportCertificate(extCAname, certificate, false);
            }
        } catch (final CertificateAlreadyExistsException | ExternalCAAlreadyExistsException | CertificateFieldException ex) {
            logger.debug("Error occured either Certificate/ExternalCA/CertificateField already exists ", ex);
            logger.info("BAD REQUEST message {} cause {}", ex.getMessage(), ex.getCause());
            return Response.status(Status.BAD_REQUEST).entity(ex.getMessage()).build();
        } catch (final Exception ex) {
            logger.debug("Error occured while importing ExternalCA Certificate ", ex);
            logger.info("Exception {}", ex.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
        }
        return Response.status(Status.OK).build();
    }
}
