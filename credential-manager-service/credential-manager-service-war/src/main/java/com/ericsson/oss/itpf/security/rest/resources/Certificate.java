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
package com.ericsson.oss.itpf.security.rest.resources;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.credmservice.api.CredMRestAvailability;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.CredMServiceWeb;
import com.ericsson.oss.itpf.security.credmservice.api.PKIDbFactory;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateExsitsException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateGenerationException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidCSRException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.credmservice.api.rest.model.GetCertificateRequest;
import com.ericsson.oss.itpf.security.credmservice.api.rest.model.GetCertificateResponse;

@Path("/1.0/certificate")
@RequestScoped
public class Certificate {

    @Inject
    private Logger logger;

    @EServiceRef
    private CredMService credMService;

    @Inject
    CredMRestAvailability credMPkiConfBean;

    @EServiceRef
    private CredMServiceWeb credmServiceWeb;

    @POST
    @Path("/issue")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces({ MediaType.APPLICATION_JSON })
    public Response getCertificate(final GetCertificateRequest certificateRequest) {
        logger.info("(POST) issueCertificate called");
        Response response = null;
        if (credMPkiConfBean.isEnabled()) {
            try {
                final PKCS10CertificationRequest certRequest = new PKCS10CertificationRequest(
                        DatatypeConverter.parseBase64Binary(certificateRequest.getCsrEncoded()));

                final CredentialManagerPKCS10CertRequest csr = new CredentialManagerPKCS10CertRequest(certRequest);

                final X500Name entity500Name = csr.getRequest().getSubject();
                final X509Name entity509Name = new X509Name(entity500Name.toString());
                final String entityName = "CN=" + entity509Name.getValues(X509Name.CN).get(0);
                // added chain to credmAPI certificate in order to manage rekey of CAs certificate
                final CredentialManagerX509Certificate[] getCertificateResponse = credMService.getCertificate(csr, entityName, true, null);

                final GetCertificateResponse certificateResponse = new GetCertificateResponse(getCertificateResponse);
                response = Response.ok().entity(certificateResponse).build();
            } catch (final IOException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerCertificateEncodingException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerEntityNotFoundException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerCertificateGenerationException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerInvalidCSRException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerInvalidEntityException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerCertificateExsitsException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            }
        } else {
            logger.info("credMPkiConfBean is not yet enabled");
            response = Response.status(Status.SERVICE_UNAVAILABLE).entity("credMPkiConfBean is not yet enabled").build();
        }
        return response;
    }

    @Inject
    PKIDbFactory pKIDbFactory;

    @GET
    @Path("/test")
    @Produces({ MediaType.APPLICATION_JSON })
    public Response getCertificateTest() {
        logger.info("(GET) getcertificateTest called");
        try {
            pKIDbFactory.importExtCaCertificate();

        } catch (final Exception e) {

            // TODO Auto-generated catch block
            e.printStackTrace();
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("pKIDbFactory.importExtCaCertificate receives exception").build();
        }
        return Response.ok().build();
    }

    @POST
    @Path("/reissue")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response getReissueCertificate(final List<String> serviceList) {
        logger.info("(POST) reissueCertificate called");

        if (credMPkiConfBean.isEnabled()) {
            if ((serviceList == null) || serviceList.isEmpty()) {
                return Response.status(Status.BAD_REQUEST).entity("At least a service name should be present").build();
            }

            Set<CredentialManagerEntity> serviceSet;
            try {
                serviceSet = credmServiceWeb.getServices();
            } catch (final CredentialManagerInternalServiceException e) {
                logger.error("{} during getServices", e.getMessage());
                return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
            }
            for (final String service : serviceList) {
                boolean serviceExists = false;
                for (final CredentialManagerEntity serviceEntity : serviceSet) {
                    if (serviceEntity.getName().equals(service) && ((serviceEntity.getEntityStatus() == CredentialManagerEntityStatus.ACTIVE)
                            || (serviceEntity.getEntityStatus() == CredentialManagerEntityStatus.REISSUE))) {
                        serviceExists = true;
                        break;
                    }
                }
                if (!serviceExists) {
                    logger.error("CredentialManagerEntityNotFoundException during reissueCertificateByService for service : " + service);
                    final String message = "Target Service does not exist.";
                    return Response.status(Status.BAD_REQUEST).entity(message).build();
                }
            }

            for (final String service : serviceList) {
                try {
                    credmServiceWeb.reissueCertificateByService(service);
                } catch (final CredentialManagerInternalServiceException | CredentialManagerEntityNotFoundException
                        | CredentialManagerInvalidEntityException ex) {
                    logger.error("{} during reissueCertificateByService for service : {} ", ex.getMessage(), service);
                    return Response.status(Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
                }
            }
        } else {
            logger.info("credMPkiConfBean is not yet enabled");
            return Response.status(Status.SERVICE_UNAVAILABLE).entity("credMPkiConfBean is not yet enabled").build();
        }
        return Response.ok().build();
    }

}
