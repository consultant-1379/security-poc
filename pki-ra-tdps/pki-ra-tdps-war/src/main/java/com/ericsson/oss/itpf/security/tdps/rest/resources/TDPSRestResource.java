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

package com.ericsson.oss.itpf.security.tdps.rest.resources;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.TrustDistributionParameters;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.eserviceref.EServiceHolder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionResourceNotFoundException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionServiceException;
import com.ericsson.oss.itpf.security.tdps.rest.exceptions.MissingMandatoryParamException;
import com.ericsson.oss.itpf.security.tdps.rest.validator.TrustDistributionParamsValidator;

@Path("/")
@Produces("application/pkix-cert")
public class TDPSRestResource {

    @Inject
    EServiceHolder eServiceHolder;

    @Inject
    TrustDistributionParamsValidator trustDistributionParamsValidator;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;
    private static final String SPACE_IN_URL = "%20";
    private static final String SPACE = " ";

    /**
     * @param entityType
     *            type of the entity whether ca or entity
     * @param entityName
     *            name of the entity
     * @param serialNo
     *            certificate serialNumber
     * @return
     * @throws TrustDistributionResourceNotFoundException
     *             thrown if the given url is not found
     * @throws IOException
     *             thrown when certificate to be encoded is having incorrect data
     * @throws MissingMandatoryParamException
     *             thrown in case entity type or name or serialNumber is not provided
     * @throws CertificateException
     *             thrown in the case where there is a problem in the certificate
     */
    @GET
    @Path("{EntityType}/{EntityName}/{CertificateSerialNumber}/{CertificateStaus}/{IssuerName}")
    public Response process(@PathParam("EntityType") final String entityType, @PathParam("EntityName")  String entityName, @PathParam("CertificateSerialNumber") final String serialNo,
            @PathParam("CertificateStaus") final String certificateStaus, @PathParam("IssuerName") String issuerName) throws IOException, CertificateException {

        if (entityName.contains(SPACE_IN_URL)) {
            entityName = entityName.replaceAll(SPACE_IN_URL, SPACE);
        }
        if (issuerName.contains(SPACE_IN_URL)) {
            issuerName = issuerName.replaceAll(SPACE_IN_URL, SPACE);
        }
        final TrustDistributionParameters trustDistributionParameters = (new TrustDistributionParameters()).setEntityType(entityType).setEntityName(entityName).setCertificateSerialId(serialNo)
                .setIssuerName(issuerName).setCertificateStatus(certificateStaus.toUpperCase());
        trustDistributionParamsValidator.validate(trustDistributionParameters);

        final byte[] trustCert = eServiceHolder.getTrustDistributionPointService().getCertificate(trustDistributionParameters);

        final String fileName = entityName.toUpperCase() + "_" + serialNo;
        final File certificate = writeCertificateToFile(fileName, trustCert);
        systemRecorder.recordEvent("TDPS_SERVICE.GET_TRUSTED_CERTIFICATES", EventLevel.COARSE, "Get Trusted Certificate",
                "Trusted Certificates of Entity which invoked TDPS", "TDPS_SERVICE.CERTIFICATE_REQUEST_FINISHED");
        return Response.ok((Object) certificate).header("Content-Disposition", "attachment; filename=\"" + certificate + "\"").build();

    }

    private File writeCertificateToFile(final String fileName, final byte[] certificateByteArray) throws TrustDistributionServiceException, IOException, CertificateException {
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        final X509Certificate x509cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateByteArray));
        final File certificate = File.createTempFile(fileName, ".crt");
        logger.info("Creating file in temp directory {} ", System.getProperty("java.io.tmpdir"));
        try(final JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(certificate))){
        writer.writeObject(x509cert);
        writer.flush();
        logger.info("Certificate file created");
        }
        return certificate;
    }
}