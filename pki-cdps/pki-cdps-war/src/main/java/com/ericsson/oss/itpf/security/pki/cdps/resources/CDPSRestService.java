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
package com.ericsson.oss.itpf.security.pki.cdps.resources;

import java.io.*;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.recording.*;
import com.ericsson.oss.itpf.security.pki.cdps.api.CRLDistributionPointService;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.*;
import com.ericsson.oss.itpf.security.pki.cdps.common.constant.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CRLConversionException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLExpiredException;

/**
 * This class process the requested data from requested URL using caName and caCertSerialNumber
 * 
 * @author xjagcho
 *
 */
@Path("/")
public class CDPSRestService {

    @EServiceRef
    private CRLDistributionPointService crlDistributionPointService;

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method process the getCRL method request using caName and caCertSerialNumber as arguments as input
     * 
     * @param caName
     *            name of the CA which is the issuer of the CRL
     * @param caCertSerialNumber
     *            which is the certificate serial number of the CACertificate by which the CRL is issued
     * @return Response as CRL file to download
     * 
     * @throws CRLConversionException
     *             will be thrown in case of Failing in converting CRL byte array
     * @throws CRLDistributionPointServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * @throws CRLExpiredException
     *             will be thrown in case of CRL is expired.
     * @throws CRLNotFoundException
     *             will be thrown in case of CRL is not found.
     * @throws IOException
     *             will be thrown in case of FileOutputStream close failed.
     * @throws MissingMandatoryParamException
     *             will be thrown in case of input arguments are not there.
     */
    @GET
    @Path("/")
    @Produces("application/pkix-crl")
    public Response getCRL(@QueryParam("ca_name") final String caName, @QueryParam("ca_cert_serialnumber") final String caCertSerialNumber) throws CRLConversionException,
            CRLDistributionPointServiceException, CRLExpiredException, CRLNotFoundException, IOException, MissingMandatoryParamException {
        logger.debug("getCRL method in CDPSRestService class");

        if ((caName == null || caName.isEmpty())) {
            logger.error(ErrorMessages.ERR_EMPTY_CANAME);
            systemRecorder.recordError("PKI_CDPS.EMPTY_CA_NAME", ErrorSeverity.ERROR, "CRLClient", "CRLDownLoad", "CAName should not be empty in the URL to download CRL from CDPS.");

            throw new MissingMandatoryParamException(ErrorMessages.ERR_EMPTY_CANAME);
        }

        if ((caCertSerialNumber == null || caCertSerialNumber.isEmpty())) {
            logger.error(ErrorMessages.ERR_EMPTY_CACERTSERIALNUMBER);
            systemRecorder.recordError("PKI_CDPS.EMPTY_CACERTSERIALNUMBER", ErrorSeverity.ERROR, "CRLClient", "CRLDownLoad",
                    "CA Certificate Serial Number should not be empty in the URL to download CRL from CDPS.");

            throw new MissingMandatoryParamException(ErrorMessages.ERR_EMPTY_CACERTSERIALNUMBER);
        }

        final byte[] crlContent = getCRLContent(caName, caCertSerialNumber);
        final Response response = Response.ok((Object) crlContent).header("Content-Disposition", "attachment; filename=\"" + caName + "_" + caCertSerialNumber + ".crl" + "\"").build();

        logger.debug("End of getCRL method in CDPSRestService class");
        systemRecorder.recordEvent("PKI_CDPS.CRL_DOWNLOAD", EventLevel.COARSE, "CDPSService", "CRLClient", "Requested CRL file is downloaded from CDPS Service for the CAName " + caName
                + " and Certificate Serial Number :" + caCertSerialNumber);

        return response;
    }

    /**
     * This method process the write CRL To File using caName and caCertSerialNumber as arguments as input
     * 
     * @param caName
     *            name of the CA which is the issuer of the CRL
     * @param caCertSerialNumber
     *            which is the certificate serial number of the CACertificate by which the CRL is issued
     * @return Byte Array of CRL content
     * @throws CRLDistributionPointServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     */
    private byte[] getCRLContent(final String caName, final String caCertSerialNumber) throws CRLDistributionPointServiceException {
        logger.debug("getCRLContent method in CDPSRestService class");

        byte[] crlContent = crlDistributionPointService.getCRL(caName, caCertSerialNumber);
        if (StringUtility.isBase64(new String(crlContent))) {
            crlContent = Base64.decode(crlContent);
        }
        logger.debug("End of getCRLContent method in CDPSRestService class");

        return crlContent;
    }
}