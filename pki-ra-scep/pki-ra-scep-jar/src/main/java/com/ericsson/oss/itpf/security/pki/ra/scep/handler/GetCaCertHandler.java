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
package com.ericsson.oss.itpf.security.pki.ra.scep.handler;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepRequest;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepResponse;
import com.ericsson.oss.itpf.security.pki.ra.scep.builder.GetCaCertResponseBuilder;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Constants;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Operation;
import com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice.CryptoService;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepResponseData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.BadRequestException;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException;
import com.ericsson.oss.itpf.security.pki.ra.scep.instrumentation.SCEPInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.ra.scep.qualifier.RequestQualifier;

/**
 * This GetCaCertHandler class handles GetCaCert requests coming from SCEP client and calls the GetCaCertResponseBuilder to build the response. Implemented instrumentation for the GetCaCert requests
 * for SCEP DDC/DDP information
 *
 * @author xramdag
 */
@RequestQualifier(Operation.GETCACERT)
public class GetCaCertHandler implements RequestHandler {
    @Inject
    private Logger logger;

    @Inject
    private GetCaCertResponseBuilder getCaCertResponseBuilder;

    @Inject
    private PkiScepResponse pkiScepResponse;

    @Inject
    private CryptoService cryptoService;

    @Inject
    private Pkcs7ScepResponseData pkcs7ScepResponseData;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    SCEPInstrumentationBean scepInstrumentationBean;

    /**
     * This method handles and GetCACert message. It reads caName from the pkiScepRequest and fetches certificate chain corresponding to that caName from key store/ trust store based on the flag
     * 'readFromTrustStore' in PkiScepRequest message.
     *
     * @param pkiScepRequest
     *            which contains caName as one of the parameters.
     * @return PkiScepResponse Which contains PKCS#7 SignedData CertsOnly message and contentType.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * @throws BadRequestException
     *             is thrown when there is invalid CA name in the URL.
     */
    @Profiled
    @Override
    public PkiScepResponse handle(final PkiScepRequest pkiScepRequest) throws PkiScepServiceException, BadRequestException {
        logger.debug("In handle method of GetCaCertHandler class");
        scepInstrumentationBean.setEnrollmentInvocations();
        systemRecorder.recordEvent("PKI_RA_SCEP.GET_CA_CERTIFICATE_REQUEST", EventLevel.COARSE, "PKIRASCEPService", "SCEP Enrollment for End Entity",
                "CA Certificate request has been received from End Entity for the CA Name :" + pkiScepRequest.getCaName());
        List<Certificate> certificateList = new ArrayList<>();

        if (pkiScepRequest.isReadFromTrustStore()) {
            final Certificate certifiate = cryptoService.readCertificate(pkiScepRequest.getCaName(), pkiScepRequest.isReadFromTrustStore());
            certificateList.add(certifiate);
        } else {
            final Certificate[] certChain = cryptoService.readCertificateChain(pkiScepRequest.getCaName(), pkiScepRequest.isReadFromTrustStore());
            certificateList = cryptoService.getCertificateListFromChain(certChain, false);
        }
        final byte[] response = getCaCertResponseBuilder.buildGetCaCertResponse(certificateList, pkcs7ScepResponseData);
        pkiScepResponse.setMessage(response);
        pkiScepResponse.setContentType(Constants.GETCACERT_CONTENT_TYPE);
        logger.debug("End of handle method in GetCaCertHandler class");

        systemRecorder.recordEvent("PKI_RA_SCEP.GET_CA_CERTIFICATE_RESPONSE", EventLevel.COARSE, "PKIRASCEPService", "SCEP Enrollment for End Entity",
                "CA Certificate has been sent to End Entity successfully for the CA Name :" + pkiScepRequest.getCaName());
        return pkiScepResponse;
    }
}
