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
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepRequest;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepResponse;
import com.ericsson.oss.itpf.security.pki.ra.scep.builder.GetCaCertChainResponseBuilder;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Constants;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Operation;
import com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice.CryptoService;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepResponseData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.BadRequestException;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException;
import com.ericsson.oss.itpf.security.pki.ra.scep.qualifier.RequestQualifier;

/**
 * This GetCaCertHandler class handles GetCaCertChain requests coming from Node and calls the GetCaCertChainResponseBuilder to build the response and sends it back to the Bean class.
 *
 * @author xramdag
 */

@RequestQualifier(Operation.GETCACERTCHAIN)
public class GetCaCertChainHandler implements RequestHandler {

    @Inject
    private Logger logger;

    @Inject
    private GetCaCertChainResponseBuilder getCaCertChainResponseBuilder;

    @Inject
    private PkiScepResponse pkiScepResponse;

    @Inject
    private CryptoService cryptoService;

    @Inject
    private Pkcs7ScepResponseData pkcs7ScepResponseData;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method handles the GetCaCertChain message. It reads caName from the pkiScepRequest and fetches certificate chain corresponding to that caName from key store/ trust store based on the flag
     * 'readFromTrustStore' in PkiScepRequest message.
     *
     * @param pkiScepRequest
     *            which contains caName as one of the parameters.
     * @return PKIScepResponse which contains PKCS#7 SignedData CertsOnly message and contentType.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * @throws BadRequestException
     *             is thrown if the alias name from the SCEP client is invalid.
     */
    @Override
    public PkiScepResponse handle(final PkiScepRequest pkiScepRequest) throws PkiScepServiceException, BadRequestException {

        logger.debug("In handle method of GetCaCertChainHandler class");
        systemRecorder.recordEvent("PKI_RA_SCEP.GET_CA_CERTIFICATE_CHAIN_REQUEST", EventLevel.COARSE, "PKIRASCEPService", "SCEP End Entity",
                "CA Certificate chain request has been received from End Entity for the CA Name :" + pkiScepRequest.getCaName());

        List<Certificate> certificateList = null;
        final Certificate[] certChain = cryptoService.readCertificateChain(pkiScepRequest.getCaName(), pkiScepRequest.isReadFromTrustStore());
        certificateList = cryptoService.getCertificateListFromChain(certChain, true);
        final byte[] response = getCaCertChainResponseBuilder.buildGetCaCertChainResponse(certificateList, pkcs7ScepResponseData);
        pkiScepResponse.setMessage(response);
        pkiScepResponse.setContentType(Constants.GETCACERTCHAIN_CONTENT_TYPE);
        logger.debug("End of handle method in GetCaCertChainHandler class");

        systemRecorder.recordEvent("PKI_RA_SCEP.GET_CA_CERTIFICATE_CHAIN_RESPONSE", EventLevel.COARSE, "PKIRASCEPService", "SCEP End Entity",
                "CA Certificate chain has been sent to End Entity sccessfully for the CA Name :" + pkiScepRequest.getCaName());
        return pkiScepResponse;

    }
}
