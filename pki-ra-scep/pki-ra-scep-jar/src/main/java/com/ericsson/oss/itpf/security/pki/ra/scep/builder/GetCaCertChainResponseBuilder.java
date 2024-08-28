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
package com.ericsson.oss.itpf.security.pki.ra.scep.builder;

import java.io.IOException;
import java.security.cert.Certificate;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepResponseData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException;

/**
 * GetCaCertChainResponseBuilder class is used to prepare response message for the GetCACertChain Request received. This class will call the super class method(createSignedData) to build the
 * GetCAcertChain response which is pkcs#7 certs only signedData message.
 *
 * @author xramdag
 */
public class GetCaCertChainResponseBuilder extends Pkcs7CmsSignedDataBuilder {
    @Inject
    private Logger logger;

    @Inject
    Pkcs7ScepResponseData pkcs7ScepResponseData;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method returns PKCS#7 SignedData CertsOnly message for the corresponding GetCACertChain request. This method accepts certificateList.
     *
     * @param certificateList
     *            Which is the list of certificates of the certificate chain.
     * @return byte[] Which contains PKCS#7 SignedData CertsOnly message.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while building the response.
     */

    @Profiled
    public byte[] buildGetCaCertChainResponse(final List<Certificate> certificateList, final Pkcs7ScepResponseData pkcs7ScepResponseData) throws PkiScepServiceException {
        logger.debug("createGetCaCertChainResponse method in GetCaCertChainResponseBuilder class");
        byte[] response = null;
        CMSSignedData cmsSigendData = null;
        try {
            pkcs7ScepResponseData.setCmsTypedData(new CMSAbsentContent());
            pkcs7ScepResponseData.setAddSignerInfo(false);
            pkcs7ScepResponseData.setCertificateList(certificateList);
            pkcs7ScepResponseData.setAttributes(null);
            pkcs7ScepResponseData.setEncapsulate(false);
            cmsSigendData = buildSignedData(pkcs7ScepResponseData);
            response = cmsSigendData.getEncoded();

        } catch (final IOException e) {
            logger.error("Caught IOException while encoding the CMSSigned data  : {}" , e.getMessage());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "GetCACertChainResponseBuilder", "Failure while building GetCACertChain Response", "SCEP Response Build", ErrorSeverity.ERROR,
                    "FAILURE");
            throw new PkiScepServiceException(ErrorMessages.GETCACERTCHAIN_RESP_FAILURE);
        } catch (PkiScepServiceException e) {
            logger.error("Failed to create GetCaCertChain Response");
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "GetCACertChainResponseBuilder", "Failure while building GetCACertChain Response", "SCEP Response Build", ErrorSeverity.ERROR,
                    "FAILURE");
            throw new PkiScepServiceException(ErrorMessages.GETCACERTCHAIN_RESP_FAILURE);
        }
        logger.debug("End of  createGetCACertChainResponse method of createGetCACertChainResponse class");
        return response;
    }

}
