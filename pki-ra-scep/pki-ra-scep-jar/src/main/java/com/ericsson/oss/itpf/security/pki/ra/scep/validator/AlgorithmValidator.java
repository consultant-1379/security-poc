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
package com.ericsson.oss.itpf.security.pki.ra.scep.validator;

import java.util.Enumeration;
import java.util.List;

import javax.cache.Cache;
import javax.inject.Inject;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.cache.annotation.NamedCache;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.FailureInfo;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepRequestData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;

/**
 * SupportedAlgorithmValidator validates the algorithm when a PKCSReq is sent from a SCEP client. The algorithms are present in the cache and when a given PKCSReq is received from SCEP client the oid
 * of the algorithm is validated with the algorithms oids present in the cache.
 * 
 * @author tcsanne
 *
 */

public class AlgorithmValidator {

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    @NamedCache("SupportedAlgorithmsCache")
    private Cache<String, List<String>> cache;

    /**
     * This method is used to read the digest algorithm from Signed Data and validate whether this digest algorithm is supported or not.
     * 
     * @param signedData
     *            is the ASN1 SingedData of PKCS7 message.
     * @throws SupportedAlgsNotFoundException
     *             is thrown when list of supported algorithms are not found in cache.
     * @throws BadRequestException
     *             is thrown when the required algorithm oid is null in the request.
     * @throws UnSupportedAlgException
     *             is thrown when the digest algorithm is not supported.
     */

    public void validateSignedDataDigestAlg(final SignedData signedData) throws SupportedAlgsNotFoundException, BadRequestException, UnSupportedAlgException {

        boolean isSupported = Boolean.FALSE;
        final ASN1Set signedDataDigestAlgSet = signedData.getDigestAlgorithms();
        final Enumeration<?> enumeration = signedDataDigestAlgSet.getObjects();
        String algorithmOID = null;
        if (enumeration.hasMoreElements()) {
            final DERSequence derSequenceAttr = (DERSequence) enumeration.nextElement();
            algorithmOID = derSequenceAttr.toArray()[0].toString();
            if (derSequenceAttr.size() > 0) {
                isSupported = isSupportedAlgorithm(algorithmOID, "Signed Data Digest", AlgorithmType.MESSAGE_DIGEST_ALGORITHM);
            }
        }

        if (!isSupported) {
            logger.error("Signed Data digest algorithm is not supported");
            systemRecorder.recordSecurityEvent("SCEP Client", "AlgorithmValidator", "Signed Data digest algorithm wiht oid " + algorithmOID + " is not supported", "Algorithm Validation",
                    ErrorSeverity.ERROR, "FAILURE");
            throw new UnSupportedAlgException(FailureInfo.BADALG.name());
        }
    }

    /**
     * This method returns the algorithm Oid value which is supported by the PKI Manager.
     * 
     * @param algorithmOid
     *            is the algrithmOid used at the time of preparing the request.
     * @param description
     *            is the description of the algorithm being validated.
     * @param AlgorithmType
     *            is the type algorithm supported by PKI system.
     * @return boolean value which specifies whether algorithm is supported or not.
     * @throws BadRequestException
     *             is thrown when the required algorithm oid is null in the request.
     * @throws SupportedAlgsNotFoundException
     *             is thrown when list of supported algorithms are not found in cache.
     */

    public boolean isSupportedAlgorithm(final String algorithmOid, final String description, final AlgorithmType algorithmType) throws BadRequestException, SupportedAlgsNotFoundException {

        logger.debug("algorithmOid " + algorithmOid);
        logger.debug("algorithmType " + algorithmType);
        final List<String> listOfAlgOid = cache.get(algorithmType.value());
        if (listOfAlgOid == null) {
            logger.error("Supported algorithms are not found in cache");
            systemRecorder.recordError("PKI_RA_SCEP.AlG_NOT_FOUND", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollment for End Entity", "Supported algorithms are not found in cache");
            throw new SupportedAlgsNotFoundException(ErrorMessages.REQUEST_PROCESS_FAILURE);
        }
        if (algorithmOid == null) {
            logger.error("Required " + description + " Algorithm oid is Null");
            systemRecorder.recordError("PKI_RA_SCEP.ALGORITHM_OID_NULL", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollment for End Entity", "Required " + description + " algorithm oid is Null");
            throw new BadRequestException(description + ErrorMessages.EMPTY_ALGORITHM);
        }
        boolean isSupportedAlg = Boolean.FALSE;
        logger.debug("List of supported algorithms for messageTye " + algorithmType + " are: " + listOfAlgOid.toString());
        if (listOfAlgOid.contains(algorithmOid)) {
            isSupportedAlg = Boolean.TRUE;
        }

        return isSupportedAlg;
    }

    /**
     * This method validates whether the signature algorithm used in Signed Data is supported or not.
     * 
     * @param signerInformation
     *            SignerInformation in Signed Data.
     * @param pkcs7ScepRequestData
     *            which holds the data of PKCSreq to be required to generate Response.
     * @throws SupportedAlgsNotFoundException
     *             is thrown when list of supported algorithms are not found in cache.
     * @throws BadRequestException
     *             is thrown if the algorithm OId is null.
     * @throws UnSupportedAlgException
     *             is thrown if the algorithm from the request message is not supported.
     */
    public void validateSignatureAlgorithm(final Pkcs7ScepRequestData pkcs7ScepRequestData) throws BadRequestException, SupportedAlgsNotFoundException, UnSupportedAlgException {

        final String digestAlgOid = pkcs7ScepRequestData.getSignerInformation().getDigestAlgOID();
        final String encryptAlgOid = pkcs7ScepRequestData.getSignerInformation().getEncryptionAlgOID();
        if ((digestAlgOid == null) && (encryptAlgOid == null)) {
            logger.error("Required Signature Algorithm oid is null in request with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                    + pkcs7ScepRequestData.getEndEntityName());
            systemRecorder.recordError(
                    "PKI_RA_SCEP.SIGNATURE_ALGORITHM_OID_NULL",
                    ErrorSeverity.ERROR,
                    "SCEP Client",
                    "SCEP Enrollment for End Entity",
                    "Required Signature Algorithm oid is null in request with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                            + pkcs7ScepRequestData.getEndEntityName());
            throw new BadRequestException(ErrorMessages.SIGNING_ALG_NOT_FOUND);
        }
        pkcs7ScepRequestData.setContentDigestAlgOid(digestAlgOid);
        pkcs7ScepRequestData.setEncryptDigestAlgOID(encryptAlgOid);
        logger.debug("Digest algorithm oid is: " + digestAlgOid + " Encryption algorithm oid is: " + encryptAlgOid);
        setSignatureAlgorithm(pkcs7ScepRequestData);
        if (!(isSupportedAlgorithm(digestAlgOid, "Signer Information Digest", AlgorithmType.MESSAGE_DIGEST_ALGORITHM) && isSupportedAlgorithm(encryptAlgOid, "Signer Information Encryption",
                AlgorithmType.ASYMMETRIC_KEY_ALGORITHM))) {
            logger.error("Signature algorithm in request with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName()
                    + " is not supported.");
            systemRecorder.recordSecurityEvent("SCEP Client", "AlgorithmValidator", "Signature algorithm in request with the transaction id :" + pkcs7ScepRequestData.getTransactionId()
                    + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName() + " is not supported.", "Algorithm Validation", ErrorSeverity.ERROR, "FAILURE");
            throw new UnSupportedAlgException(ErrorMessages.UNSUPPORTED_SIGNING_ALGORITHM);
        }

    }

    /**
     * This method is used to construct the signature algorithm from the given messageDigest and public key algorithms.
     * 
     * @param pkcs7ScepRequestData
     *            which holds the data of PKCSreq to be required to generate Response.
     */
    @Profiled
    private void setSignatureAlgorithm(final Pkcs7ScepRequestData pkcs7ScepRequestData) {
        final DefaultCMSSignatureAlgorithmNameGenerator cmsSignature = new DefaultCMSSignatureAlgorithmNameGenerator();
        pkcs7ScepRequestData.setSignatureAlgorithm(cmsSignature.getSignatureName(AlgorithmIdentifier.getInstance(pkcs7ScepRequestData.getContentDigestAlgOid()),
                AlgorithmIdentifier.getInstance(pkcs7ScepRequestData.getEncryptDigestAlgOid())));
    }
}
