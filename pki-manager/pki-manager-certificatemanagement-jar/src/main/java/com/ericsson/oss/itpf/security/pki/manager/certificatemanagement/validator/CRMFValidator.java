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

package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.POPOSigningKeyInput;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util.CertificateRequestParser;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;

/**
 * Class for validating subject/subjectAltName,issuerName,public key size and Proof-of-Possession for CRMF Request
 * 
 * @author xpranma
 */
public class CRMFValidator {

    // TODO Make use of sub classes here each specialized in validating the specific information, this comment will be addressed as part of TORF-59437
    // TODO Refactor CRMF design, this comment will be addressed as part of TORF-70743

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    /**
     * Method for validating the CRMF request.
     * 
     * @param certificateRequestMessage
     *            The CertificateRequestMessage object.
     * @param entity
     *            The Entity object.
     * @throws InvalidCertificateRequestException
     *             Thrown in case of given CRMF request is invalid.
     */
    public void validate(final CertificateRequestMessage certificateRequestMessage, final Entity entity) throws InvalidCertificateRequestException {

        validateSubjectAndSAN(certificateRequestMessage);
        validatePublickeySize(certificateRequestMessage);
        // validateIssuerName(certificateRequestMessage, entity);
        validatePOP(certificateRequestMessage);
    }

    /**
     * Validates Subject and SAN
     * 
     * @param certificateRequestMessage
     *            The CertificateRequestMessage object.
     * @throws InvalidCertificateRequestException
     *             Thrown in case of given CRMF request is invalid.
     */
    public void validateSubjectAndSAN(final CertificateRequestMessage certificateRequestMessage) throws InvalidCertificateRequestException {

        if (certificateRequestMessage.getCertTemplate().getSubject() != null
                && certificateRequestMessage.getCertTemplate().getSubject().getRDNs().length > 0
                || CertificateRequestParser.checkForSubjectAltName(certificateRequestMessage)) {
            return;
        }
        logger.error(ErrorMessages.CSR_SUBJECT_OR_SUBJECT_ALT_NAME_MANDATORY);
        throw new InvalidCertificateRequestException(ErrorMessages.CSR_SUBJECT_OR_SUBJECT_ALT_NAME_MANDATORY);
    }

    /**
     * Validates CRMF PublicKeySize against keysizes supported by the PKI Manager.
     * 
     * @param certificateRequest
     *            The CRMF request object.
     * @throws InvalidCertificateRequestException
     *             Thrown when the given publickey is invalid.
     */
    public void validatePublickeySize(final CertificateRequestMessage certificateRequest) throws InvalidCertificateRequestException {

        try {
            final SubjectPublicKeyInfo info = certificateRequest.getCertTemplate().getPublicKey();

            final PublicKey key = getPublicKey(info);

            Integer keySize = null;

            final Map<String, Object> attributes = new HashMap<String, Object>();

            if (key instanceof RSAPublicKey) {
                keySize = ((RSAPublicKey) key).getModulus().bitLength();
                attributes.put("name", key.getAlgorithm());
            } else if (key instanceof ECPublicKey) {
                keySize = ((ECPublicKey) key).getQ().getCurve().getFieldSize();
                attributes.put("name", Constants.ECDSA_ALGORITHM_NAME);
            }

            attributes.put("keySize", keySize);

            logger.info("keysize in the Request is {}", keySize);
            logger.info("Algorithm in the Request is {}", key.getAlgorithm());

            final List<AlgorithmData> algorithmData = persistenceManager.findEntitiesByAttributes(AlgorithmData.class, attributes);

            if (algorithmData.isEmpty() || !algorithmData.get(0).isSupported()) {
                logger.error(ErrorMessages.KEY_SIZE_NOT_SUPPORTED);
                throw new InvalidCertificateRequestException(ErrorMessages.KEY_SIZE_NOT_SUPPORTED);
            }
        } catch (final InvalidKeyException invalidKeyException) {
            logger.error(ErrorMessages.CSR_KEY_INVALID);
            throw new InvalidCertificateRequestException(ErrorMessages.CSR_KEY_INVALID, invalidKeyException);
        } catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(ErrorMessages.CSR_KEY_ALGORITHM_INVALID);
            throw new InvalidCertificateRequestException(ErrorMessages.CSR_KEY_ALGORITHM_INVALID, noSuchAlgorithmException);
        }
        return;
    }

    /**
     * Validates Issuer Name received from request against the IssuerName present in Entity.
     * 
     * @param certificateRequest
     *            The CRMF request object.
     * @param entity
     *            The Entity Object
     * @throws InvalidCSRException
     *             Thrown when the given IssuerName is invalid.
     * @throws EntityNotFoundException
     *             Thrown when entity is not found
     */
    public void validateIssuerName(final CertificateRequestMessage certificateRequest, final Entity entity)
            throws InvalidCertificateRequestException, CANotFoundException {

        final String IssuerCANameInEntity = entity.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName();
        final CAEntityData caEntityData = persistenceManager.findEntityByName(CAEntityData.class, IssuerCANameInEntity, Constants.CA_NAME_PATH);
        logger.debug("Issuer CAName in Entity is {}", IssuerCANameInEntity);

        if (caEntityData == null) {
            logger.error("Issuer CA {} not found", IssuerCANameInEntity);
            throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND);
        }

        final String issuerDNInRequest = certificateRequest.getCertTemplate().getIssuer().toString();
        final String caSubjectDN = caEntityData.getCertificateAuthorityData().getSubjectDN();

        logger.debug("Issuer DN in the Request is {}", issuerDNInRequest);
        logger.debug("Issuer SubjectDN in the Entity is {}", caSubjectDN);

        final boolean isValidIssuer = isDNMatched(caSubjectDN, issuerDNInRequest);
        if (!isValidIssuer) {
            logger.error(ErrorMessages.ISSUER_NAME_IS_NOT_MATCHED);
            throw new InvalidCertificateRequestException(ErrorMessages.ISSUER_NAME_IS_NOT_MATCHED);
        }
        return;
    }

    /**
     * Validates IssuerSubjectDN in Entity against the IssuerName received from request. This method returns true if issuerName in the request matches
     * with the issuerName in the Entity.
     * 
     * @param issuerSubjectDNFromEntity
     *            The issuerSubjectDNValue present in Entity
     * @param issuerDNInRequest
     *            The issuerName received from request.
     * @throws InvalidCSRException
     *             Thrown when the given IssuerName is invalid.
     */
    private boolean isDNMatched(final String issuerSubjectDNFromEntity, final String issuerDNInRequest) throws InvalidCertificateRequestException {
        List<Rdn> issuerDN = null, issuerSubjectDN = null;
        try {
            issuerDN = new LdapName(issuerDNInRequest).getRdns();
            issuerSubjectDN = new LdapName(issuerSubjectDNFromEntity).getRdns();
        } catch (final InvalidNameException exception) {
            logger.error("Invalid Name");
            throw new InvalidCertificateRequestException(exception.getMessage(), exception);

        }

        if (issuerDN.size() != issuerSubjectDN.size()) {
            return false;
        }
        final Set<Object> issuerDNSet = new HashSet<Object>();
        issuerDNSet.addAll(issuerDN);
        final Set<Object> issuerSubjectDNSet = new HashSet<Object>();
        issuerSubjectDNSet.addAll(issuerSubjectDN);

        return issuerDNSet.equals(issuerSubjectDNSet);
    }

    /**
     * Validates Proof-of-Possession present in CRMF Request.
     * 
     * @param certificateRequest
     *            The CRMF request object.
     * @throws InvalidCertificateRequestException
     *             Thrown when the given IssuerName is invalid.
     */
    public boolean validatePOP(final CertificateRequestMessage certificateRequest) throws InvalidCertificateRequestException {
        boolean isPOPValid = false;

        final CertReqMsg certReqMsg = certificateRequest.toASN1Structure();
        final CertRequest req = certReqMsg.getCertReq();
        final ProofOfPossession pop = certReqMsg.getPopo();
        final X500Name subjectDN = req.getCertTemplate().getSubject();
        final SubjectPublicKeyInfo publicKeyInfo = req.getCertTemplate().getPublicKey();

        final POPOSigningKey poposk = POPOSigningKey.getInstance(pop.getObject());

        final POPOSigningKeyInput popoSigningKeyInput = poposk.getPoposkInput();
        ASN1Encodable protectedObject = popoSigningKeyInput;
        ByteArrayOutputStream byteArrayOutputStream = null;

        try {
            if (popoSigningKeyInput == null) {
                protectedObject = certReqMsg.getCertReq();
            } else {
                protectedObject = getProtectedObject(subjectDN, popoSigningKeyInput, protectedObject, publicKeyInfo);
            }

            if (protectedObject != null) {
                byteArrayOutputStream = new ByteArrayOutputStream();
                ASN1OutputStream.create(byteArrayOutputStream, ASN1Encoding.DER).writeObject(protectedObject);
                final byte[] protBytes = byteArrayOutputStream.toByteArray();
                final AlgorithmIdentifier algId = poposk.getAlgorithmIdentifier();
                final Signature sig = Signature.getInstance(algId.getAlgorithm().getId());
                sig.initVerify(getPublicKey(publicKeyInfo));
                sig.update(protBytes);
                final DERBitString bs = poposk.getSignature();
                isPOPValid = sig.verify(bs.getBytes());
            }
        } catch (final InvalidKeyException invalidKeyException) {
            logger.error(ErrorMessages.CSR_KEY_INVALID);
            throw new InvalidCertificateRequestException(ErrorMessages.CSR_KEY_INVALID, invalidKeyException);
        } catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(ErrorMessages.CSR_KEY_ALGORITHM_INVALID);
            throw new InvalidCertificateRequestException(ErrorMessages.CSR_KEY_ALGORITHM_INVALID, noSuchAlgorithmException);
        } catch (final IOException ioException) {
            logger.error(ErrorMessages.CSR_ENCODING_FAILED);
            throw new InvalidCertificateRequestException(ErrorMessages.CSR_ENCODING_FAILED, ioException);
        } catch (final SignatureException signatureException) {
            logger.error(ErrorMessages.CSR_SIGNATURE_INVALID);
            throw new InvalidCertificateRequestException(ErrorMessages.CSR_SIGNATURE_INVALID, signatureException);
        } finally {
            closeOutStream(byteArrayOutputStream);
        }
        return isPOPValid;
    }

    private void closeOutStream(final ByteArrayOutputStream byteArrayOutputStream) {
        if (byteArrayOutputStream != null) {
            try {
                byteArrayOutputStream.close();
            } catch (final IOException e) {
                logger.error(ErrorMessages.CSR_ENCODING_FAILED);
                throw new InvalidCertificateRequestException(ErrorMessages.CSR_ENCODING_FAILED, e);
            }
        }
    }

    private ASN1Encodable getProtectedObject(final X500Name subjectDN, final POPOSigningKeyInput popoSigningKeyInput, ASN1Encodable protectedObject,
            final SubjectPublicKeyInfo publicKeyInfo) throws IOException {

        if (subjectDN != null && !subjectDN.toString().equals(popoSigningKeyInput.getSender().getName().toString())) {
            protectedObject = null;
        }
        if (publicKeyInfo != null && !Arrays.equals(publicKeyInfo.getEncoded(), popoSigningKeyInput.getPublicKey().getEncoded())) {
            protectedObject = null;
        }

        return protectedObject;
    }

    /**
     * This method is used to get PublicKey from SubjectPublicKeyInfo Object.
     * 
     * @param subjectPKInfo
     *            The SubjectPublicKeyInfo request object.
     * @throws NoSuchAlgorithmException
     *             Thrown when the given algorithm is invalid.
     * @throws InvalidKeyException
     *             Thrown when the given publickey is invalid
     * @throws InvalidCertificateRequestException
     *             Thrown when the given IssuerName is invalid.
     */
    private PublicKey getPublicKey(final SubjectPublicKeyInfo subjectPKInfo)
            throws NoSuchAlgorithmException, InvalidKeyException, InvalidCertificateRequestException {

        PublicKey publicKey = null;
        try {
            final X509EncodedKeySpec xspec = new X509EncodedKeySpec(new DERBitString(subjectPKInfo).getBytes());
            final AlgorithmIdentifier keyAlgorithm = subjectPKInfo.getAlgorithm();

            publicKey = KeyFactory.getInstance(keyAlgorithm.getAlgorithm().getId(), Security.getProvider(Constants.PROVIDER_NAME))
                    .generatePublic(xspec);

        } catch (final IOException ioException) {
            logger.error(ErrorMessages.CSR_ENCODING_FAILED);
            throw new InvalidCertificateRequestException(ErrorMessages.CSR_ENCODING_FAILED, ioException);
        } catch (final InvalidKeySpecException invalidKeySpecException) {
            logger.error(ErrorMessages.CSR_KEY_INVALID);
            throw new InvalidCertificateRequestException(ErrorMessages.CSR_KEY_INVALID, invalidKeySpecException);
        }
        return publicKey;
    }
}
