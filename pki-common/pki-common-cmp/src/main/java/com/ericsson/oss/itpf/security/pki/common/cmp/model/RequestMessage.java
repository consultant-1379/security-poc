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
package com.ericsson.oss.itpf.security.pki.common.cmp.model;

import java.io.IOException;
import java.io.Serializable;
import java.security.cert.*;
import java.util.HashSet;
import java.util.Set;

import javax.naming.InvalidNameException;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.PKIMessageUtil;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateParseException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidCertificateVersionException;

/**
 * This class sets all the requiredFields for a requestMessage also contains setters and getters.
 * 
 * @author tcsramc
 * 
 */
public class RequestMessage implements Serializable {

    private static final Logger logger = LoggerFactory.getLogger(RequestMessage.class);

    private static final long serialVersionUID = -5873049226492368477L;
    private int requestType;
    private int certRequestId;
    private String senderName;
    private String subjectName;
    private String recipientName;
    private byte[] protectionBytes;
    private byte[] encodedProtection;
    private AlgorithmIdentifier protectionAlgorithm;
    private String senderNonce;
    private String receipientNonce = null;
    private String base64TransactionID = null;
    private String protectionAlgorithmObjID = null;
    private boolean syncRequest = false;

    private X509Certificate userCertificate = null;
    private Set<X509Certificate> certChainSet = null;

    private PKIMessage pKIMessage = null;

    private String issuerName = null;

    /**
     * This Constructor extracts the PKIMessage fields and sets to RequestMessage.
     * 
     * @param inputByteArray
     *            Byte array from which PKIMessage is extracted
     * @throws IOException
     *             is thrown when any I/O exception occurs during encoding
     * @throws MessageParsingException
     *             is thrown if any parsing error occurs
     * @throws CertificateParseException
     *             is thrown if any certificate parsing errors occurs
     * @throws InvalidCertificateVersionException
     *             is thrown if version is not supported
     */
    public RequestMessage(final byte[] inputByteArray) throws IOException, MessageParsingException, CertificateParseException, InvalidCertificateVersionException {
        pKIMessageFromByteArray(inputByteArray);
        requestType = pKIMessage.getBody().getType();
        certRequestId = PKIMessageUtil.getRequestId(pKIMessage);
        senderName = pKIMessage.getHeader().getSender().getName().toString();
        if (requestType == PKIBody.TYPE_INIT_REQ || requestType == PKIBody.TYPE_KEY_UPDATE_REQ) {
            subjectName = CertificateUtility.fetchSubjectNameFromPKIMessage(pKIMessage);
            if (senderName.isEmpty()) {
                senderName = CertificateUtility.fetchSubjectNameFromPKIMessage(pKIMessage);
            }
        }
        recipientName = pKIMessage.getHeader().getRecipient().getName().toString();
        constructBase64TransactionID();

        protectionBytes = pKIMessage.getProtection().getBytes();
        encodedProtection = new ProtectedPart(pKIMessage.getHeader(), pKIMessage.getBody()).getEncoded();
        protectionAlgorithm = pKIMessage.getHeader().getProtectionAlg();
        extractUserCertAndCertChains();

        if (this.pKIMessage.getHeader().getProtectionAlg() != null) {
            protectionAlgorithmObjID = pKIMessage.getHeader().getProtectionAlg().getAlgorithm().getId();
        }

        if (this.pKIMessage.getHeader().getSenderNonce() != null) {
            senderNonce = new String(Base64.encode(this.pKIMessage.getHeader().getSenderNonce().getOctets()));
        }
        if (this.pKIMessage.getHeader().getRecipNonce() != null) {
            receipientNonce = new String(Base64.encode(this.pKIMessage.getHeader().getRecipNonce().getOctets()));
        }

    }


    /**
     * returns certificate
     * 
     * @return
     */
    public X509Certificate getUserCertificate() {
        return userCertificate;
    }

    /**
     * returns chainset
     * 
     * @return
     */
    public Set<X509Certificate> getCertChainSet() {
        return this.certChainSet;
    }

    /**
     * returns algorithmId
     * 
     * @return
     */
    public String getProtectionAlgorithmID() {
        return this.protectionAlgorithmObjID;
    }

    /**
     * returns AlgorithmIdentifier
     * 
     * @return
     */
    public AlgorithmIdentifier getProtectAlgorithm() {
        return this.protectionAlgorithm;
    }

    /**
     * returns PV number
     * 
     * @return
     */
    public String getPvNumber() {
        return this.pKIMessage.getHeader().getPvno().getValue().toString();
    }

    /**
     * returns byte array
     * 
     * @return
     */
    public byte[] getProtectionBytes() {
        return this.protectionBytes;
    }

    /**
     * returns requesttype
     * 
     * @return
     */
    public int getRequestType() {
        return this.requestType;
    }

    /**
     * returns recipientname
     * 
     * @return
     */
    public String getRecipientName() {
        return this.recipientName;
    }

    /**
     * returns sendername
     * 
     * @return
     */
    public String getSenderName() {
        return this.senderName;
    }

    public void setSenderName(final String senderName) {
        this.senderName = senderName;
    }

    /**
     * returns commonName
     * 
     * @return
     */
    public String getSubjectName() {
        return this.subjectName;
    }

    public void setSubjectName(final String subjectName) {
        this.subjectName = subjectName;
    }

    /**
     * returns recipientNonce
     * 
     * @return
     */
    public String getRecepientNonce() {
        return this.receipientNonce;
    }

    /**
     * returns requestMessage
     * 
     * @return
     */
    public String getRequestMessage() {
        return PKIMessageUtil.convertRequestTypeToString(this.requestType);
    }

    /**
     * sets transactionID
     * 
     * @param transactionId
     *            value to set
     */
    public void setBase64TransactionID(final String transactionId) {
        this.base64TransactionID = transactionId;
    }

    /**
     * returns pkimessage
     * 
     * @return
     */
    public PKIMessage getPKIMessage() {
        return pKIMessage;
    }

    /**
     * returns PKIHeader
     * 
     * @return
     */
    public PKIHeader getPKIHeader() {
        return pKIMessage.getHeader();
    }

    /**
     * returns PKIBody
     * 
     * @return PKIBody of the PKIMessage
     */
    public PKIBody getPKIBody() {
        return pKIMessage.getBody();
    }

    /**
     * returns RequestId
     * 
     * @return certificate Request ID
     */
    public int getRequestId() {
        return certRequestId;
    }

    /**
     * @return the syncRequest
     */
    public boolean isSyncRequest() {
        return syncRequest;
    }

    /**
     * @param syncRequest
     *            the syncRequest to set
     */
    public void setSyncRequest(final boolean syncRequest) {
        this.syncRequest = syncRequest;
    }

    /**
     * returns byteArray
     * 
     * @return byte Array of the PKI Message
     */
    public byte[] toByteArray() throws MessageParsingException {
        byte[] convertedToByteArray = null;

        try {
            convertedToByteArray = pKIMessage.getEncoded();
        } catch (IOException ioException) {
            throw new MessageParsingException(ErrorMessages.IO_EXCEPTION, ioException);
        }
        return convertedToByteArray;

    }

    /**
     * returns byte array
     * 
     * @return byte array of protection part of PKIMessage
     */
    public byte[] getProtectionEncoded() {
        return encodedProtection;
    }

    /**
     * returns transactionId from the PKIMessage
     * 
     * @return transaction ID if is present in the PKI Message else returns null
     */
    public String getBase64TransactionID() {
        return base64TransactionID;
    }

    private void constructBase64TransactionID() {
        if (pKIMessage.getHeader().getTransactionID() != null) {
            final DEROctetString dos = (DEROctetString) (pKIMessage.getHeader().getTransactionID());
            base64TransactionID = new String(org.bouncycastle.util.encoders.Base64.encode(dos.getOctets()));
        }
    }

    /**
     * checks whether sender and recipient tags are in proper directory format or not, returns true if sender and recipient tag no are in proper format
     * 
     * @return true if it is in directory format else return false
     */
    public boolean isSenderNameInDirectoryFormat() {
        boolean isSenderinDirFormat = false;
        if (pKIMessage.getHeader().getSender().getTagNo() == GeneralName.directoryName && pKIMessage.getHeader().getRecipient().getTagNo() == GeneralName.directoryName) {
            isSenderinDirFormat = true;
        }
        return isSenderinDirFormat;
    }

    /**
     * Checks whether requestMessage is of MacBased or not based on algorithmId
     * 
     * @return true if it is mac based else false
     */
    public boolean isMacBased() {
        boolean iakToBeValidated = false;
        if (protectionAlgorithmObjID != null && protectionAlgorithmObjID.equals(IAKParameters.ALGORITHM_ID)) {
            iakToBeValidated = true;
        }
        return iakToBeValidated;
    }

    private void extractUserCertAndCertChains() throws MessageParsingException, CertificateParseException, InvalidCertificateVersionException {
        if (pKIMessage.getExtraCerts() != null) {
            certChainSet = new HashSet<>();
            boolean isUserCert = true;
            X500Name certSubjectName = null;
            CertificateFactory certificateFactory = null;

            try {
                certificateFactory = CertificateFactory.getInstance(Constants.X509);
                for (final CMPCertificate eachCert : pKIMessage.getExtraCerts()) {
                    if (!eachCert.isX509v3PKCert()) {
                        throw new InvalidCertificateVersionException(ErrorMessages.INVALID_CERTIFICATE_VERSION);
                    }
                    certSubjectName = eachCert.getX509v3PKCert().getSubject();
                    final String subjectCnfromCertificate = StringUtility.getCNfromDN(certSubjectName.toString());
                    final String senderNamefromRequest = StringUtility.getCNfromDN(senderName);

                    final X509Certificate certificate = convertInputStreamtoX509Certificate(certificateFactory, eachCert);
                    if (subjectCnfromCertificate.equals(senderNamefromRequest) && isUserCert) {
                        isUserCert = false;
                        userCertificate = certificate;
                    } else {
                        certChainSet.add(certificate);
                    }
                }
            } catch (IOException ioException) {
                throw new MessageParsingException(ErrorMessages.IO_EXCEPTION, ioException);

            } catch (CertificateException certificateException) {
                throw new CertificateParseException(ErrorMessages.CERTIFICATION_EXCEPTION, certificateException);

            } catch (InvalidNameException invalidNameException) {
                throw new MessageParsingException(ErrorMessages.INVALID_DN, invalidNameException);
            }
        }
    }

    private X509Certificate convertInputStreamtoX509Certificate(final CertificateFactory certificateFactory, final CMPCertificate eachCert) throws IOException, CertificateException {
        final X509Certificate x509Certificate;
        ASN1InputStream inputStream = null;
        try {
            inputStream = new ASN1InputStream(eachCert.getEncoded());
            x509Certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException ioexception) {
                    logger.error("Exception occured while closing the input stream in RequestMessage class");
                    logger.debug("Exception occured while closing the input stream in RequestMessage class ", ioexception);
                }
            }
        }
        return x509Certificate;
    }

    private void pKIMessageFromByteArray(final byte[] inputByteArray) throws MessageParsingException, IOException {
        final ASN1InputStream inputStream = new ASN1InputStream(inputByteArray);
        try {
            final ASN1Primitive rawMessage = inputStream.readObject();
            pKIMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(rawMessage));
        } catch (IOException ioException) {
            throw new MessageParsingException(ErrorMessages.IO_EXCEPTION, ioException);
        } finally {
            inputStream.close();
        }

    }

    /**
     * @return the senderNonce
     */
    public String getSenderNonce() {
        return senderNonce;
    }

    /**
     * @param requestType
     *            the requestType to set
     */
    public void setRequestType(final int requestType) {
        this.requestType = requestType;
    }

    /**
     * @param certRequestId
     *            the certRequestId to set
     */
    public void setCertRequestId(final int certRequestId) {
        this.certRequestId = certRequestId;
    }

    /**
     * @param recipientName
     *            the recipientName to set
     */
    public void setRecipientName(final String recipientName) {
        this.recipientName = recipientName;
    }

    /**
     * @param protectionBytes
     *            the protectionBytes to set
     */
    public void setProtectionBytes(final byte[] protectionBytes) {
        this.protectionBytes = protectionBytes;
    }

    /**
     * @param encodedProtection
     *            the encodedProtection to set
     */
    public void setEncodedProtection(final byte[] encodedProtection) {
        this.encodedProtection = encodedProtection;
    }

    /**
     * @param protectionAlgorithm
     *            the protectionAlgorithm to set
     */
    public void setProtectionAlgorithm(final AlgorithmIdentifier protectionAlgorithm) {
        this.protectionAlgorithm = protectionAlgorithm;
    }

    /**
     * @return the issuerName
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * @param issuerName
     *            the issuerName to set
     */
    public void setIssuerName(final String issuerName) {
        this.issuerName = issuerName;
    }

}
