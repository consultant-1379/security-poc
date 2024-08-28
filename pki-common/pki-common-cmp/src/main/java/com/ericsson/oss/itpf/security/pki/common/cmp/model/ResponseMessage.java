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

import java.io.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.CMPCertificateEncodingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.exception.ProtocolException;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;

/**
 * This class sets all the requiredFields for a ResponseMessage also contains setters and getters.
 * 
 * @author tcsramc
 * 
 */
public abstract class ResponseMessage implements Serializable {

    protected PKIHeader responsePKIHeader = null;
    protected PKIMessage responsePKIMessage = null;
    protected PKIBody responsePKIBody = null;
    protected AlgorithmIdentifier protectionAlgorithmIdentifier = null;

    private final Logger logger = LoggerFactory.getLogger(ResponseMessage.class);
    private static final long serialVersionUID = -1958255854532065484L;
    private String base64TransactionID;
    private String senderNonce = null;
    private String receipientNonce = null;
    private int responseType = 0;
    private String issuerName = null;

    protected ASN1Encodable encodableContent = null;

    public abstract void createPKIBody(final ASN1Encodable content);

    public ResponseMessage() {

    }

    /**
     * This Constructor extracts the PKIMessage fields and sets to ResponseMessage.
     * 
     * @param cMPResponseByteArray
     *            CMP Response byte array from which PKI message need to be extracted
     * @throws MessageParsingException
     *             is thrown if any parsing error occurs
     */
    public ResponseMessage(final byte[] cMPResponseByteArray) throws MessageParsingException {
        try {
            final ASN1Primitive rawMessage = toASN1Primitive(cMPResponseByteArray);
            responsePKIMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(rawMessage));
            responsePKIHeader = responsePKIMessage.getHeader();
            responsePKIBody = responsePKIMessage.getBody();
            responseType = responsePKIBody.getType();

            if (responsePKIHeader.getTransactionID() != null) {
                final DEROctetString dos = (DEROctetString) (responsePKIHeader.getTransactionID());
                base64TransactionID = new String(org.bouncycastle.util.encoders.Base64.encode(dos.getOctets()));
            }

            if (responsePKIHeader.getSenderNonce() != null) {
                setSenderNonce(new String(Base64.encode(responsePKIHeader.getSenderNonce().getOctets())));
            }

            if (responsePKIHeader.getRecipNonce() != null) {
                setReceipientNonce(new String(Base64.encode(responsePKIHeader.getRecipNonce().getOctets())));
            }

            protectionAlgorithmIdentifier = responsePKIHeader.getProtectionAlg();

        } catch (IOException ioException) {
            throw new MessageParsingException(ErrorMessages.IO_EXCEPTION, ioException);
        }
    }

    /**
     * @return the encodableContent
     */
    public ASN1Encodable getEncodableContent() {
        return encodableContent;
    }

    /**
     * Returns ResposeType
     * 
     * @return repsonse type
     */
    public int getResponseType() {
        if (responsePKIBody != null) {
            responseType = responsePKIBody.getType();
        }
        return this.responseType;
    }

    /**
     * Returns ResponsePKIMessage
     * 
     * @return Response PKI Message
     */
    public PKIMessage getPKIResponseMessage() {
        return this.responsePKIMessage;
    }

    /**
     * Returns TransactionID
     * 
     * @return Transaction ID of the PKI message
     */
    public String getBase64TransactionID() {
        return this.base64TransactionID;
    }

    /**
     * This method is used to set the protection algorithm Identifier
     * 
     * @param protectionAlgorithm
     *            byte stream of the protection Algorithm
     * 
     * @throws IOException
     *             is thro wn when any I/O exception occurs during encoding
     */
    public void setProtectionAlgorithm(final byte[] protectionAlgorithm) throws IOException {
        final ASN1InputStream inputStream = new ASN1InputStream(protectionAlgorithm);
        try {
            final ASN1Primitive rawMessage = inputStream.readObject();
            this.protectionAlgorithmIdentifier = AlgorithmIdentifier.getInstance(ASN1Sequence.getInstance(rawMessage));
        } finally {
            inputStream.close();
        }
    }

    /**
     * Returns ProtectionAlgorithmIdentifier
     * 
     * @return protection Algorithm Identifier
     */
    public AlgorithmIdentifier getProtectionAlgorithm() {
        return this.protectionAlgorithmIdentifier;
    }

    /**
     * Returns ReponsePKIHeader PKIHeader of the Response PKIMessage
     * 
     * @return
     */
    public PKIHeader getResponsePKIHeader() {
        return this.responsePKIHeader;
    }

    /**
     * This method is used to create the PKIHeader
     * 
     * @param sender
     *            sender name
     * @param recipient
     *            recipient name
     * @param senderNonce
     *            sender nonce to be set in the PKIHeader
     * @param recipientNonce
     *            recipient nonce to be set in the PKIHeader
     * @param transactionId
     *            transactionId to be set in the PKIHeader
     */
    public void createPKIHeader(final String sender, final String recipient, final String senderNonce, final String recipientNonce, final String transactionId) {

        logger.info("Start building the PKIHeader");
        final GeneralName senderGeneralName = new GeneralName(new X500Name(sender));
        final GeneralName recipientGeneralName = new GeneralName(new X500Name(recipient));
        final PKIHeaderBuilder pKIHeaderBuilder = setPKIHeaderBuilder(senderNonce, recipientNonce, transactionId, senderGeneralName, recipientGeneralName);
        logger.info("PKIHeader building is done");
        this.responsePKIHeader = pKIHeaderBuilder.build();

    }

    /**
     * This method is used to create PKIBody
     * 
     * @param content
     *            The content that need to be set
     */

    /**
     * This method is used to create a org.bouncycastle.asn1.cmp.PKIMessage. The PKIMessage is created by putting a dummy content in the protection field. Before passing it on, it has to be properly
     * signed.
     * 
     * @param responsePKIHeader
     *            the PKIHeader
     * @param responsePKIBody
     *            the PKIBody
     * @param extraCerts
     *            extraCerts are used to validate the PKIMessage and the entity certificate it contains. It is possible to create a PKIMessage without providing any extracerts.
     * @return the PKIMessage
     * @throws CMPv2ResponseBuilderException
     */
    public void createPKIMessage(final List<X509Certificate> extraCerts) throws CMPCertificateEncodingException {
        CMPCertificate[] cMPExtraCerts = null;
        final DERBitString protection = null;
        final X509Certificate x509Certificate = null;
        try {
            if (extraCerts.isEmpty()) {
                buildPKIMessageWithEmptyExtraCerts();
            } else {
                cMPExtraCerts = convertToCMPCertArray(extraCerts);
                this.responsePKIMessage = new PKIMessage(this.responsePKIHeader, this.responsePKIBody, protection, cMPExtraCerts);
            }
        } catch (CertificateEncodingException certEncodeException) {
            logger.debug("Certificate contents are as below, which gave an certificateEncoding exception {}", x509Certificate);
            throw new CMPCertificateEncodingException(ErrorMessages.CERTIFICATE_ENCODING_ERROR, certEncodeException);
        }
    }

    public void createPKIMessage() throws ProtocolException {
        this.responsePKIMessage = new PKIMessage(responsePKIHeader, responsePKIBody);
    }

    public String getSenderNonce() {
        return senderNonce;
    }

    public void setSenderNonce(final String senderNonce) {
        this.senderNonce = senderNonce;
    }

    public String getReceipientNonce() {
        return receipientNonce;
    }

    public void setReceipientNonce(final String receipientNonce) {
        this.receipientNonce = receipientNonce;
    }

    public byte[] toByteArray() throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ASN1OutputStream mout = null;
        byte[] byteArray = null;
        try {
              mout = ASN1OutputStream.create(baos, ASN1Encoding.DER);
              mout.writeObject(this.responsePKIMessage);
              byteArray = baos.toByteArray();
        } finally {
            try {
                if (mout != null) {
                    mout.close();
                }
            } catch (IOException ioexception) {
                logger.warn("Exception occured while closing the input stream in ResponseMessage class");
                logger.debug("Exception occured while closing the input stream in ResponseMessage class ", ioexception);
            }
            try {
                baos.close();
            } catch (IOException ioexception) {
                logger.warn("Exception occured while closing the input stream in ResponseMessage class");
                logger.debug("Exception occured while closing the input stream in ResponseMessage class ", ioexception);
            }
        }
        return byteArray;
    }

    protected ASN1Primitive toASN1Primitive(final byte[] byteArray) throws IOException {
        final ASN1InputStream inputStream = new ASN1InputStream(byteArray);
        final ASN1Primitive rawMessage;
        try {
            rawMessage = inputStream.readObject();
        } finally {
            inputStream.close();

        }
        return rawMessage;
    }

    private void buildPKIMessageWithEmptyExtraCerts() {
        this.responsePKIMessage = new PKIMessage(this.responsePKIHeader, this.responsePKIBody);
    }

    private CMPCertificate[] convertToCMPCertArray(final List<X509Certificate> extraCerts) throws CertificateEncodingException {

        final List<X509Certificate> tempExtraCerts = new ArrayList<>(extraCerts);
        final List<CMPCertificate> cMPCertificates = new ArrayList<>();
        final Iterator<X509Certificate> extraCertsItr = tempExtraCerts.iterator();
        CMPCertificate[] cMPExtraCerts = null;
        CMPCertificate cMPCertificate = null;
        X509Certificate x509Certificate = null;

        while (extraCertsItr.hasNext()) {
            x509Certificate = extraCertsItr.next();
            cMPCertificate = new CMPCertificate(org.bouncycastle.asn1.x509.Certificate.getInstance(x509Certificate.getEncoded()));
            cMPCertificates.add(cMPCertificate);
        }
        cMPExtraCerts = cMPCertificates.toArray(new CMPCertificate[cMPCertificates.size()]);
        return cMPExtraCerts;
    }

    private PKIHeaderBuilder setPKIHeaderBuilder(final String senderNonce, final String recipientNonce, final String transactionId, final GeneralName senderGeneralName,
            final GeneralName recipientGeneralName) {

        final PKIHeaderBuilder pKIHeaderBuilder = new PKIHeaderBuilder(2, senderGeneralName, recipientGeneralName);

        pKIHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));

        if (recipientNonce != null) {
            pKIHeaderBuilder.setRecipNonce(toDEROctetString(recipientNonce));
        }

        if (senderNonce != null) {
            pKIHeaderBuilder.setSenderNonce(toDEROctetString(senderNonce));
        }

        if (transactionId != null) {
            pKIHeaderBuilder.setTransactionID(toDEROctetString(transactionId));
        }
        return pKIHeaderBuilder;
    }

    private DEROctetString toDEROctetString(final String string) {
        return new DEROctetString(Base64.decode(string.getBytes()));
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
