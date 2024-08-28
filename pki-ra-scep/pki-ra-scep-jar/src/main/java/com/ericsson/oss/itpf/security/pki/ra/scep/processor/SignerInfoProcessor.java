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
package com.ericsson.oss.itpf.security.pki.ra.scep.processor;

import java.util.*;

import javax.inject.Inject;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.cms.*;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepRequestData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;

/**
 * This class processes the Signer Information of the Signed Data present in the PKCSReq or GetCertInitial Messages.
 * 
 * @author xshaeru
 */
public class SignerInfoProcessor {
    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method extracts the signer information of the cmsSignedData message.
     * 
     * @param cmsSignedData
     *            from which the signer info is extracted.
     * @param pkcs7ScepRequestData
     *            which holds the data of PKCSreq to be required to generate Response.
     * @throws BadRequestException
     *             is thrown when the signer information is not present.
     */

    public void extractSignerInformation(final CMSSignedData cmsSignedData, final Pkcs7ScepRequestData pkcs7ScepRequestData) throws BadRequestException {
        logger.debug("Entering of extractSignerInformation method of PkiOperationReqProcessor;");
        SignerInformation signerInformation = null;
        final SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();
        final Collection<?> signers = signerInformationStore.getSigners();
        final Iterator<?> it = signers.iterator();
        if (it.hasNext()) {
            signerInformation = (SignerInformation) it.next();
        }
        if (signerInformation != null) {
            pkcs7ScepRequestData.setSignerInformation(signerInformation);
            extractAuthenticateAttributes(signerInformation, pkcs7ScepRequestData);
        } else {
            logger.error("SignerInformation is not present in the request with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                    + pkcs7ScepRequestData.getEndEntityName());
            systemRecorder.recordError(
                    "PKI_RA_SCEP.SIGNER_INFO_NOT_FOUND",
                    ErrorSeverity.ERROR,
                    "SCEP Client",
                    "SCEP Enrollment for End Entity",
                    "SignerInformation is not present in request with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                            + pkcs7ScepRequestData.getEndEntityName());
            throw new BadRequestException(ErrorMessages.SIGNER_INFO_NOT_FOUND);
        }
        logger.debug("End of extractSignerInformation method of PkiOperationReqProcessor;");
    }

    /**
     * extractAuthenticateAttributes takes SignerInformation as input parameter It fetches all authenticated attributes such as Message Type,Sender Nonce,Transaction ID,Message Digest,Signing Time and
     * stores them and also it stores Issuer Name, Issuer serial Number,Digest Algorithm,DigestEncryption Algorithm Identifier.
     * 
     * @param signerInfromation
     *            is the SignerInformation of the ASN1 SignedData.
     * @param pkcs7ScepRequestData
     *            which holds the data of PKCSreq to be required to generate Response.
     * @throws BadRequestException
     *             is thrown when the Request is not having proper authenticated attribute values.
     */
    private void extractAuthenticateAttributes(final SignerInformation signerInfromation, final Pkcs7ScepRequestData pkcs7ScepRequestData) throws BadRequestException {
        logger.debug("extractAuthenticateAttributes method of PkiOperationReqProcessor");
        DERPrintableString attributeString = null;
        ASN1OctetString attributeASN1String = null;
        final Map<ASN1ObjectIdentifier, String> mapOfAuthAttributes = mapofAuthenticatedAttributes();

        final AttributeTable attributeTable = signerInfromation.getSignedAttributes();
        final ASN1ObjectIdentifier[] attributeArray = mapOfAuthAttributes.keySet().toArray(new ASN1ObjectIdentifier[0]);

        for (final ASN1ObjectIdentifier asn1AtrributeOID : attributeArray) {

            final Attribute attribute = attributeTable.get(asn1AtrributeOID);

            if (attribute != null) {
                final ASN1Set values = attribute.getAttrValues();

                final Enumeration<?> enumeration = values.getObjects();

                switch (asn1AtrributeOID.toString()) {
                case Constants.MESSAGE_TYPE_OID:
                    if (enumeration.hasMoreElements()) {
                        attributeString = (DERPrintableString) enumeration.nextElement();
                        pkcs7ScepRequestData.setMessageType(Integer.valueOf(attributeString.getString()));
                        if (MessageType.getNameByValue(pkcs7ScepRequestData.getMessageType()) == null) {
                            throw new InvalidMessageTypeException(ErrorMessages.INVALID_MESSAGE_TYPE);
                        }
                    }
                    break;
                case Constants.SENDER_NONCE:
                    if (enumeration.hasMoreElements()) {
                        attributeASN1String = (ASN1OctetString) enumeration.nextElement();
                        pkcs7ScepRequestData.setSenderNonce(attributeASN1String.getOctets());
                    }
                    break;
                case Constants.TRANSACTION_ID:
                    if (enumeration.hasMoreElements()) {
                        attributeString = (DERPrintableString) enumeration.nextElement();
                        pkcs7ScepRequestData.setTransactionId(attributeString.toString());
                    }
                    break;
                }

            } else {
                logger.error(mapOfAuthAttributes.get(asn1AtrributeOID) + " value is not present in PKCS7 Request with the transaction id :" + pkcs7ScepRequestData.getTransactionId()
                        + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
                systemRecorder.recordError("PKI_RA_SCEP.AUTHENTICATION_ATTRIBUTE_NOT_FOUND", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollment for End Entity", "Authenticate Attribute "
                        + mapOfAuthAttributes.get(asn1AtrributeOID) + " is not present in PKCS7 Request with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                        + pkcs7ScepRequestData.getEndEntityName());
                throw new AttributeNotFoundException(mapOfAuthAttributes.get(asn1AtrributeOID) + ErrorMessages.ATTRIBUTE_NOT_FOUND);
            }

        }
        logger.debug("End of extractAuthenticateAttributes method of PkiOperationReqProcessor");

    }

    /**
     * mapofAuthenticatedAttributes maps all the Authenticated attributes with the name of the attribute in a HashMap so that it helps to print proper name of the attribute if it is not present in
     * AuthenticatedAttributes.
     * 
     */

    private Map<ASN1ObjectIdentifier, String> mapofAuthenticatedAttributes() {

        final Map<ASN1ObjectIdentifier, String> mapOfAuthAttributes = new HashMap<ASN1ObjectIdentifier, String>();
        mapOfAuthAttributes.put(new ASN1ObjectIdentifier(Constants.MESSAGE_TYPE_OID), "Message Type");
        mapOfAuthAttributes.put(new ASN1ObjectIdentifier(Constants.SENDER_NONCE), "Sender Nonce ");
        mapOfAuthAttributes.put(new ASN1ObjectIdentifier(Constants.TRANSACTION_ID), "Transaction ID");
        mapOfAuthAttributes.put(CMSAttributes.messageDigest, "Message Digest ID");
        return mapOfAuthAttributes;

    }

}
