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
package com.ericsson.oss.itpf.security.pki.common.cmp.util;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.util.encoders.Base64;

import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;

/**
 * This class prints the PKIMessage
 * 
 * @author tcsramc
 * 
 */
public class PKIMessageStringUtility {

    private static final String PKI_MESSAGE_DATA = "*******************PKI MESSAGE DATA*******************";
    private static final String END_MESSAGE_DATA = "*******************END MESSAGE DATA*******************";

    private PKIMessageStringUtility() {
    }

    /**
     * Prints PKIMEssage
     * 
     * @param incomingMsg
     * @param pKIMessage
     * @param base64TransactionID
     * @return
     * @throws IOException
     *             is thrownif any I/o Error Occurs
     */
    public static String printPKIMessage(final boolean incomingMsg, final PKIMessage pKIMessage, final String base64TransactionID) throws IOException {
        final StringBuilder strBuilder = new StringBuilder();
        final String tab = "  ";
        strBuilder.append(Constants.NEW_LINE + PKI_MESSAGE_DATA + (incomingMsg ? " >>>> " + Constants.NEW_LINE : " <<<< " + Constants.NEW_LINE));
        strBuilder.append(senderNonceToString(pKIMessage));
        strBuilder.append(recipientNonceToString(pKIMessage));
        strBuilder.append(tab + "Message type:\t" + PKIMessageUtil.convertRequestTypeToString(pKIMessage.getBody().getType()) + Constants.NEW_LINE);
        strBuilder.append(tab + "Sender:\t" + pKIMessage.getHeader().getSender() + Constants.NEW_LINE);
        strBuilder.append(tab + "Recip :\t" + pKIMessage.getHeader().getRecipient() + Constants.NEW_LINE);
        strBuilder.append(transactionIdToString(base64TransactionID));
        strBuilder.append(Constants.NEW_LINE + END_MESSAGE_DATA + Constants.NEW_LINE);
        return strBuilder.toString();

    }

    private static String senderNonceToString(final PKIMessage pKIMessage) throws IOException {
        final StringBuilder strBuilder = new StringBuilder();
        final String tab = " ";
        final ASN1OctetString senderNonce = pKIMessage.getHeader().getSenderNonce();
        if (senderNonce != null) {
            strBuilder.append(tab);
            strBuilder.append("Sender Nonce:\t" + new String(Base64.encode(pKIMessage.getHeader().getSenderNonce().getEncoded())));
            strBuilder.append(Constants.NEW_LINE);
        } else {
            strBuilder.append(tab);
            strBuilder.append("Not provided");
            strBuilder.append(Constants.NEW_LINE);
        }
        return strBuilder.toString();

    }

    private static String recipientNonceToString(final PKIMessage pKIMessage) throws IOException {
        final StringBuilder strBuilder = new StringBuilder();
        final String tab = " ";
        final ASN1OctetString recipientNonce = pKIMessage.getHeader().getRecipNonce();
        strBuilder.append(tab + "Recip  Nonce:\t");
        if (recipientNonce != null) {
            strBuilder.append(tab);
            strBuilder.append(new String(Base64.encode(pKIMessage.getHeader().getRecipNonce().getEncoded())));
            strBuilder.append(Constants.NEW_LINE);
        } else {
            strBuilder.append(tab);
            strBuilder.append("Not provided");
            strBuilder.append(Constants.NEW_LINE);
        }
        return strBuilder.toString();
    }

    private static String transactionIdToString(final String transactionID) {
        final StringBuilder strBuilder = new StringBuilder();
        final String tab = " ";
        strBuilder.append(tab + "Transaction ID:\t");
        if (transactionID != null) {
            strBuilder.append(tab);
            strBuilder.append(transactionID);
            strBuilder.append(Constants.NEW_LINE);
        } else {
            strBuilder.append(tab);
            strBuilder.append("Not provided");
            strBuilder.append(Constants.NEW_LINE);
        }
        return strBuilder.toString();
    }
}
