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
package com.ericsson.oss.itpf.security.pki.common.test.utilities;

import java.util.Date;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.util.encoders.Base64;

import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;


public class PKIHeaderUtil {

    public static PKIHeader createPKIHeader(final Parameters parameters, final GeneralName sender, final GeneralName recipient, final String senderNonce, final String recipientNonce,
            final String transactionId, final AlgorithmIdentifier algorithmIdentifier) {

        final boolean isValidHeader = parameters.isValidHeader();
        final boolean isInDirectoryFormat = parameters.isInDirectoryFormat();
        final boolean isValidProtectionAlgo = parameters.isValidProtectionAlgo();
        final boolean isNullProtAlgoObjID = parameters.isNullProtectionAlgorithm();
        final int headerVersion = getHeaderVersion(isValidHeader);

        PKIHeaderBuilder pKIHeaderBuilder = null;
        pKIHeaderBuilder = initializeHeaderBuilder(sender, recipient, isInDirectoryFormat, headerVersion);
        setProtectionAlgorithm(algorithmIdentifier, isValidProtectionAlgo, isNullProtAlgoObjID, pKIHeaderBuilder);
        setMessageTime(pKIHeaderBuilder);
        setSenderNonce(senderNonce, pKIHeaderBuilder);
        setRecipientNonce(recipientNonce, pKIHeaderBuilder);
        setTransactionId(transactionId, pKIHeaderBuilder);

        final PKIHeader pkiHeader = pKIHeaderBuilder.build();

        return pkiHeader;
    }

    private static PKIHeaderBuilder initializeHeaderBuilder(final GeneralName sender, final GeneralName recipient, final boolean isInDirectoryFormat, final int headerVersion) {
        PKIHeaderBuilder pKIHeaderBuilder;
        if (isInDirectoryFormat) {
            pKIHeaderBuilder = new PKIHeaderBuilder(headerVersion, sender, recipient);
        } else {
            pKIHeaderBuilder = new PKIHeaderBuilder(headerVersion, new GeneralName(GeneralName.dNSName, "CN=Entity"), new GeneralName(GeneralName.dNSName, "CN=Entity"));
        }
        return pKIHeaderBuilder;
    }

    private static void setTransactionId(final String transactionId, final PKIHeaderBuilder pKIHeaderBuilder) {
        if (transactionId != null) {
            pKIHeaderBuilder.setTransactionID(new DEROctetString(Base64.decode(transactionId.getBytes())));
        }
    }

    private static void setRecipientNonce(final String recipientNonce, final PKIHeaderBuilder pKIHeaderBuilder) {
        if (recipientNonce != null) {
            pKIHeaderBuilder.setRecipNonce(new DEROctetString(Base64.decode(recipientNonce.getBytes())));
        }
    }

    private static void setSenderNonce(final String senderNonce, final PKIHeaderBuilder pKIHeaderBuilder) {
        if (senderNonce != null) {
            pKIHeaderBuilder.setSenderNonce(new DEROctetString(Base64.decode(senderNonce.getBytes())));
        }
    }

    private static void setMessageTime(final PKIHeaderBuilder pKIHeaderBuilder) {
        pKIHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
    }

    private static void setProtectionAlgorithm(final AlgorithmIdentifier algorithmIdentifier, final boolean isValidProtectionAlgo, final boolean isNullProtAlgoObjID, final PKIHeaderBuilder pKIHeaderBuilder) {
        if (!isValidProtectionAlgo) {
            final String invalidProtectionAlgorithmID = "1.2.840.113549.1.6";
            final ASN1ObjectIdentifier objID = new ASN1ObjectIdentifier(invalidProtectionAlgorithmID);
            pKIHeaderBuilder.setProtectionAlg(new AlgorithmIdentifier(objID));

        } else if (isNullProtAlgoObjID) {
            pKIHeaderBuilder.setProtectionAlg(null);
        } else {
            if (algorithmIdentifier == null) {
                pKIHeaderBuilder.setProtectionAlg(new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption));
            } else {
                pKIHeaderBuilder.setProtectionAlg(algorithmIdentifier);
            }
        }
    }

    private static int getHeaderVersion(final boolean isValidHeader) {
        int headerVersion = PKIHeader.CMP_2000;
        if (!isValidHeader) {
            headerVersion = PKIHeader.CMP_1999;
        }
        return headerVersion;
    }

}
