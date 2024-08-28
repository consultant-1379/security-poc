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

import org.bouncycastle.asn1.cmp.*;

/**
 * This class contains all the parameters required for IAK.
 * 
 * @author tcsramc
 * 
 */
public class IAKParameters implements Serializable {

    public static final String ALGORITHM_ID = "1.2.840.113533.7.66.13";

    private static final long serialVersionUID = -1896874175123241434L;
    private int iterationCount;
    private String macOid = null;
    private String owfId = null;
    private ProtectedPart protectedPart;
    private byte[] saltOctets = null;
    private PKIMessage pKIMessage;


    /**
     * Constructor method which extracts PKIMEssage from RequestMessage.
     * 
     * @param pKIRequestMessage
     *            PKI request Message
     */
    public IAKParameters(final RequestMessage pKIRequestMessage) {
        pKIMessage = pKIRequestMessage.getPKIMessage();

    }

    /**
     * This method returns protected part from the PKIMessage.
     * 
     * @return byte array of the protected part of PKIMessage
     * @throws IOException
     *             is thrown when an encoding error occurs.
     */
    public byte[] getProtectedPart() throws IOException {
        protectedPart = new ProtectedPart(pKIMessage.getHeader(), pKIMessage.getBody());
        return protectedPart.getEncoded();
    }

    /**
     * This method extracts and returns AlgorithmIdentifier from PKIMessage.
     * 
     * @return owf ID extracted from the pBMParameter
     */
    public String getOWFId() {
        PBMParameter pbmParameter;
        pbmParameter = PBMParameter.getInstance(pKIMessage.getHeader().getProtectionAlg().getParameters());
        owfId = pbmParameter.getOwf().getAlgorithm().getId();
        return owfId;
    }

    /**
     * This method returns iteration Count from parameters.
     * 
     * @return iteration count extracted from the pBMParameter
     */
    public int getIAKIterationCount() {
        PBMParameter pbmParameter;
        pbmParameter = PBMParameter.getInstance(pKIMessage.getHeader().getProtectionAlg().getParameters());
        iterationCount = pbmParameter.getIterationCount().getPositiveValue().intValue();
        return iterationCount;
    }

    /**
     * Returns saltOctects.
     * 
     * @return salt Octets extracted from the pBMParameter
     */
    public byte[] getSaltOctets() {
        PBMParameter pbmParameter;
        pbmParameter = PBMParameter.getInstance(pKIMessage.getHeader().getProtectionAlg().getParameters());
        saltOctets = pbmParameter.getSalt().getOctets();
        return saltOctets;
    }

    /**
     * Returns MAcOid
     * 
     * @return mac OID extracted from the pBMParameter
     */
    public String getMacOid() {
        PBMParameter pbmParameter;
        pbmParameter = PBMParameter.getInstance(pKIMessage.getHeader().getProtectionAlg().getParameters());
        macOid = pbmParameter.getMac().getAlgorithm().getId();
        return macOid;
    }

    /**
     * This method is used to verify whether the Obtained requestMEssage is IAK or VC based on aLgorithmIdentifier.
     * 
     * @param requestMessage
     *            PKI Request Message
     * 
     * @return true if it is MACBased else false
     */
    public static boolean isMacBased(final RequestMessage requestMessage) {
        boolean iakToBeValidated = false;
        String algorithmID = null;
        algorithmID = requestMessage.getProtectionAlgorithmID();

        if (algorithmID != null && algorithmID.equals(IAKParameters.ALGORITHM_ID)) {
            iakToBeValidated = true;
        }
        return iakToBeValidated;
    }

    /**
     * @param pKIMessage the pKIMessage to set
     */
    public void setpKIMessage(final PKIMessage pKIMessage) {
        this.pKIMessage = pKIMessage;
    }
}
