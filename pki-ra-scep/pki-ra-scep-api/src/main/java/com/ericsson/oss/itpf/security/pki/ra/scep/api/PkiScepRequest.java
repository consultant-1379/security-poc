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
package com.ericsson.oss.itpf.security.pki.ra.scep.api;

import java.io.Serializable;

import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Operation;

/**
 * This class contains message variable to store certificate request message which will be in DER encodable format, operation variable which specifies the SCEP operation to perform and caName value
 * which is used to fetch the corresponding CA certificate. These values are received from the SCEP client.
 *
 * @author xtelsow
 */
public class PkiScepRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private byte[] message;

    private Operation operation;

    private String caName;

    private boolean readFromTrustStore = false;

    /**
     * @return the message
     */
    public byte[] getMessage() {
        return message;
    }

    /**
     * @param message
     *            the message to set
     */
    public void setMessage(final byte[] message) {
        this.message = message;
    }

    /**
     * @return the operation
     */
    public Operation getOperation() {
        return operation;
    }

    /**
     * @param operation
     *            the operation to set
     */
    public void setOperation(final Operation operation) {
        this.operation = operation;
    }

    /**
     * @return the caName
     */
    public String getCaName() {
        return caName;
    }

    /**
     * @param caName
     *            the caName to set
     */
    public void setCaName(final String caName) {
        this.caName = caName;
    }

    /**
     * @return the readFromTrustStore
     */
    public boolean isReadFromTrustStore() {
        return readFromTrustStore;
    }

    /**
     * @param readFromTrustStore
     *            the readFromTrustStore to set
     */
    public void setReadFromTrustStore(final boolean readFromTrustStore) {
        this.readFromTrustStore = readFromTrustStore;
    }
}
