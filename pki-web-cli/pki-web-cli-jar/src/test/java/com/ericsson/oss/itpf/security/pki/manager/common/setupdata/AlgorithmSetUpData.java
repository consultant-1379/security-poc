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
package com.ericsson.oss.itpf.security.pki.manager.common.setupdata;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;

/**
 * This class acts as builder for {@link AlgorithmSetUpData}
 */
public class AlgorithmSetUpData {
    private String name;
    private AlgorithmType type;
    private String oid;
    private boolean supported;
    private Integer keySize;

    /**
     * 
     * @param name
     * @return
     */
    public AlgorithmSetUpData name(final String name) {
        this.name = name;
        return this;
    }

    /**
     * 
     * @param type
     * @return
     */
    public AlgorithmSetUpData type(final AlgorithmType type) {
        this.type = type;
        return this;
    }

    /**
     * 
     * @param oid
     * @return
     */
    public AlgorithmSetUpData oid(final String oid) {
        this.oid = oid;
        return this;
    }

    /**
     * 
     * @param supported
     * @return
     */
    public AlgorithmSetUpData supported(final boolean supported) {
        this.supported = supported;
        return this;
    }

    /**
     * 
     * @param keySize
     * @return
     */
    public AlgorithmSetUpData keySize(final Integer keySize) {
        this.keySize = keySize;
        return this;
    }

    /**
     * Method that returns valid Algorithm
     * 
     * @return Algorithm
     */
    public Algorithm build() {
        final Algorithm algorithm = new Algorithm();
        algorithm.setName(name);
        algorithm.setType(type);
        algorithm.setKeySize(keySize);
        algorithm.setOid(oid);
        algorithm.setSupported(supported);
        return algorithm;
    }
}