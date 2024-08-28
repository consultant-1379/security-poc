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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator;

import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCoreEntityAttributeException;

/**
 * This CrlGenerationFactory will generate a CrlGenerator object based on the Version of the CRL to be generated
 * 
 * @author xananer
 * 
 */
public class CrlGeneratorFactory {

    @Inject
    CrlGenerator crlV2Generator;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method will provide a CrlGenrator object based on the version of the CRL to be generated.
     * 
     * @param certificateAuthority
     * @return CrlGenerator
     * @throws InvalidCoreEntityAttributeException
     *             Thrown in case of any invalid attribute found in entity.
     */
    public CrlGenerator getCrlGenerator(final CertificateAuthority certificateAuthority) throws InvalidCoreEntityAttributeException {
        switch (certificateAuthority.getCrlGenerationInfo().get(0).getVersion()) {
        case V2:
            return crlV2Generator;
        default:
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.INAVALID_CRL_VERSION", ErrorSeverity.ERROR, "CrlGeneratorFactory", "CRL Generation", "Invalid CRL version "
                    + certificateAuthority.getCrlGenerationInfo().get(0).getVersion());
            throw new InvalidCoreEntityAttributeException("Invalid CRL Version found");

        }
    }
}
