/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.api;

public interface SourceConstants {

    /**
     * Trust Source INTERNAL CAs only
     */
    String TRUST_SOURCE_INTERNAL = "internal";

    /**
     * Trust Source EXTERNAL CAs only
     */
    String TRUST_SOURCE_EXTERNAL = "external";

    /**
     * Trust Source both INTERNAL and EXTERNAL CAs
     */
    String TRUST_SOURCE_BOTH = "both";

    /**
     * Crl Source INTERNAL CAs only
     */
    String CRL_SOURCE_INTERNAL = "internal";

    /**
     * Crl Source EXTERNAL CAs only
     */
    String CRL_SOURCE_EXTERNAL = "external";

    /**
     * Trust Source both INTERNAL and EXTERNAL CAs
     */
    String CRL_SOURCE_BOTH = "both";

}
