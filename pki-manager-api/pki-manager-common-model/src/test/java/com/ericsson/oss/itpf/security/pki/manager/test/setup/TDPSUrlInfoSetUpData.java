/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import com.ericsson.oss.itpf.security.pki.manager.model.TDPSUrlInfo;

public class TDPSUrlInfoSetUpData {
    private static final String EQUAL_IPV4_ADDRESS = "EqualIpv4address";
    private static final String NOT_EQUAL_IPV4_ADDRESS = "NotEqualIpv4address";
    private static final String EQUAL_IPV6_ADDRESS = "EqualIpv6address";
    private static final String NOT_EQUAL_IPV6_ADDRESS = "NotEqualIpv6address";

    /**
     * Method that returns valid TDPSUrlInfo
     * 
     * @return TDPSUrlInfo
     */
    public TDPSUrlInfo getTDPSUrlInfoForEqual() {
        final TDPSUrlInfo tdpsUrlInfo = new TDPSUrlInfo();
        tdpsUrlInfo.setIpv4Address(EQUAL_IPV4_ADDRESS);
        tdpsUrlInfo.setIpv6Address(EQUAL_IPV6_ADDRESS);
        return tdpsUrlInfo;
    }

    /**
     * Method that returns different valid TDPSUrlInfo
     * 
     * @return TDPSUrlInfo
     */
    public TDPSUrlInfo getTDPSUrlInfoForNotEqual() {
        final TDPSUrlInfo tdpsUrlInfo = new TDPSUrlInfo();
        tdpsUrlInfo.setIpv4Address(NOT_EQUAL_IPV4_ADDRESS);
        tdpsUrlInfo.setIpv6Address(NOT_EQUAL_IPV6_ADDRESS);
        return tdpsUrlInfo;
    }
}
