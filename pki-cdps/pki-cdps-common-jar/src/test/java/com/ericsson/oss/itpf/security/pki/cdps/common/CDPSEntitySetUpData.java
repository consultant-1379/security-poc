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
package com.ericsson.oss.itpf.security.pki.cdps.common;

import java.io.FileInputStream;
import java.security.cert.*;

import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData;

/**
 * This class used to create CDPSEntityData instances to test CDPSEntityData functionality
 * 
 * @author tcsgoja
 *
 */
public class CDPSEntitySetUpData {

    private final static String CA_NAME = "CDPS_CA";
    private final static String CERTIFICATE_SERIAL_NUMBER = "20142345RYH7653WKSIJRFRFDGFRDR3D";
    private final static byte[] CRL_DATA = getX509CRL("src/test/resources/crls/testCA.crl");
    private final static int ID_NUMBER = 101010;

    private final String CDPS_CA_NAME = "CDPS_CA_NAM";
    private final String CERTIFICATE_SERIAL_NUM = "20142345RYH7653WKSIJRFRFDGFRDR3F";
    private final byte[] CRL = getX509CRL("src/test/resources/crls/testCA.crl");
    private final int ID_NUM = 101011;

    /**
     * This method used to prepare CDPSEntityData and return it.
     * 
     * @return
     */
    public static CDPSEntityData getCDPSEntityForEqual() {

        final CDPSEntityData cdpsEntityData = new CDPSEntityData();
        cdpsEntityData.setCaName(CA_NAME);
        cdpsEntityData.setCertSerialNumber(CERTIFICATE_SERIAL_NUMBER);
        cdpsEntityData.setCrl(CRL_DATA);
        cdpsEntityData.setId(ID_NUMBER);
        return cdpsEntityData;
    }

    /**
     * This method used to prepare CDPSEntityData and return it.
     * 
     * @return
     */
    public CDPSEntityData getCDPSEntityForNotEqual() {

        final CDPSEntityData cdpsEntityData = new CDPSEntityData();
        cdpsEntityData.setCaName(CDPS_CA_NAME);
        cdpsEntityData.setCertSerialNumber(CERTIFICATE_SERIAL_NUM);
        cdpsEntityData.setCrl(CRL);
        cdpsEntityData.setId(ID_NUM);
        return cdpsEntityData;
    }

    private static byte[] getX509CRL(String fileName) {
        X509CRL x509crl = null;
        byte[] crlContent = null;
        try {
            FileInputStream inputStream = new FileInputStream(fileName);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);
            crlContent = x509crl.getEncoded();
        } catch (Exception e) {
        }
        return crlContent;
    }

}
