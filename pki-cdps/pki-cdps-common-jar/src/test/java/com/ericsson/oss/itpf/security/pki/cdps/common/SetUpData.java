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
import java.io.FileNotFoundException;
import java.security.cert.*;
import java.util.LinkedList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData;

/**
 * This class used test and to prepare instances of cdps-common functionality
 * 
 * @author tcsgoja
 *
 */
public class SetUpData {

    /**
     * This method used to prepare CACertificateInfo and return it.
     * 
     * @return
     */
    private byte[] crl;

    protected CACertificateInfo prepareCACertificateInfo() {

        String caName = "nu_oam_ca";
        String certificateSerialNumber = "204173BB72886E4B1CB6700267AA3B3D";

        CACertificateInfo caCertificateInfo = new CACertificateInfo();
        caCertificateInfo.setCaName(caName);
        caCertificateInfo.setCertificateSerialNumber(certificateSerialNumber);

        return caCertificateInfo;
    }

    /**
     * This method used to prepare CACertificateInfo and return it.
     * 
     * @return
     */
    protected CACertificateInfo prepareCACertInfo() {

        String caName = "nu_om_ca";
        String certificateSerialNumber = "204173BB72886E4B1CB6700267AA3B3F";

        CACertificateInfo caCertificateInfo = new CACertificateInfo();
        caCertificateInfo.setCaName(caName);
        caCertificateInfo.setCertificateSerialNumber(certificateSerialNumber);

        return caCertificateInfo;
    }

    /**
     * This method used to prepare CACertificateInfo and return it.
     * 
     * @return
     */
    protected CACertificateInfo prepareCACertInfoEmpty() {

        String caName = null;
        String certificateSerialNumber = null;

        CACertificateInfo caCertificateInfo = new CACertificateInfo();
        caCertificateInfo.setCaName(caName);
        caCertificateInfo.setCertificateSerialNumber(certificateSerialNumber);

        return caCertificateInfo;
    }

    /**
     * This method used to prepare List<CACertificateInfo> and return it.
     * 
     * @return
     */
    protected List<CACertificateInfo> prepareCACertificateInfoList() {

        List<CACertificateInfo> caCertInfoList = new LinkedList<CACertificateInfo>();
        caCertInfoList.add(prepareCACertificateInfo());
        caCertInfoList.add(prepareCACertInfo());

        return caCertInfoList;

    }

    /**
     * This method used to prepare CDPSEntityData and return it.
     * 
     * @return
     */
    protected CDPSEntityData prepareCDPSEntityData() {

        String caName = "nu_oam_ca";
        String certSerialNumber = "204173BB72886E4B1CB6700267AA3B3D";
        try {
            crl = getX509CRL("src/test/resources/crls/testCA.crl");
        } catch (FileNotFoundException | CRLException | CertificateException e) {
        }
        int id = 101010;

        CDPSEntityData entity = new CDPSEntityData();
        entity.setCaName(caName);
        entity.setCertSerialNumber(certSerialNumber);
        entity.setCrl(crl);
        entity.setId(id);

        return entity;

    }

    /**
     * This method used to prepare CRLInfo and return it.
     * 
     * @return
     */
    protected CRLInfo prepareCRLInfo() {

        try {
            crl = getX509CRL("src/test/resources/crls/testCA.crl");
        } catch (FileNotFoundException | CRLException | CertificateException e) {
        }

        CRLInfo crlInfo = new CRLInfo();
        crlInfo.setCaCertificateInfo(prepareCACertificateInfo());
        crlInfo.setEncodedCRL(crl);

        return crlInfo;

    }

    /**
     * This method used to prepare CRLInfo and return it.
     * 
     * @return
     */
    protected CRLInfo prepareCRLInfoEmpty() {

        CRLInfo crlInfo = new CRLInfo();

        return crlInfo;

    }

    /**
     * This method used to prepare List<CRLInfo> and return it.
     * 
     * @return
     */
    protected List<CRLInfo> prepareCRLInfoList() {

        List<CRLInfo> crlInfoList = new LinkedList<CRLInfo>();
        crlInfoList.add(prepareCRLInfo());

        return crlInfoList;
    }

    /**
     * This method used to prepare CDPSEntityData and return it.
     * 
     * @return
     */
    protected CDPSEntityData prepareCDPSEntyData() {

        String caName = "CRL_ENM_CA";
        String certSerialNumber = "2014TYUP67YTFR35GH5689YH23ER45TD";
        try {
            crl = getX509CRL("src/test/resources/crls/testCA.crl");
        } catch (FileNotFoundException | CRLException | CertificateException e) {
        }
        int id = 101011;

        CDPSEntityData entity = new CDPSEntityData();
        entity.setCaName(caName);
        entity.setCertSerialNumber(certSerialNumber);
        entity.setCrl(crl);
        entity.setId(id);

        return entity;

    }

    /**
     * This method used to prepare List<CDPSEntityData> and return it.
     * 
     * @return
     */
    protected List<CDPSEntityData> prepareCDPSEntityDataList() {

        List<CDPSEntityData> entities = new LinkedList<CDPSEntityData>();
        entities.add(prepareCDPSEntityData());
        entities.add(prepareCDPSEntyData());

        return entities;
    }

    private byte[] getX509CRL(String fileName) throws FileNotFoundException, CRLException, java.security.cert.CertificateException {

        FileInputStream inputStream = new FileInputStream(fileName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509CRL x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);

        return x509crl.getEncoded();
    }
}
