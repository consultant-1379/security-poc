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
package com.ericsson.oss.itpf.security.pki.manager.rest.mappers;

import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.CertificateRevocationInfoDTO;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.RevocationStatusDTO;

/**
 * This class prepares the DNBasedCertificateIdentifier info and RevokeStatus info by using CertificateRevokeDTO object
 * 
 * @author xnarsir
 *
 */
public class CertificateRevocationInfoMapper {

    /**
     * This method is used to prepare the DNBasedCertifiicateIdentifier from the CertificateRevocationInfoDTO
     * 
     * @param certificateRevocationInfoDTO
     *            It consists of serialNumber,issuer,subject,revocationReason.
     * @return DNBasedCertificateIdentifier consists of issuerDN,subjectDN and certificateSerialNumber
     * 
     */

    public DNBasedCertificateIdentifier getDnBasedCertificateIdentifier(final CertificateRevocationInfoDTO certificateRevocationInfoDTO) {
        final DNBasedCertificateIdentifier dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();
        dnBasedCertificateIdentifier.setCerficateSerialNumber(certificateRevocationInfoDTO.getSerialNumber());
        dnBasedCertificateIdentifier.setIssuerDN(certificateRevocationInfoDTO.getIssuer());
        dnBasedCertificateIdentifier.setSubjectDN(certificateRevocationInfoDTO.getSubject());
        return dnBasedCertificateIdentifier;
    }

    /**
     * This method is used prepare RevokeStatusDTO object from CertificiateRevokeDTO object.
     * 
     * @param certificateRevocationInfoDTO
     *            It contains serialNumber,issuer,subject,revocationReason
     * @return RevocationStatusDTO consists of serialNumber,issuer,subject and message
     * 
     */
    public RevocationStatusDTO getRevocationStatusDTO(final CertificateRevocationInfoDTO certificateRevocationInfoDTO, final String message, final int status, final String code) {
        final RevocationStatusDTO revocationStatusDTO = new RevocationStatusDTO();
        revocationStatusDTO.setSerialNumber(certificateRevocationInfoDTO.getSerialNumber());
        revocationStatusDTO.setIssuer(certificateRevocationInfoDTO.getIssuer());
        revocationStatusDTO.setSubject(certificateRevocationInfoDTO.getSubject());
        revocationStatusDTO.setStatus(status);
        revocationStatusDTO.setCode(code);
        revocationStatusDTO.setMessage(message);
        return revocationStatusDTO;
    }
}
