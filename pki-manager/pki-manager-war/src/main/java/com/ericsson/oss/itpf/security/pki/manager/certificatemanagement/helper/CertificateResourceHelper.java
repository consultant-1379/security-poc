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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper;

import static com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util.Constants.*;

import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.interfaces.*;
import java.util.*;

import javax.inject.Inject;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreFileWriterFactory;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.dto.DownloadDTO;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.filter.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util.CertificateUtil;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.rest.common.KeyStoreHelper;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.CommonUtil;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.SubjectUtils;

/**
 * Helper class for CertificateResource to prepare Response
 * 
 */
public class CertificateResourceHelper {

    @Inject
    private CertificateUtil certificateUtil;

    @Inject
    private CommonUtil commonUtil;

    @Inject
    KeyStoreHelper keyStoreHelper;

    KeyStoreFileWriterFactory keyStoreFileWriterFactory;

    @Inject
    Logger logger;

    /**
     * Split all properties with comma(,) and generate properties set
     * 
     * @param properties
     *            properties string separated by comma
     * @return set of properties
     */
    public Set<String> getIgnoredProperties(final String properties) {
        final StringTokenizer excludedProperties = new StringTokenizer(properties, ",");
        final Set<String> detailsFilterProperties = new HashSet<String>();
        while (excludedProperties.hasMoreTokens()) {
            detailsFilterProperties.add(excludedProperties.nextToken());
        }
        return detailsFilterProperties;
    }

    /**
     * Builds certificate basic details.
     * 
     * @param certificateBasicDetailsList
     *            {@link CertificateBasicDetailsDTO} List
     * @param certificate
     *            The Certificate object
     */
    public CertificateBasicDetailsDTO getCertificateBasicDetailsList(final Certificate certificate) {

        final EntityType entityType = certificateUtil.getEntityType(certificate.getX509Certificate().getBasicConstraints());
        String subjectDN = null;
        final String actualIssuerDN = new X500Name(certificate.getX509Certificate().getIssuerX500Principal().getName()).toString();
        /* CA X509Certificate Subject Dn RDNs are getting stored in the DB in the reverse order*/
        final String[] issuerRDNList = SubjectUtils.splitDNs(actualIssuerDN);
        final StringBuilder x500IssuerDN = new StringBuilder(actualIssuerDN.length());
        x500IssuerDN.append(issuerRDNList[issuerRDNList.length - 1]);
        for (int index = issuerRDNList.length - 2; index >= 0; index--) {
            x500IssuerDN.append(',');
            x500IssuerDN.append(issuerRDNList[index]);
        }

        final String reversedIssuerDN = x500IssuerDN.toString();
        String serialNumber = null;
        if (certificate.getSubject() != null) {
            subjectDN = certificate.getSubject().toASN1String();
        }
        if (certificate.getSerialNumber() != null) {
            serialNumber = certificate.getSerialNumber();
        }

        final CertificateBasicDetailsDTO certificateBasicDetails = new CertificateBasicDetailsBuilder().id(certificate.getId()).signatureAlgorithm(certificate.getX509Certificate().getSigAlgName())
                .type(entityType).subject(subjectDN).notBefore(certificate.getNotBefore()).notAfter(certificate.getNotAfter()).status(certificate.getStatus()).issuer(reversedIssuerDN)
                .serialNumber(serialNumber).build();

        return certificateBasicDetails;
    }

    /**
     * Builds certificate basic details and extensions
     *
     * @param certificate
     *            The certificate object
     * @return returns {@link CertificateResponseDTO}
     *
     * @throws CertificateParsingException
     *             throws exception while parsing Certificate Extensions
     * @throws IOException
     *             throws exception while parsing Certificate Extensions
     */
    public CertificateResponseDTO getCertificateResponse(final Certificate certificate) throws CertificateParsingException, IOException {

        String subjectAltName = null;
        String subjectDN = null;
        final String issuerDN = new X500Name(certificate.getX509Certificate().getIssuerX500Principal().getName()).toString();
        if (certificate.getSubjectAltName() != null) {
            subjectAltName = certificateUtil.getSubjectAltName(certificate.getSubjectAltName());
        }

        if (certificate.getSubject() != null) {
            subjectDN = certificate.getSubject().toASN1String();
        }

        final Integer keySize = getKeySize(certificate.getX509Certificate().getPublicKey());

        final EntityType entityType = certificateUtil.getEntityType(certificate.getX509Certificate().getBasicConstraints());

        final CertificateBasicDetailsDTO certificateBasicDetails = new CertificateBasicDetailsBuilder().id(certificate.getId()).type(entityType).notAfter(certificate.getNotAfter())
                .notBefore(certificate.getNotBefore()).status(certificate.getStatus()).subject(subjectDN).issuer(issuerDN).keySize(keySize)
                .signatureAlgorithm(certificate.getX509Certificate().getSigAlgName()).build();

        final CertificateExtensionsResponseDTO certificateExtensionsDetails = new CertificateExtensionsResponseBuilder().subjectAltName(subjectAltName)
                .keyPurposeIds(commonUtil.getExtendedKeyUsage(certificate.getX509Certificate().getExtendedKeyUsage()))
                .keyUsages(certificateUtil.getKeyUsage(certificate.getX509Certificate().getKeyUsage())).cRLDistributionPoints(commonUtil.getCRLDistributionPoint(certificate.getX509Certificate()))
                .build();

        final CertificateResponseDTO certificateResponseFilter = new CertificateBuilder().certificateBasicDetails(certificateBasicDetails).certificateExtensionsResponse(certificateExtensionsDetails)
                .build();
        return certificateResponseFilter;
    }

    private Integer getKeySize(final PublicKey publicKey) {

        if (publicKey instanceof DSAPublicKey) {
            final DSAPublicKey dsaPublicKey = (DSAPublicKey) publicKey;
            return dsaPublicKey.getY().bitLength();
        } else if (publicKey instanceof RSAPublicKey) {
            final RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            return rsaPublicKey.getModulus().bitLength();
        } else if (publicKey instanceof ECPublicKey) {
            final ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            return ecPublicKey.getParams().getOrder().bitLength();
        }
        return null;

    }

    /**
     * This method returns array of files, each containing certificate with the given type/extension.
     *
     * @param downloadDTO
     *            DownloadDTO contains the attribute certificateIds to get the certificates and type to return a certificate with the given type/extension.
     * @param certList
     *            list contains multiple certificate.
     * @return File tar.gz file containing all the selected certificates each one with the given type/extension for multiple certificates.
     */
    public File[] createKeyStoreForCertificates(final DownloadDTO downloadDTO, final List<Certificate> certList) {

        final File[] files = new File[certList.size()];
        String alias = null;

        for (int index = 0; index < certList.size(); index++) {

            alias = getAliasName(certList.get(index));

            final String serialNumber = certList.get(index).getSerialNumber();
            final String fileName = alias + FILE_NAME_SEPARATOR + serialNumber + FILE_NAME_SEPARATOR + System.currentTimeMillis();

            final KeyStoreInfo keyStoreInfo = keyStoreHelper.createKeyStoreInfo(fileName, downloadDTO.getFormat(), downloadDTO.getPassword(), alias);
            final String resourceName = keyStoreHelper.createKeyStore(keyStoreInfo, Arrays.asList(certList.get(index)));
            final File file = new File(Constants.TMP_DIR + Constants.FILE_SEPARATOR + resourceName);

            files[index] = file;
        }
        return files;

    }

    private String getAliasName(final Certificate certificate) {

        String alias = null;

        if (certificate.getSubject() != null && !certificate.getSubject().toASN1String().isEmpty()) {
            alias = getCommonName(certificate.getSubject().getSubjectFields());
            if (alias == null) {
                alias = CERTIFICATE_FILE_NAME_PREFIX;
            }
        } else {
            alias = CERTIFICATE_FILE_NAME_PREFIX;
        }

        return alias;
    }

    private String getCommonName(final List<SubjectField> subjectFields) {

        for (final SubjectField subjectField : subjectFields) {
            if (subjectField.getType() == SubjectFieldType.COMMON_NAME) {
                if (!subjectField.getValue().isEmpty()) {
                    if (subjectField.getValue().contains(",")) {
                        return subjectField.getValue().replace("," , "_");
                    } else {
                        return subjectField.getValue();
                    }
                } else {
                    return CERTIFICATE_FILE_NAME_PREFIX;
                }
            }
        }
        return null;
    }

    /**
     * returns latest 10 certificates for certificate Summary
     * 
     * @param certificates
     *            list of certificates
     * @return returns latest ten certificates
     */
    public List<Certificate> getLatestCertificatesForSummary(List<Certificate> certificates) {
        if (certificates.size() > 10) {

            certificates = certificates.subList(0, 9);
        }
        return certificates;
    }

}
