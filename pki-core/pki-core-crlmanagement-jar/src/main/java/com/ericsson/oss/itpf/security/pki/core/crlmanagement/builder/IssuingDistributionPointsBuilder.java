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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.builder;

import java.io.IOException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPointName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.IssuingDistributionPoint;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.InvalidCRLExtensionException;

/**
 * Class that builds {@link org.bouncycastle.asn1.x509.IssuingDistributionPoint} extension for {@link X509CRL}.
 * 
 */
public class IssuingDistributionPointsBuilder {

    @Inject
    Logger logger;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Builds {@link org.bouncycastle.asn1.x509.IssuingDistributionPoint} extension for CRL generation.
     * 
     * @param crlGenerationInfo
     *            {@link CrlGenerationInfo} model that contains Issuing Distribution point extension.
     * @return Issuing Distribution point extension built for CRL.
     * @throws InvalidCRLExtensionException
     *             Thrown in case of Invalid CRL Extension found.
     */
    public Extension buildIssuingDistributionPoint(final CrlGenerationInfo crlGenerationInfo) throws InvalidCRLExtensionException {

        final IssuingDistributionPoint issuingDistributionPoint = crlGenerationInfo.getCrlExtensions().getIssuingDistributionPoint();
        org.bouncycastle.asn1.x509.DistributionPointName iDPdistributionPointName = null;

        if (issuingDistributionPoint != null) {
            validateIDPExtension(issuingDistributionPoint);
            ReasonFlags reasonFlags = null;
            if (issuingDistributionPoint.getOnlySomeReasons() != null) {
                reasonFlags = new ReasonFlags(generateReasonFlags(issuingDistributionPoint.getOnlySomeReasons()));
            }
            final DistributionPointName distributionPointName = issuingDistributionPoint.getDistributionPoint();

            if (distributionPointName.getFullName() != null) {
                iDPdistributionPointName = getDistibutionPointNames(distributionPointName);
            } else if (distributionPointName.getNameRelativeToCRLIssuer() != null) {
                iDPdistributionPointName = getDistributionsPointByNameRelativeToCRLIssuer(distributionPointName);
            }
            final org.bouncycastle.asn1.x509.IssuingDistributionPoint issuingDistPoint = new org.bouncycastle.asn1.x509.IssuingDistributionPoint(iDPdistributionPointName,
                    issuingDistributionPoint.isOnlyContainsUserCerts(), issuingDistributionPoint.isOnlyContainsCACerts(), reasonFlags, issuingDistributionPoint.isIndirectCRL(),
                    issuingDistributionPoint.isOnlyContainsAttributeCerts());
            try {
            	 return  new Extension(Extension.issuingDistributionPoint, issuingDistributionPoint.isCritical(), new DEROctetString(issuingDistPoint));
            } catch (IOException ioException) {
                logger.error(ErrorMessages.EXTENSION_ENCODING_IS_INVALID, ioException);
                systemRecorder.recordError("PKI_CORE_ISSUING_DISTRIBUTION_POINTS_BUILDER.CRL_GENERATION_FAILURE", ErrorSeverity.ERROR, "IssuingDistributionPointsBuilder", "Generation of CRL",
                        "Error occured while preparing IssuingDistributionPoints due to improper extension encoding for the CRLGenerationInfo : " + crlGenerationInfo.getId() + ".");
                throw new InvalidCRLExtensionException(ErrorMessages.EXTENSION_ENCODING_IS_INVALID);
            }
        }
        return null;

    }

    private org.bouncycastle.asn1.x509.DistributionPointName getDistibutionPointNames(final DistributionPointName distributionPointName) {

        if (distributionPointName.getFullName() != null && distributionPointName.getFullName().size() > 0) {

            final List<GeneralName> iDPGeneralNameList = new ArrayList<GeneralName>();
            final List<String> issuingDistPointUrls = distributionPointName.getFullName();

            if (issuingDistPointUrls != null && issuingDistPointUrls.size() > 0) {
                for (final String idPUrl : issuingDistPointUrls) {
                    iDPGeneralNameList.add(new GeneralName(GeneralName.uniformResourceIdentifier, idPUrl));
                }
            }
            final GeneralNames iDPGeneralNames = new GeneralNames(iDPGeneralNameList.toArray(new GeneralName[0]));
            return new org.bouncycastle.asn1.x509.DistributionPointName(iDPGeneralNames);
}
return null;
    }

    private org.bouncycastle.asn1.x509.DistributionPointName getDistributionsPointByNameRelativeToCRLIssuer(final DistributionPointName distributionPointName) {

        if (distributionPointName.getNameRelativeToCRLIssuer() != null) {

            final List<GeneralName> cRLGeneralNameList = new ArrayList<GeneralName>();

            cRLGeneralNameList.add(new GeneralName(new X500Name(distributionPointName.getNameRelativeToCRLIssuer())));

            final GeneralNames cRLGeneralNames = new GeneralNames(cRLGeneralNameList.toArray(new GeneralName[0]));

           return new org.bouncycastle.asn1.x509.DistributionPointName(
                    org.bouncycastle.asn1.x509.DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER, cRLGeneralNames);
}
        return null;
    }

    private void validateIDPExtension(final IssuingDistributionPoint issuingDistributionPoint) {

        if ((issuingDistributionPoint.isOnlyContainsUserCerts() && (issuingDistributionPoint.isOnlyContainsCACerts() || issuingDistributionPoint.isOnlyContainsAttributeCerts()))
                || (issuingDistributionPoint.isOnlyContainsCACerts() && (issuingDistributionPoint.isOnlyContainsUserCerts() || issuingDistributionPoint.isOnlyContainsAttributeCerts()))
                || (issuingDistributionPoint.isOnlyContainsAttributeCerts() && (issuingDistributionPoint.isOnlyContainsUserCerts() || issuingDistributionPoint.isOnlyContainsCACerts()))) {
            throw new InvalidCRLExtensionException(ErrorMessages.INVALID_ISSUEING_DISTRIBUTION_POINT);
        }

    }

    /**
     * @param reasonFlags
     * @return
     * @throws InvalidCRLExtensionException
     */
    public int generateReasonFlags(final List<ReasonFlag> reasonFlags) throws InvalidCRLExtensionException {

        int reasonFlag = 0;

        for (final ReasonFlag reasonFlg : reasonFlags) {
            reasonFlag = reasonFlag | getReasonCodes(reasonFlg);
        }
        return reasonFlag;
    }

    private int getReasonCodes(final ReasonFlag reasonFlag) throws InvalidCRLExtensionException {

        switch (reasonFlag) {
        case UNUSED:
            return ReasonFlags.unused;
        case KEY_COMPROMISE:
            return ReasonFlags.keyCompromise;
        case CA_COMPROMISE:
            return ReasonFlags.cACompromise;
        case AFFILIATION_CHANGED:
            return ReasonFlags.affiliationChanged;
        case SUPERSEDED:
            return ReasonFlags.superseded;
        case CESSATION_OF_OPERATION:
            return ReasonFlags.cessationOfOperation;
        case CERTIFICATE_HOLD:
            return ReasonFlags.certificateHold;
        case PRIVILEGE_WITHDRAWN:
            return ReasonFlags.privilegeWithdrawn;
        case AA_COMPROMISE:
            return ReasonFlags.aACompromise;
        default:
            throw new InvalidCRLExtensionException(ErrorMessages.INVALID_REASON_CODE);
        }

    }

}
