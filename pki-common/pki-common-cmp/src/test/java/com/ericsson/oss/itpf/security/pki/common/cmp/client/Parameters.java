package com.ericsson.oss.itpf.security.pki.common.cmp.client;

import com.ericsson.oss.itpf.security.pki.common.cmp.client.AbstractRequestResponse.WorkingMode;

public class Parameters {
    private String workingDirectory;
    private String vendorTrustedCA;
    private String nodeName;
    private String keyAlgorithm;
    private String signatureAlgorithm;
    private int keySize;
    private int threadId;
    private WorkingMode mode;
    private boolean isSendTransactionID;
    private String transactionID;
    private String recipientSubjectDN;
    private String url;
    private CertDataHolder entityCredential;
    private String tlsCAPath;
    private String ipsecCAPath;
    private boolean isTLS;
    private int keyLengthInRequest;
    private int validityInMinutes;
    private int postponeInMinutes;
    private int pvno;

    private boolean isValidProtectionAlgo = true;
    private boolean isValidHeader = true;
    private boolean isInDirectoryFormat = true;
    private boolean isValidRequestType = true;
    private boolean isValidKey = true;
    private boolean isValidProtectionBytes = true;
    private boolean isValidIAK = true;

    public boolean isValidIAK() {
        return isValidIAK;
    }

    public void setValidIAK(boolean isValidIAK) {
        this.isValidIAK = isValidIAK;
    }

    public boolean isValidProtectionBytes() {
        return isValidProtectionBytes;
    }

    public void setValidProtectionBytes(boolean isValidProtectionBytes) {
        this.isValidProtectionBytes = isValidProtectionBytes;
    }

    public boolean isValidKey() {
        return isValidKey;
    }

    public void setValidKey(boolean isValidKey) {
        this.isValidKey = isValidKey;
    }

    public boolean isValidProtectionAlgo() {
        return isValidProtectionAlgo;
    }

    public void setValidProtectionAlgo(boolean isValidProtectionAlgo) {
        this.isValidProtectionAlgo = isValidProtectionAlgo;
    }

    public boolean isValidRequestType() {
        return isValidRequestType;
    }

    public void setValidRequestType(boolean isValidRequestType) {
        this.isValidRequestType = isValidRequestType;
    }

    public boolean isInDirectoryFormat() {
        return isInDirectoryFormat;
    }

    public void setInDirectoryFormat(boolean isInDirectoryFormat) {
        this.isInDirectoryFormat = isInDirectoryFormat;
    }

    public boolean isValidHeader() {
        return isValidHeader;
    }

    public void setValidHeader(boolean isValidHeader) {
        this.isValidHeader = isValidHeader;
    }

    public int getPvno() {
        return pvno;
    }

    public void setPvno(int pvno) {
        this.pvno = pvno;
    }

    public String getWorkingDirectory() {
        return workingDirectory;
    }

    public void setWorkingDirectory(String workingDirectory) {
        this.workingDirectory = workingDirectory;
    }

    public String getVendorTrustedCA() {
        return vendorTrustedCA;
    }

    public void setVendorTrustedCA(String vendorTrustedCA) {
        this.vendorTrustedCA = vendorTrustedCA;
    }

    public String getNodeName() {
        return nodeName;
    }

    public void setNodeName(String nodeName) {
        this.nodeName = nodeName;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public int getThreadId() {
        return threadId;
    }

    public void setThreadId(int threadId) {
        this.threadId = threadId;
    }

    public boolean isSendTransactionID() {
        return isSendTransactionID;
    }

    public void setSendTransactionID(boolean isSendTransactionID) {
        this.isSendTransactionID = isSendTransactionID;
    }

    public String getRecipientSubjectDN() {
        return recipientSubjectDN;
    }

    public void setRecipientSubjectDN(String recipientSubjectDN) {
        this.recipientSubjectDN = recipientSubjectDN;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public CertDataHolder getEntityCredential() {
        return entityCredential;
    }

    public void setEntityCredential(CertDataHolder vendorCred) {
        this.entityCredential = vendorCred;
    }

    public String getTlsCAPath() {
        return tlsCAPath;
    }

    public void setTlsCAPath(String tlsCAPath) {
        this.tlsCAPath = tlsCAPath;
    }

    public String getIpsecCAPath() {
        return ipsecCAPath;
    }

    public void setIpsecCAPath(String ipsecCAPath) {
        this.ipsecCAPath = ipsecCAPath;
    }

    public boolean isTLS() {
        return isTLS;
    }

    public void setTLS(boolean isTLS) {
        this.isTLS = isTLS;
    }

    public int getKeyLengthInRequest() {
        return keyLengthInRequest;
    }

    public void setKeyLengthInRequest(int keyLengthInRequest) {
        this.keyLengthInRequest = keyLengthInRequest;
    }

    public String getRecipientCA() {
        return isTLS ? tlsCAPath : ipsecCAPath;
    }

    public int getValidityInMinutes() {
        return validityInMinutes;
    }

    public void setValidityInMinutes(int validityInMinutes) {
        this.validityInMinutes = validityInMinutes;
    }

    public int getPostponeInMinutes() {
        return postponeInMinutes;
    }

    public void setPostponeInMinutes(int postponeInMinutes) {
        this.postponeInMinutes = postponeInMinutes;
    }

    public String getTransactionID() {
        return transactionID;
    }

    public void setTransactionID(String transactionID) {
        this.transactionID = transactionID;
    }

    public WorkingMode getMode() {
        return mode;
    }

    public void setMode(WorkingMode mode) {
        this.mode = mode;
    }

}
