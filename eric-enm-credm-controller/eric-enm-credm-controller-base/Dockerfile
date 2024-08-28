ARG ERIC_ENM_SLES_BASE_IMAGE_NAME=eric-enm-sles-base
ARG ERIC_ENM_SLES_BASE_IMAGE_REPO=armdocker.rnd.ericsson.se/proj-enm
ARG ERIC_ENM_SLES_BASE_IMAGE_TAG=1.29.0-6

FROM ${ERIC_ENM_SLES_BASE_IMAGE_REPO}/${ERIC_ENM_SLES_BASE_IMAGE_NAME}:${ERIC_ENM_SLES_BASE_IMAGE_TAG}

ARG BUILD_DATE=unspecified
ARG IMAGE_BUILD_VERSION=unspecified
ARG GIT_COMMIT=unspecified
ARG ISO_VERSION=unspecified
ARG RSTATE=unspecified
ARG NEXUS_BASE_POC_URL=https://arm1s11-eiffel004.eiffel.gic.ericsson.se:8443/nexus/service/local/artifact/maven/redirect?r=snapshots&g=com.ericsson.oss.itpf.poc.security


LABEL \
com.ericsson.product-number="CXC Placeholder" \
com.ericsson.product-revision=$RSTATE \
enm_iso_version=$ISO_VERSION \
org.label-schema.name="Credm Controller Base Image" \
org.label-schema.build-date=$BUILD_DATE \
org.label-schema.vcs-ref=$GIT_COMMIT \
org.label-schema.vendor="Ericsson" \
org.label-schema.version=$IMAGE_BUILD_VERSION \
org.label-schema.schema-version="1.0.0-rc1"

# install kubectl
# TODO use CCD data for kubernetes version
RUN curl -LO "https://arm.seli.gic.ericsson.se/artifactory/kubernetes-release-remote-2rc-cache/release/v1.21.1/bin/linux/amd64/kubectl" && \
    sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

#install helm
#RUN zypper -n install wget
#RUN wget https://get.helm.sh/helm-v3.0.2-linux-amd64.tar.gz && \
#    tar xvf helm-v3.0.2-linux-amd64.tar.gz && \
#    sudo mv linux-amd64/helm /usr/local/bin/

# install k8api for pyphon
RUN sudo zypper -n install python3-pip && \
    sudo pip3 install kubernetes==21.7.0 --trusted-host proj-eo-pypi-local

# build main directories
COPY ./image_content/ /credm/
RUN mkdir /credm/resources; mkdir /credm/scripts; mkdir /credm/src; mkdir /credm/certs; mkdir /var/log/credmcontroller

# install credentialmanagercli
#RUN curl -k -o /credm/resources/ERICcredentialmanagercli_CXP9031389-1.36.2.rpm https://arm901-eiffel004.athtem.eei.ericsson.se:8443/nexus/content/groups/enm_deploy_proxy/com/ericsson/oss/itpf/security/ERICcredentialmanagercli_CXP9031389/1.36.2/ERICcredentialmanagercli_CXP9031389-1.36.2.rpm
#RUN chmod 777 /credm/resources/ERICcredentialmanagercli_CXP9031389-1.36.2.rpm
#RUN sudo rpm -ivh /credm/resources/ERICcredentialmanagercli_CXP9031389-1.36.2.rpm

# install credentialamangercli
# RUN zypper download ERICcredentialmanagercli_CXP9031389 && \
#    rpm -ivh /var/cache/zypp/packages/enm_iso_repo/ERICcredentialmanagercli_CXP9031389*.rpm && \
#    zypper clean -a

# install credentialamangercli
RUN zypper install -y wget && \
    wget -q -O /tmp/ERICcredentialmanagercli_CXP9031389.rpm "${NEXUS_BASE_POC_URL}&a=ERICcredentialmanagercli_CXP9031389&v=1.0.1-SNAPSHOT&p=rpm" && \
    rpm -ivh /tmp/ERICcredentialmanagercli_CXP9031389.rpm && \
    zypper clean -a
