ARG ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_NAME=eric-enm-credm-controller-base
ARG ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_REPO=armdocker.rnd.ericsson.se/proj-enm
#ARG ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_TAG=latest
ARG ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_TAG=POC

FROM ${ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_REPO}/${ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_NAME}:${ERIC_ENM_CREDM_CONTROLLER_BASE_IMAGE_TAG}

ARG BUILD_DATE=unspecified
ARG IMAGE_BUILD_VERSION=unspecified
ARG GIT_COMMIT=unspecified
ARG ISO_VERSION=unspecified
ARG RSTATE=unspecified

LABEL \
com.ericsson.product-number="CXC Placeholder" \
com.ericsson.product-revision=$RSTATE \
enm_iso_version=$ISO_VERSION \
org.label-schema.name="Credm Controller Init Container" \
org.label-schema.build-date=$BUILD_DATE \
org.label-schema.vcs-ref=$GIT_COMMIT \
org.label-schema.vendor="Ericsson" \
org.label-schema.version=$IMAGE_BUILD_VERSION \
org.label-schema.schema-version="1.0.0-rc1"

COPY ./image_content/ /credm/scripts/

#CMD /credm/scripts/runCronJob.sh && /bin/bash
CMD ["/credm/scripts/runCronJob.sh"]
