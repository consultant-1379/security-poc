#!/bin/bash


versionSFWK=$(rpm -qa |grep ERICserviceframework4_CXP9037454 |awk -F "-" '{print $2}')

jar -uvf /ericsson/3pp/jboss/modules/system/layers/base/com/ericsson/oss/itpf/sdk/service-framework/4.x/sdk-security-accesscontrol-non-cdi-${versionSFWK}.jar /com/ericsson/oss/itpf/sdk/security/accesscontrol/classic/EAccessControlImpl.class
