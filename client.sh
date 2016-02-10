#!/bin/bash
KRB5_TRACE=/dev/stdout KRB5_CONFIG=krb5.conf ./gssapi-test -m client -n testservice -d
