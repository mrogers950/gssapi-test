#!/bin/bash
KRB5_TRACE=/dev/stdout KRB5_CONFIG=krb5.conf KRB5_KTNAME=tsm.keytab ./gssapi-test -m server -n testservice -d
