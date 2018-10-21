/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/conf.h>
#include <openssl/ossl_typ.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <openssl/x509v3.h>

#include <openssl/safestack.h>

#include "v3_proc.h"
#include "ext_dat.h"

ASN1_SEQUENCE(ISSUER_SERIAL) = {
	ASN1_SIMPLE(ISSUER_SERIAL, issuer, GENERAL_NAMES), //EMBED = incomplete type
	ASN1_EMBED(ISSUER_SERIAL, serial, ASN1_INTEGER),
	ASN1_OPT_EMBED(ISSUER_SERIAL, issuerUID, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(ISSUER_SERIAL)

ASN1_CHOICE(SIGNING_FOR) = {
	ASN1_SIMPLE(SIGNING_FOR, d.thirdPerson, GENERAL_NAME), //EMBED = error
	ASN1_SIMPLE(SIGNING_FOR, d.certRef, ISSUER_SERIAL), //EMBED
} ASN1_CHOICE_END(SIGNING_FOR)

ASN1_SEQUENCE(PROCURATION_SYNTAX) = {
	ASN1_EXP_OPT_EMBED(PROCURATION_SYNTAX, country, ASN1_PRINTABLESTRING, 1), 
	ASN1_EXP_OPT_EMBED(PROCURATION_SYNTAX, typeOfSubstitution, DIRECTORYSTRING, 2),
	ASN1_EXP(PROCURATION_SYNTAX, signingFor, SIGNING_FOR, 3), //EMBED?
} ASN1_SEQUENCE_END(PROCURATION_SYNTAX)

IMPLEMENT_ASN1_FUNCTIONS(SIGNING_FOR)
IMPLEMENT_ASN1_FUNCTIONS(ISSUER_SERIAL)
IMPLEMENT_ASN1_FUNCTIONS(PROCURATION_SYNTAX)

static int i2r_PROCURATION_SYNTAX(const struct v3_ext_method *method, void *in,
                                BIO *bp, int ind);

const X509V3_EXT_METHOD v3_ext_procuration = {
    NID_x509ExtProcuration,   /* .ext_nid = */
    0,                      /* .ext_flags = */
    ASN1_ITEM_ref(PROCURATION_SYNTAX), /* .it = */
    NULL, NULL, NULL, NULL,
    NULL,                   /* .i2s = */
    NULL,                   /* .s2i = */
    NULL,                   /* .i2v = */
    NULL,                   /* .v2i = */
    &i2r_PROCURATION_SYNTAX,  /* .i2r = */
    NULL,                   /* .r2i = */
    NULL                    /* extension-specific data */
};


static int i2r_ISSUER_SERIAL(const struct v3_ext_method *method, void *in,
                                BIO *bp, int ind)
{
    ISSUER_SERIAL * issuerSerial = (ISSUER_SERIAL*) in;
    int i;

    if (issuerSerial == NULL)
        return 0;

    for (i = 0; i < sk_GENERAL_NAME_num(issuerSerial->issuer); i++) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(issuerSerial->issuer, i);

        if (gen != NULL) {
            if (BIO_printf(bp, "%*s  issuer: ", ind, "") <= 0
                || GENERAL_NAME_print(bp, gen) <= 0)
                goto err;
        }
    } 

    if (&issuerSerial->serial != NULL) {
        if (BIO_printf(bp, "\n%*s  serial: ", ind, "") <= 0
            || i2a_ASN1_INTEGER(bp, &issuerSerial->serial) <= 0)
            goto err;
    }

    if (&issuerSerial->issuerUID != NULL) {
        if (BIO_printf(bp, "\n%*s  issuerUID: ", ind, "") <= 0
            || ASN1_STRING_print_ex(bp, &issuerSerial->issuerUID, 0) <= 0)
            goto err;
    }
    return 1;

err:
    return 0;
}

static int i2r_SIGNING_FOR(const struct v3_ext_method *method, void *in,
                                BIO *bp, int ind)
{
    SIGNING_FOR * signingFor = (SIGNING_FOR*) in;

    if (signingFor == NULL)
        return 0;

    switch (signingFor->type) {
        case 0:
            if (signingFor->d.thirdPerson != NULL) {
                if (BIO_printf(bp, "%*sthirdPerson: ", ind, "") <= 0
                || GENERAL_NAME_print(bp, signingFor->d.thirdPerson) <= 0)
                goto err;
            }
            break;
        case 1:
            if (signingFor->d.certRef != NULL) {
                if (BIO_printf(bp, "%*scertRef:\n", ind, "") <= 0
                || i2r_ISSUER_SERIAL(method, signingFor->d.certRef, bp, ind) <= 0)
                goto err;
            }
            break;
        return 1;
    }
return 1;

err:
    return 0;
}

static int i2r_PROCURATION_SYNTAX(const struct v3_ext_method *method, void *in,
                                BIO *bp, int ind)
{
    PROCURATION_SYNTAX * procuration = (PROCURATION_SYNTAX *)in;
    
    if (&procuration->country != NULL) {
        if (BIO_printf(bp, "%*scountry: ", ind, "") <= 0
            || ASN1_STRING_print_ex(bp, &procuration->country, 0) <= 0
            || BIO_printf(bp, "\n") <= 0)
            goto err;
    }

    if (&procuration->typeOfSubstitution != NULL) {
        if (BIO_printf(bp, "%*stypeOfSubstitution: ", ind, "") <= 0
            || ASN1_STRING_print_ex(bp, &procuration->typeOfSubstitution, 0) <= 0
            || BIO_printf(bp, "\n") <= 0)
            goto err;
    }

    if (procuration->signingFor != NULL) {
        if (i2r_SIGNING_FOR(method, procuration->signingFor, bp, ind) <= 0)
            goto err;
    }
    
    return 1;

err:
    return 0;
}

const GENERAL_NAMES *ISSUER_SERIAL_get0_issuer(const ISSUER_SERIAL *is)
{
    return is->issuer;
}

void ISSUER_SERIAL_set0_issuer(ISSUER_SERIAL *is, GENERAL_NAMES *i) 
{
    GENERAL_NAMES_free(is->issuer);
    is->issuer = i;
}

const ASN1_INTEGER ISSUER_SERIAL_get0_serial(const ISSUER_SERIAL *is)
{
    return is->serial;
}

void ISSUER_SERIAL_set0_serial(ISSUER_SERIAL *is, ASN1_INTEGER s)
{;
    is->serial = s;
}

const ASN1_BIT_STRING ISSUER_SERIAL_get0_issuerUID(const ISSUER_SERIAL *is)
{
    return is->issuerUID;
}

void ISSUER_SERIAL_set0_issuerUID(ISSUER_SERIAL *is, ASN1_BIT_STRING iuid)
{
    is->issuerUID = iuid;
}

const GENERAL_NAME *SIGNING_FOR_get0_thirdPerson(const SIGNING_FOR *sf)
{
    return sf->d.thirdPerson;
} 

void SIGNING_FOR_set0_thirdPerson(SIGNING_FOR *sf, GENERAL_NAME *tp)
{
    GENERAL_NAME_free(sf->d.thirdPerson);
    sf->d.thirdPerson = tp;
}

const ISSUER_SERIAL *SIGNING_FOR_get0_certRef(const SIGNING_FOR *sf) 
{
    return sf->d.certRef;
}

void SIGNING_FOR_set0_certRef(SIGNING_FOR *sf, ISSUER_SERIAL *cr)
{
    ISSUER_SERIAL_free(sf->d.certRef);
    sf->d.certRef = cr;
}

const ASN1_PRINTABLESTRING PROCURATION_SYNTAX_get0_country(const PROCURATION_SYNTAX *ps)
{
    return ps->country;
}

void PROCURATION_SYNTAX_set0_country(PROCURATION_SYNTAX *ps, ASN1_PRINTABLESTRING c)
{
    ps->country = c;
}

const ASN1_STRING PROCURATION_SYNTAX_get0_typeOfSubstitution(const PROCURATION_SYNTAX *ps)
{
    return ps->typeOfSubstitution;
}

void PROCURATION_SYNTAX_set0_typeOfSubstitution(PROCURATION_SYNTAX *ps, ASN1_STRING tos)
{
    ps->typeOfSubstitution = tos;
}

const SIGNING_FOR *PROCURATION_SYNTAX_get0_signingFor(const PROCURATION_SYNTAX *ps)
{
    return ps->signingFor;
}

void PROCURATION_SYNTAX_set0_signingFor(PROCURATION_SYNTAX *ps, SIGNING_FOR *sf)
{
    SIGNING_FOR_free(ps->signingFor);
    ps->signingFor = sf;
}