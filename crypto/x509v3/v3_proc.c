ASN1_SEQUENCE(PROCURATION_SYNTAX) = {
	ASN1_EXP_OPT(PROCURATION_SYNTAX, country, ASN1_PRINTABLESTRING, 1), 
	ASN1_EXP_OPT(PROCURATION_SYNTAX, typeOfSubstitution, DIRECTORYSTRING, 2),
	ASN1_EXP(PROCURATION_SYNTAX, signingFor, SIGNING_FOR, 3),
} ASN1_SEQUENC_END(PROCURATION_SYNTAX)

ASN1_CHOICE(SIGNING_FOR) = {
	ASN1_SIMPLE(SIGNING_FOR, thirdPerson, GENERAL_NAME),
	ASN1_SIMPLE(SIGNING_FOR, certRef, ISSUER_SERIAL),
} ASN1_CHOICE_END (SIGNING_FOR)

ASN1_SEQUENCE(ISSUER_SERIAL) = {
	ASN1_SIMPLE(ISSUER_SERIAL, issuer, GENERAL_NAMES),
	ASN1_SIMPLE(ISSUER_SERIAL, serial, ASN1_INTEGER),
	ASN1_OPT(ISSUER_SERIAL, issuerUID, ASN1_BIT_STRING),
} ASN1_SEQUENC_END(ISSUER_SERIAL)

IMPLEMENT_ASN1_FUNCTIONS(SIGNING_FOR)
IMPLEMENT_ASN1_FUNCTIONS(ISSUER_SERIAL)
IMPLEMENT_ASN1_FUNCTIONS(PROCURATION_SYNTAX)

static int i2r_PROCURATION_SYNTAX(const struct v3_ext_method *method, void *in,
                                BIO *bp, int ind);

const X509V3_EXT_METHOD v3_ext_admission = {
    NID_x509ExtProcuration,   /* .ext_nid = */ ---> TODO NID
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

static int i2r_PROCURATION_SYNTAX(const struct v3_ext_method *method, void *in,
                                BIO *bp, int ind)
{
    PROCURATION_SYNTAX * procuration = (PROCURATION_SYNTAX *)in;
    int i, j, k;

    if (procuration->country != NULL) {
        if (BIO_printf(bp, "%*scountry:\n", ind, "") <= 0
            || BIO_printf(bp, "%*s  ", ind, "") <= 0
            || GENERAL_NAME_print(bp, procuration->country) <= 0 ---> XXX
            || BIO_printf(bp, "\n") <= 0)
            goto err;
    }

    if (procuration->typeOfSubstitution != NULL) {
        if (BIO_printf(bp, "%*stypeOfSubstitution:\n", ind, "") <= 0
            || BIO_printf(bp, "%*s  ", ind, "") <= 0
            || GENERAL_NAME_print(bp, procutation->typeOfSubstitution) <= 0 ---> XXX
            || BIO_printf(bp, "\n") <= 0)
            goto err;
    }

    SIGNING_FOR* signingFor = procuration->signingFor;

    // TODO CHOICE..



const GENERAL_NAMES *ISSUER_SERIAL_get0_issuer(const ISSUER_SERIAL *is)
{
    return is->issuer;
}

void ISSUER_SERIAL_set0_issuer(ISSUER_SERIAL *is, GENERAL_NAMES* i) 
{
    GENERAL_NAMES_free(is->issuer);
    is->issuer = i;
}

const ASN1_INTEGER *ISSUER_SERIAL_get0_serial(const ISSUER_SERIAL *is)
{
    return is->serial;
}

void ISSUER_SERIAL_set0_serial(ISSUER_SERIAL *is, ASN1_INTEGER* s)
{
    ASN1_INTEGER_free(is->serial);
    is->serial = s;
}

const ASN1_BIT_STRING *ISSUER_SERIAL_get0_issuerUID(const ISSUER_SERIAL *is)
{
    return is->issuerUID;
}

void ISSUER_SERIAL_set0_issuerUID(ISSUER_SERIAL *is, ASN1_BIT_STRING* iuid)
{
    ASN1_BIT_STRING_free(is->issuerUID);
    is->issuerUID = iuid;
}

const GENERAL_NAME *SIGNING_FOR_get0_thirdPerson(const SIGNING_FOR *sf)
{
    return sf->thirdPerson;
}

void SIGNING_FOR_set0_thirdPerson(SIGNING_FOR *sf, GENERAL_NAME* tp)
{
    GENERAL_NAME_free(sf->thirdPerson);
    sf->thirdPerson = tp;
}

const ISSUER_SERIAL *SIGNING_FOR_get0_certRef(const SIGNING_FOR *sf) 
{
    return sf->certRef;
}

void SIGNING_FOR_set0_certRef(SIGNING_FOR *sf, ISSUER_SERIAL* cr)
{
    ISSUER_SERIAL_free(sf->certRef);
    sf->certRef = cr;
}

const ASN1_PRINTABLESTRING *PROCURATION_SYNTAX_get0_country(const PROCURATION_SYNTAX *ps)
{
    return ps->country;
}

void PROCUATION_SYNTAX_set0_certRef(PROCURATION_SYNTAX *ps, ASN1_PRINTABLESTRING* c)
{
    ASN1_PRINTABLESTRING_free(ps->country);
    ps->country = c;
}

const ASN1_STRING *PROCURATION_SYNTAX_get0_typeOfSubstitution(const PROCURATION_SYNTAX *ps)
{
    return ps->typeofSubstitution;
}

void PROCUATION_SYNTAX_set0_typeOfSubstitution(PROCURATION_SYNTAX *ps, ASN1_STRING* tos)
{
    ASN1_IA5STRING_free(ps->typeOfSubstitution);
    ps->typeOfSubstitution = tos;
}

const SIGNING_FOR *PROCURATION_SYNTAX_get0_signingFor(const PROCURATION_SYNTAX *ps)
{
    return ps->signingFor;
}

void PROCUATION_SYNTAX_set0_signingFor(PROCURATION_SYNTAX *ps, SIGNING_FOR* sf)
{
    SIGNING_FOR_free(ps->signingFor;
    ps->signingFor = sf;
}

.... i2r functions ....
