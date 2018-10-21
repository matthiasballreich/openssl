/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef HEADER_V3_PROCURATION_H
# define HEADER_V3_PROCURATION_H

struct ProcurationSyntax_st {
	ASN1_PRINTABLESTRING country;
	ASN1_STRING typeOfSubstitution; /* i.e. DIRECTORYSTRING */
	SIGNING_FOR* signingFor;
};

struct SigningFor_st {
	int type;
	union {
		GENERAL_NAME* thirdPerson;
		ISSUER_SERIAL* certRef;
	} d;
};

struct IssuerSerial_st {
	GENERAL_NAMES* issuer;
	ASN1_INTEGER serial;
	ASN1_BIT_STRING issuerUID;
};

#endif
