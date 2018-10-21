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
