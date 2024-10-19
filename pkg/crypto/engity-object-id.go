package crypto

import "encoding/asn1"

func CutEngityObjectIdPrefix(in asn1.ObjectIdentifier) (rest asn1.ObjectIdentifier) {
	if len(in) < 7 {
		return nil
	}
	if in[0] == 1 &&
		in[1] == 3 &&
		in[2] == 6 &&
		in[3] == 1 &&
		in[4] == 4 &&
		in[5] == 1 &&
		in[6] == 60498 {
		return in[7:]
	}
	return nil
}

func PrefixWithEngityObjectId(in asn1.ObjectIdentifier) asn1.ObjectIdentifier {
	return append(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 60498}, in...)
}
