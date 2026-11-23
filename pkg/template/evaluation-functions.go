package template

import "strings"

type evaluationFunctionKind uint8

const (
	evaluationFunctionUnknown evaluationFunctionKind = iota
	evaluationFunctionLocal
	evaluationFunctionScoped
	evaluationFunctionClock
	evaluationFunctionEntropy
	evaluationFunctionNetwork
	evaluationFunctionPlatform
	evaluationFunctionUnordered
)

// This is an explicit inventory of Bifroest's function registry, including
// Sprig v3.3.0. Sprig's HermeticTxtFuncMap alone is insufficient: it still
// includes shuffle, randInt, certificate generation, durationRound and others.
// Local means no ambient dependency for controlled input values, not that a
// function cannot mutate its input (set/merge) or consume substantial resources.
// New, unclassified registry entries are denied by Evaluation, never allowed.
var evaluationFunctionGroups = []struct {
	kind  evaluationFunctionKind
	names string
}{
	{evaluationFunctionLocal, `
		hello duration date_modify dateModify must_date_modify mustDateModify unixEpoch
		abbrev abbrevboth trunc trim upper lower title untitle substr repeat trimall
		trimAll trimSuffix trimPrefix nospace initials swapcase snakecase camelcase
		kebabcase wrap wrapWith contains hasPrefix hasSuffix quote squote cat indent
		nindent replace plural sha1sum sha256sum sha512sum adler32sum toString atoi
		int64 int float64 seq toDecimal split splitList splitn toStrings until untilStep
		add1 add sub div mod mul add1f addf subf divf mulf biggest max min maxf minf
		ceil floor round join sortAlpha default empty coalesce all any compact
		mustCompact fromJson toJson toPrettyJson toRawJson mustFromJson mustToJson
		mustToPrettyJson mustToRawJson ternary deepCopy mustDeepCopy typeOf typeIs
		typeIsLike kindOf kindIs deepEqual base dir clean ext isAbs b64enc b64dec
		b32enc b32dec tuple list dict get set unset hasKey pluck pick omit merge
		mergeOverwrite mustMerge mustMergeOverwrite append push mustAppend mustPush
		prepend mustPrepend first mustFirst rest mustRest last mustLast initial
		mustInitial reverse mustReverse uniq mustUniq without mustWithout has mustHas
		slice mustSlice concat dig chunk mustChunk derivePassword buildCustomCert
		decryptAES semver semverCompare fail regexMatch mustRegexMatch regexFindAll
		mustRegexFindAll regexFind mustRegexFind regexReplaceAll mustRegexReplaceAll
		regexReplaceAllLiteral mustRegexReplaceAllLiteral regexSplit mustRegexSplit
		regexQuoteMeta urlParse urlJoin pathJoin fingerprint format
	`},
	{evaluationFunctionScoped, `firstMatching lastMatching file stat fileExists dirExists env expandenv now`},
	{evaluationFunctionClock, `ago date date_in_zone dateInZone durationRound htmlDate htmlDateInZone mustToDate toDate`},
	{evaluationFunctionEntropy, `randAlphaNum randAlpha randAscii randNumeric randBytes randInt shuffle uuidv4 bcrypt htpasswd genPrivateKey genCA genCAWithKey genSelfSignedCert genSelfSignedCertWithKey genSignedCert genSignedCertWithKey encryptAES`},
	{evaluationFunctionNetwork, `getHostByName`},
	{evaluationFunctionPlatform, `osBase osClean osDir osExt osIsAbs osJoin`},
	// Sorting these results would silently change existing policy semantics.
	{evaluationFunctionUnordered, `keys values`},
}

var evaluationFunctionKinds = func() map[string]evaluationFunctionKind {
	result := make(map[string]evaluationFunctionKind)
	for _, group := range evaluationFunctionGroups {
		for _, name := range strings.Fields(group.names) {
			result[name] = group.kind
		}
	}
	return result
}()
