package test

import rt "github.com/arnodel/golua/runtime"

func (s *luaState) readPlatform(value rt.Value) (platformSpec, error) {
	var result platformSpec
	if value.IsNil() {
		return result, nil
	}
	table, ok := value.TryTable()
	if !ok {
		return result, invalid("platform must be a table")
	}
	if err := s.checkKeys(table, "os", "arch", "version"); err != nil {
		return result, err
	}
	for _, field := range []string{"os", "arch", "version"} {
		value := tableField(table, field)
		if value.IsNil() {
			continue
		}
		array, ok := value.TryTable()
		if !ok || array.Len() > 64 {
			return result, invalid("platform fields require arrays of at most 64 strings")
		}
		data, err := s.readTable(array, true, 0, new(int), map[*rt.Table]bool{})
		if err != nil {
			return result, err
		}
		values := make([]string, 0, len(data.([]any)))
		for _, item := range data.([]any) {
			plain, ok := item.(string)
			if !ok || len(plain) == 0 || len(plain) > 256 {
				return result, invalid("platform values require nonempty strings of at most 256 bytes")
			}
			if field != "version" && !platformToken.MatchString(plain) {
				return result, invalid("platform os/arch values require lowercase identifiers")
			}
			values = append(values, plain)
		}
		switch field {
		case "os":
			result.os = values
		case "arch":
			result.arch = values
		case "version":
			result.versions = make([]versionSelector, 0, len(values))
			for _, plain := range values {
				s.r.RequireCPU(256)
				s.r.RequireMem(1024)
				selector, err := parseVersionSelector(plain)
				if err != nil {
					return result, err
				}
				result.versions = append(result.versions, selector)
			}
		}
	}
	return result, nil
}
