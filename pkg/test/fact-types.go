package test

// JSON cannot retain the integer/float distinction of integral Lua numbers.
// Check every modeled numeric identity before decoding into Go ID fields.
func validateFactIntegers(raw any) error {
	world, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	check := func(fields map[string]any, key string) error {
		if value, present := fields[key]; present {
			if _, integer := value.(int64); !integer {
				return invalid("account/group numeric identities require integers")
			}
		}
		return nil
	}
	if ids, ok := world["absentUIDs"].([]any); ok {
		for _, value := range ids {
			if _, integer := value.(int64); !integer {
				return invalid("absent UIDs require integers")
			}
		}
	}
	if accounts, ok := world["accounts"].([]any); ok {
		for _, item := range accounts {
			fields, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if err := check(fields, "uid"); err != nil {
				return err
			}
			if group, ok := fields["group"].(map[string]any); ok {
				if err := check(group, "gid"); err != nil {
					return err
				}
			}
			if groups, ok := fields["groups"].([]any); ok {
				for _, item := range groups {
					if group, ok := item.(map[string]any); ok {
						if err := check(group, "gid"); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}
