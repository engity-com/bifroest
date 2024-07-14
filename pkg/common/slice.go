package common

import "fmt"

func MapSlice[I any, O any](in []I, mapper func(I) O) []O {
	out := make([]O, len(in))
	for i, inV := range in {
		out[i] = mapper(inV)
	}
	return out
}

func MapSliceErr[I any, O any](in []I, mapper func(I) (O, error)) ([]O, error) {
	out := make([]O, len(in))
	for i, inV := range in {
		var err error
		if out[i], err = mapper(inV); err != nil {
			return nil, fmt.Errorf("[%d] %w", i, err)
		}
	}
	return out, nil
}
