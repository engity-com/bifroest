package common

import (
	"iter"
	"slices"
)

func JoinSeq[T any](seqs ...iter.Seq[T]) iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, seq := range seqs {
			for t := range seq {
				if !yield(t) {
					return
				}
			}
		}
	}
}

func JoinSeq2[K any, V any](seqs ...iter.Seq2[K, V]) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for _, seq := range seqs {
			for k, v := range seq {
				if !yield(k, v) {
					return
				}
			}
		}
	}
}

func SeqOf[T any](ts ...T) iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, t := range ts {
			if !yield(t) {
				return
			}
		}
	}
}

type KV[K any, V any] struct {
	K K
	V V
}

func Seq2Of[K any, V any](kvs ...KV[K, V]) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for _, kv := range kvs {
			if !yield(kv.K, kv.V) {
				return
			}
		}
	}
}

func Seq2ErrOf[T any](ts ...T) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		for _, t := range ts {
			if !yield(t, nil) {
				return
			}
		}
	}
}

func SingleSeqOf[T any](t T) iter.Seq[T] {
	return func(yield func(T) bool) {
		yield(t)
	}
}

func SingleSeq2Of[K any, V any](k K, v V) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		yield(k, v)
	}
}

func Collect[T any](in iter.Seq[T]) []T {
	return slices.Collect(in)
}

func CollectOrFail[T any](in iter.Seq2[T, error]) ([]T, error) {
	var vs []T
	for v, err := range in {
		if err != nil {
			return nil, err
		}
		vs = append(vs, v)
	}
	return vs, nil
}

func BatchOrFail[T any](size uint32, in iter.Seq2[T, error]) iter.Seq2[[]T, error] {
	return func(yield func([]T, error) bool) {
		batch := make([]T, size)
		i := uint32(0)
		for v, err := range in {
			if err != nil {
				if !yield(nil, err) {
					return
				}
				continue
			}
			batch[i] = v
			i++
			if i == size {
				if !yield(batch, nil) {
					return
				}
			}
			i = 0
		}
	}
}
