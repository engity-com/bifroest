package common

import "iter"

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
