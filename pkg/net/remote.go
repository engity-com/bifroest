package net

type Remote interface {
	User() string
	Host() Host
	String() string
}
