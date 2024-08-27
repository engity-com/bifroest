package session

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_isReaderEqualToBytes(t *testing.T) {
	cases := []struct {
		left     []byte
		right    []byte
		expected bool
	}{{
		left:     createBytes(t, 10*1024),
		right:    createBytes(t, 10*1024),
		expected: true,
	}, {
		left:     createBytes(t, 1*1024),
		right:    createBytes(t, 1*1024),
		expected: true,
	}, {
		left:     createBytes(t, 3*1024),
		right:    createBytes(t, 3*1024),
		expected: true,
	}, {
		left:     createBytes(t, 4*1024),
		right:    createBytes(t, 4*1024),
		expected: true,
	}, {
		left:     createBytes(t, (4*1024)+1),
		right:    createBytes(t, (4*1024)+1),
		expected: true,
	}, {
		left:     createBytes(t, (4*1024)-1),
		right:    createBytes(t, (4*1024)-1),
		expected: true,
	}, {
		left:     createBytes(t, 6*1024),
		right:    createBytes(t, 6*1024),
		expected: true,
	}, {
		left:     createBytes(t, 10*1024),
		right:    createBytes(t, (10*1024)-1),
		expected: false,
	}, {
		left:     createBytes(t, 10*1024),
		right:    createBytes(t, (10*1024)-1),
		expected: false,
	}, {
		left:     createBytes(t, 1*1024),
		right:    createBytes(t, 10*1024),
		expected: false,
	}, {
		left:     createBytes(t, 4*1024),
		right:    createBytes(t, 10*1024),
		expected: false,
	}, {
		left:     createBytes(t, 10*1024),
		right:    createBytes(t, 1*1024),
		expected: false,
	}, {
		left:     createBytes(t, 4*1024),
		right:    createBytes(t, 1*1024),
		expected: false,
	}}
	for i, c := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			actual, actualErr := isReaderEqualToBytes(bytes.NewReader(c.left), c.right)
			require.NoError(t, actualErr)
			assert.Equal(t, c.expected, actual)
		})
	}
}

func createBytes(t testing.TB, l int) []byte {
	b := make([]byte, l)

	n, err := rand.New(rand.NewSource(666)).Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != l {
		t.Errorf("rand.Reader.Read returned %d bytes, expected %d", n, l)
	}

	return b
}
