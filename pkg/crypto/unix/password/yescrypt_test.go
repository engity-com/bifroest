package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestYescrypt_Validate(t *testing.T) {
	instance := Yescrypt{}

	{
		actual, actualErr := instance.Validate("changeme!", []byte("$y$j9T$joV328FhBQB66mB66/3vm.$cNgBaMBYgW0JyUMQsfi/OVoXIE2iy9MDUchynBlKiNA"))
		assert.NoError(t, actualErr)
		assert.Equal(t, true, actual)
	}

	{
		actual, actualErr := instance.Validate("changeme!2", []byte("$y$j9T$joV328FhBQB66mB66/3vm.$cNgBaMBYgW0JyUMQsfi/OVoXIE2iy9MDUchynBlKiNA"))
		assert.NoError(t, actualErr)
		assert.Equal(t, false, actual)
	}

	{
		actual, actualErr := instance.Validate("changeme!", []byte("$y$j9T$joV328FhBQB66mB66/3vm.$cNgBaMBYgW0JyUMQsfi/OVoXIE2iy9MDUchynblKiNA"))
		assert.NoError(t, actualErr)
		assert.Equal(t, false, actual)
	}

}
