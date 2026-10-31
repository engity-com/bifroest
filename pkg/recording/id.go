package recording

import recordingid "github.com/engity-com/bifroest/pkg/recording/id"

type Id = recordingid.Id

func NewId() (Id, error)        { return recordingid.NewId() }
func validateId(value Id) error { return recordingid.Validate(value) }
