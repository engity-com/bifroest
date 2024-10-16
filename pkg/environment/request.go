package environment

type Request interface {
	Context

	StartPreparation(id, title string, attrs PreparationProgressAttributes) (PreparationProgress, error)
}

type PreparationProgressAttributes map[string]any

type PreparationProgress interface {
	Report(progress float32) error
	Done() error
	Error(error) error
}
