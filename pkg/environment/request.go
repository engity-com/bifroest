package environment

type Request interface {
	Context
	PreparationProgressEnabled
}

type PreparationProgressAttributes map[string]any

type PreparationProgress interface {
	Report(progress float32) error
	Done() error
	Error(error) error
}

type PreparationProgressEnabled interface {
	StartPreparation(id, title string, attrs PreparationProgressAttributes) (PreparationProgress, error)
}
