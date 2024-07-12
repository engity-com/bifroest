package environment

type Environment interface {
	WillBeAccepted(Request) (bool, error)
	Run(Task) error
}
