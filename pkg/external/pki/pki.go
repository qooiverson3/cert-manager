package pki

type Engine struct {
	AppRole string
}

func NewEngine(appRole string) *Engine {
	return &Engine{AppRole: appRole}
}
