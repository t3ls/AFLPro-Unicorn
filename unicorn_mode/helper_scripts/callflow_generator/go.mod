module callflow_generator

go 1.15

require (
	code.jpap.org/go-zydis v0.0.0-20210127041937-82defce55489
	github.com/sirupsen/logrus v1.8.1
	github.com/urfave/cli v1.22.5
)

replace code.jpap.org/go-zydis => ./go-zydis
