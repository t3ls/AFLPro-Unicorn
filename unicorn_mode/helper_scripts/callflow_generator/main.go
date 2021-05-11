package main

import (
	"callflow_generator/generator"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"os"
	"strings"
)

var defaultPotentialFuncScore = 5000

var potentialFunc = [...]string{"memcpy", "strcpy"}
var highEnergyFunc = [...]string{"strcmp", "memcmp"}

func main() {
	app := cli.NewApp()
	app.Name = "call_flow_generator cli"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "log-level",
			Value: "info",
		},
	}
	app.Before = func(c *cli.Context) error {
		l, err := log.ParseLevel(c.String("log-level"))
		if err != nil {
			return err
		}
		log.SetLevel(l)
		return nil
	}
	app.Commands = []cli.Command{
		{
			Name: "run",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:     "file, f",
					Required: true,
				},
			},
			Action: func(ctx *cli.Context) error {
				g := generator.NewElfByPath(ctx.String("file"))
				if g == nil {
					return nil
				}
				g.Debug = false
				err := g.InitFuncTable()
				if err != nil {
					log.Info(err)
				}
				log.Debugf("%+v\n", g.ImportedFuncTable)
				results, err := g.Analyze()
				if err != nil {
					return err
				}
				export2Python(results)
				return err
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func export2Python(results []*generator.Result) {
	for _, result := range results {
		for _, funcName := range potentialFunc {
			if strings.Contains(result.FuncName, funcName) {
				fmt.Printf("potential_address[0x%x] = %d\n", result.Addr, defaultPotentialFuncScore)
				break
			}
		}
		for _, funcName := range highEnergyFunc {
			if strings.Contains(result.FuncName, funcName) {
				fmt.Printf("high_energy_address[0x%x] = '%s'\n", result.Addr, funcName)
				break
			}
		}
	}
}