package main

/*
#include <stdio.h>
#include <stdlib.h>
struct call_graph_result {
  char* func_name;
  int arg_index;
  char* arg_type;
  // arg value : number / string
  unsigned long long i;
  char* s;
};
*/
import "C"
import (
	"bytes"
	"callflow_generator/generator"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"os"
	"reflect"
	"runtime"
	"unsafe"
)

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
				g.Debug = true
				err := g.InitFuncTable()
				if err != nil {
					log.Info(err)
				}
				log.Debugf("%+v\n", g.ImportedFuncTable)
				_, err = g.Analyze()
				if err != nil {
					return err
				}
				return err
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

var YrUndefined uintptr = 0xFFFABADAFABADAFF

//export GetCallGraph
func GetCallGraph(data *C.char, dataSize C.ulonglong) (uintptr, C.int) {
	// Elf 大于 4G 直接返回
	if uint64(dataSize) > 4*1024*1024*1024 {
		return YrUndefined, C.int(0)
	}
	var goData []byte
	goDataPtr := (*reflect.SliceHeader)(unsafe.Pointer(&goData))
	goDataPtr.Data = uintptr(unsafe.Pointer(data))
	goDataPtr.Len = int(dataSize)
	goDataPtr.Cap = int(dataSize)

	r := bytes.NewReader(goData)
	g := generator.NewElf(r)
	if g == nil {
		return YrUndefined, C.int(0)
	}
	err := g.InitFuncTable()
	if err != nil {
		log.Fatal(err)
	}
	log.Debugf("%+v\n", g.ImportedFuncTable)
	goResults, err := g.Analyze()
	if err != nil {
		return YrUndefined, C.int(0)
	}

	// 用 C.malloc 构造返回的数组（直接用 var 来定义会使用 tcmalloc 来分配内存导致在 C 代码中无法释放），[1<<30-1] 是为了让数组支持 index 操作
	// 返回数组的 malloc 大小为假定参数为满时的极限情况
	results := (*[1<<30 - 1]*C.struct_call_graph_result)(C.malloc(C.size_t(unsafe.Sizeof(uintptr(0))) * C.size_t(len(goResults)) * C.size_t(7)))
	// idx 为实际的参数数量
	idx := 0
	for _, r := range goResults {
		for argIndex, arg := range r.Args {
			if arg == nil || !arg.Used {
				continue
			}
			// C.size_t(5) * Sizeof(ptr) 是 struct_call_graph_result 的大小
			result := (*C.struct_call_graph_result)(C.malloc(C.size_t(unsafe.Sizeof(uintptr(0))) * C.size_t(5)))
			if arg.ArgType == "number" {
				i, err := generator.Str2Uint64(arg.Value)
				if err != nil {
					continue
				}
				result.func_name = C.CString(r.FuncName)
				result.arg_index = C.int(argIndex)
				result.i = C.ulonglong(i)
				result.arg_type = C.CString("number")
			} else {
				result.func_name = C.CString(r.FuncName)
				result.arg_index = C.int(argIndex)
				result.s = C.CString(arg.Value)
				result.arg_type = C.CString("string")
			}
			(*results)[idx] = result
			idx++
		}
	}
	runtime.GC()

	return uintptr(unsafe.Pointer(&results[0])), C.int(idx)
}
