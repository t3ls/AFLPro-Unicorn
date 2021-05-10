package generator

/*
#include <stdlib.h>
*/
import "C"
import (
	"code.jpap.org/go-zydis"
	"debug/elf"
	"encoding/binary"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"strconv"
	"strings"
)

type Generator struct {
	ImportedFuncTable map[uint64]string
	elf               *elf.File
	decoder           *zydis.Decoder
	formatter         *zydis.Formatter
	results           []*Result
	Debug             bool
}

type FuncArgsRet struct {
	ArgType string
	Value   string
	Used    bool
}

type Result struct {
	Addr     uint64
	FuncName string
	Args     []*FuncArgsRet
}

type funcArg struct {
	value    string
	leaCount int
}

var funcArgsRegisters_X86_64 = []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}

var syscallArgsRegisters = []string{"rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"}

var registerSwitchBitSize = map[string]string{
	// 64bit -> 32bit
	"rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx", "rdi": "edi", "rsi": "esi", "rbp": "ebp", "r8": "r8d", "r9": "r9d",
	"r10": "r10d", "r11": "r11d", "r12": "r12d", "r13": "r13d", "r14": "r14d", "r15": "r15d",
	// 32bit -> 64bit
	"r15d": "r15", "r14d": "r14", "r9d": "r9", "r8d": "r8", "edi": "rdi", "edx": "rdx", "r12d": "r12", "r11d": "r11", "r10d": "r10",
	"ecx": "rcx", "r13d": "r13", "ebx": "rbx", "eax": "rax", "ebp": "rbp", "esi": "rsi",
}

func (g *Generator) initDynFuncTable() error {
	defer zydis.FormatterCallbackMap.Destroy()
	dynSym, err := g.elf.DynamicSymbols()
	if err != nil {
		return err
	}
	funcName := ""
	funcPltAddr := uint64(0)
	relPltTable := make(map[uint64]string)
	sec := g.elf.Section(".rela.plt")
	if sec == nil {
		return nil
	}
	data, err := sec.Data()
	if err != nil {
		return err
	}

	for len(data) > 0 {
		offset := binary.LittleEndian.Uint64(data[:8])
		index := binary.LittleEndian.Uint32(data[12:16])
		relPltTable[offset] = dynSym[index-1].Name
		data = data[24:]
	}

	sec = g.elf.Section(".plt")
	if sec == nil {
		return nil
	}
	runtimeAddress := sec.Addr
	data, err = sec.Data()
	if err != nil {
		return err
	}

	for len(data) > 0 {
		instr, err := g.decoder.Decode(data)
		if err != nil {
			return err
		}
		_, tokens, err := g.formatter.TokenizeInstruction(instr, runtimeAddress)
		instrLength := instr.Length
		instr.Destroy()
		instr = nil
		if err != nil {
			return err
		}
		if len(tokens) > 4 &&
			tokens[0].Value == "jmp" &&
			tokens[2].Value == "[" &&
			tokens[3].TokenType == zydis.TokenTypeAddressAbsolute {
			funcPltAddr = runtimeAddress
			offset, err := Str2Uint64(tokens[3].Value)
			if err != nil {
				return err
			}
			funcName = relPltTable[offset]
			if funcName != "" {
				g.ImportedFuncTable[funcPltAddr] = funcName
			}

			log.Debugf("0x%016x : 0x%x -> %s, %+v\n", runtimeAddress, funcPltAddr, funcName, tokens)
		}

		runtimeAddress += uint64(instrLength)
		data = data[instrLength:]
	}
	return nil
}

func (g *Generator) initSelfFuncTable() error {
	symbols, err := g.elf.Symbols()
	if err != nil {
		return err
	}
	for _, s := range symbols {
		if s.Info%16 == 2 && s.Value != 0 {
			// STT_FUNC == 2
			g.ImportedFuncTable[s.Value] = s.Name
		}
	}
	return nil
}

func (g *Generator) InitFuncTable() error {
	err := g.initDynFuncTable()
	if err != nil {
		return err
	}
	return g.initSelfFuncTable()
}

func NewElfByPath(path string) *Generator {
	file, err := elf.Open(path)
	if err != nil {
		log.Error(err)
		return nil
	}
	var decoder *zydis.Decoder
	if file.Machine == elf.EM_386 {
		decoder = zydis.NewDecoder(zydis.MachineModeCompat32, zydis.AddressWidth32)
	} else if file.Machine == elf.EM_X86_64 {
		decoder = zydis.NewDecoder(zydis.MachineMode64, zydis.AddressWidth64)
	}
	formatter, err := zydis.NewFormatter(zydis.FormatterStyleIntel)
	if err != nil {
		log.Error(err)
		return nil
	}
	return &Generator{
		ImportedFuncTable: make(map[uint64]string),
		elf:               file,
		decoder:           decoder,
		formatter:         formatter,
	}
}

func NewElf(r io.ReaderAt) *Generator {
	file, err := elf.NewFile(r)
	if err != nil {
		log.Error(err)
		return nil
	}
	decoder := zydis.NewDecoder(zydis.MachineMode64, zydis.AddressWidth64)
	formatter, err := zydis.NewFormatter(zydis.FormatterStyleIntel)
	if err != nil {
		log.Error(err)
		return nil
	}
	return &Generator{
		ImportedFuncTable: make(map[uint64]string),
		elf:               file,
		decoder:           decoder,
		formatter:         formatter,
	}
}

func setArgsMap(argsMap []*funcArg, from string, to string) []int {
	var indexSet []int
	if from == "" {
		return indexSet
	}
	for i, arg := range argsMap {
		if (arg.value == from || arg.value == registerSwitchBitSize[from]) && arg.value != "" {
			argsMap[i].value = to
			indexSet = append(indexSet, i)
		}
	}
	return indexSet
}

func setArgsResult(result []*FuncArgsRet, indexSet []int, argType string, value string) {
	for _, i := range indexSet {
		result[i] = &FuncArgsRet{
			ArgType: argType,
			Value:   value,
			Used:    true,
		}
	}
}

func Str2Uint64(s string) (uint64, error) {
	ret, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (g *Generator) convPointer2Str(ptr uint64) (string, error) {
	funcStr, exist := g.ImportedFuncTable[ptr]
	if exist {
		return funcStr, nil
	}
	for _, sec := range g.elf.Sections {
		if (strings.Contains(sec.Name, ".rodata") || strings.Contains(sec.Name, ".data")) && sec != nil {
			secStart := sec.Addr
			secEnd := sec.Addr + sec.Size
			if secStart <= ptr && ptr <= secEnd {
				s := ""
				secData := make([]byte, 1024)
				var seekPtr int64
				for {
					n, err := sec.ReadAt(secData, int64(ptr-secStart)+seekPtr)
					if err != nil && err != io.EOF {
						return "", err
					} else if n == 0 {
						break
					}
					for i := 0; i < n; i++ {
						seekPtr++
						if secData[i] == '\x00' {
							return s, nil
						}
						s += string(secData[i])
					}
				}
			}
		}
	}
	return "", nil
}

func (g *Generator) convArgsPtr2StrOrFuncName(argsRet []*FuncArgsRet) error {
	for i, arg := range argsRet {
		if arg != nil && arg.Used == true && arg.ArgType == "number" {
			realArg, err := Str2Uint64(arg.Value)
			if err != nil {
				return err
			}
			str, err := g.convPointer2Str(realArg)
			if err != nil {
				return err
			} else if str != "" {
				argsRet[i].ArgType = "string"
				argsRet[i].Value = str
			}
		}
	}
	return nil
}

func (g *Generator) analyzeTokenMov(tokens []zydis.FormatterToken, argsMap []*funcArg, argsRet []*FuncArgsRet) error {
	dstToken := tokens[2]
	srcToken := tokens[5]

	switch dstToken.TokenType {
	case zydis.TokenTypeRegister:
		switch srcToken.TokenType {
		case zydis.TokenTypeImmediate:
			// move from immediate to register. eg: mov eax,0
			indexSet := setArgsMap(argsMap, dstToken.Value, "")
			setArgsResult(argsRet, indexSet, "number", srcToken.Value)
		case zydis.TokenTypeRegister:
			// move from register to register, just replace argMap[dst] => argMap[src]. eg: mov eax, ebx
			if srcToken.Value != "fs" {
				// skip `fs` register
				setArgsMap(argsMap, dstToken.Value, srcToken.Value)
			}
		case zydis.TokenTypeParenthesisOpen, zydis.TokenTypeTypecast:
			// move from a local var or an absolute address to register. eg: mov rax, [rbp-0x10] / mov rax, [0x601000]
			if len(tokens) < 7 {
				return nil
			}
			if tokens[6].TokenType == zydis.TokenTypeAddressAbsolute {
				indexSet := setArgsMap(argsMap, dstToken.Value, "")
				setArgsResult(argsRet, indexSet, "number", tokens[6].Value)
			} else {
				srcMemAddr := ""
				startIdx := 5
				if srcToken.TokenType == zydis.TokenTypeTypecast {
					startIdx += 2
				}
				for _, token := range tokens[startIdx:] {
					srcMemAddr += token.Value
				}
				setArgsMap(argsMap, dstToken.Value, srcMemAddr)
			}
		default:
			log.Debugf("can not parse %+v\n", tokens)
		}
	case zydis.TokenTypeParenthesisOpen:
		// move from register to abs address or a rel address. eg: mov [rbp-0x10], rax / mov [0x601000], rax
		dstMemAddr := ""
		startIdx := 2 // dst token start from index 2 to comma, like `[rbp-0x10]` or `[0x601000]`
		for i, token := range tokens[startIdx:] {
			if token.Value == "," {
				if tokens[i+startIdx+2].TokenType == zydis.TokenTypeRegister {
					srcToken = tokens[i+startIdx+2]
				}
				break
			} else {
				dstMemAddr += token.Value
			}
		}
		// check src token is register or not
		if srcToken.TokenType == zydis.TokenTypeRegister {
			setArgsMap(argsMap, dstMemAddr, srcToken.Value)
		} else {
			log.Debugf("can not parse %+v\n", tokens)
			return nil
		}
	case zydis.TokenTypeTypecast:
		// move command with typecast addr, like `qword ptr`.
		dstToken = tokens[4]
		if dstToken.TokenType == zydis.TokenTypeParenthesisOpen {
			// move to a address typecasted. eg: mov dword ptr [rax], *
			startIdx := 4
			dstMemAddr := ""
			for i, token := range tokens[startIdx:] {
				if token.Value == "," {
					srcToken = tokens[i+startIdx+2]
					break
				} else {
					dstMemAddr += token.Value
				}
			}
			if srcToken.TokenType == zydis.TokenTypeImmediate {
				// move from an immediate. eg: mov dword ptr [rax], 0
				indexSet := setArgsMap(argsMap, dstMemAddr, "")
				setArgsResult(argsRet, indexSet, "number", srcToken.Value)
			} else if srcToken.TokenType != zydis.TokenTypeRegister {
				log.Debugf("Unexpect command: %+v\n", tokens)
				return nil
			}
		} else {
			log.Debugf("Unexpect command: %+v\n", tokens)
			return nil
		}
	default:
		log.Debugf("can not parse %+v\n", tokens)
	}
	return nil
}

func (g *Generator) analyzeBlockTokens(tokensPtr *[]zydis.FormatterToken, argsRet []*FuncArgsRet, argsMap []*funcArg, isFirstInstruction bool) error {
	tokens := *tokensPtr
	if tokens[0].Value == "mov" || tokens[0].Value == "movsxd" {
		err := g.analyzeTokenMov(tokens, argsMap, argsRet)
		if err != nil {
			return err
		}
	} else if tokens[0].Value == "xor" {
		dstToken := tokens[2]
		indexSet := setArgsMap(argsMap, dstToken.Value, "")
		setArgsResult(argsRet, indexSet, "number", "0")
	} else if tokens[0].Value == "lea" {
		dstToken := tokens[2]
		if dstToken.TokenType == zydis.TokenTypeRegister &&
			len(tokens) >= 7 &&
			tokens[5].Value == "[" &&
			tokens[6].TokenType == zydis.TokenTypeAddressAbsolute {
			indexSet := setArgsMap(argsMap, dstToken.Value, "")
			setArgsResult(argsRet, indexSet, "number", tokens[6].Value)
		} else {
			setArgsMap(argsMap, dstToken.Value, "")
		}
	} else if tokens[0].Value == "rep" {
		// rep 指令执行完成后 rcx 清零
		indexSet := setArgsMap(argsMap, "rcx", "")
		setArgsResult(argsRet, indexSet, "number", "0")
	} else if (tokens[0].Value == "call" || tokens[0].Value == "syscall") && !isFirstInstruction {
		// call 指令执行完成后 rax 修改为未知值
		setArgsMap(argsMap, "rax", "")
	} else if tokens[0].Value == "or" {
		// or 指令清空相关参数
		dstToken := tokens[2]
		setArgsMap(argsMap, dstToken.Value, "")
	}
	return nil
}

func (g *Generator) analyzeFuncArgs(blockTokens *[][]zydis.FormatterToken, isSyscall bool) ([]*FuncArgsRet, error) {
	argsSize := 0
	var tempArgsMap []*funcArg
	if isSyscall {
		argsSize = 7
		for i := 0; i < argsSize; i++ {
			tempArgsMap = append(tempArgsMap, &funcArg{
				value:    syscallArgsRegisters[i],
				leaCount: 0,
			})
		}
	} else {
		argsSize = 6
		for i := 0; i < argsSize; i++ {
			tempArgsMap = append(tempArgsMap, &funcArg{
				value:    funcArgsRegisters_X86_64[i],
				leaCount: 0,
			})
		}
	}
	argsRet := make([]*FuncArgsRet, argsSize, argsSize)
	for i := range *blockTokens {
		// isFirstInstruction 用于跳过当前代码块中的最后一条 call 或 syscall 指令，否则会清空 rax 参数
		isFirstInstruction := false
		tokens := (*blockTokens)[len(*blockTokens)-i-1]
		if i == 0 {
			isFirstInstruction = true
		}
		log.Debugf("tokens: %+v\nargsMap: %+v\n", tokens, tempArgsMap)
		err := g.analyzeBlockTokens(&tokens, argsRet, tempArgsMap, isFirstInstruction)
		if err != nil {
			return nil, err
		}
	}
	err := g.convArgsPtr2StrOrFuncName(argsRet)
	if err != nil {
		return nil, err
	}
	return argsRet, nil
}

func (g *Generator) Analyze() ([]*Result, error) {
	defer zydis.FormatterCallbackMap.Destroy()
	sec := g.elf.Section(".text")
	if sec == nil {
		return nil, nil
	}
	//data, err := sec.Data()
	data := make([]byte, 1024)
	var seekPtr int64
	var decodeIdx uint64
	runtimeAddress := sec.Addr
	n, err := sec.ReadAt(data, seekPtr)
	if err != nil && err != io.EOF {
		return nil, err
	}

	var tokens []zydis.FormatterToken
	var blockTokens [][]zydis.FormatterToken

	for {
		if uint64(n)-decodeIdx < 0x10 {
			n, err = sec.ReadAt(data, seekPtr)
			decodeIdx = 0
			if err != nil && err != io.EOF {
				return nil, err
			} else if n == 0 && err == io.EOF {
				break
			}
		}
		instr, err := g.decoder.Decode(data[decodeIdx:])
		if err != nil {
			log.Infof("decode err: len:%d, idx:%d, %v\n", n, decodeIdx, err)
			return nil, err
		}
		instrLength := instr.Length
		_, tokens, err = g.formatter.TokenizeInstruction(instr, runtimeAddress)
		instr.Destroy()
		instr = nil
		if err != nil {
			return nil, err
		}
		blockTokens = append(blockTokens, tokens)

		if tokens[0].Value == "call" {
			funcName := ""
			if tokens[2].TokenType == zydis.TokenTypeAddressAbsolute ||
				tokens[2].TokenType == zydis.TokenTypeAddressRelative {
				addr, err := Str2Uint64(tokens[2].Value)
				if err != nil {
					return nil, err
				}
				funcName = g.ImportedFuncTable[addr]
				if funcName == "" {
					// IDA style defining funcName
					funcName = "sub_" + strings.TrimLeft(strings.TrimPrefix(tokens[2].Value, "0x"), "0")
				}
			} else if len(tokens) >= 4 && tokens[3].TokenType == zydis.TokenTypeAddressAbsolute {
				addr, err := Str2Uint64(tokens[3].Value)
				if err != nil {
					return nil, err
				}
				funcName = g.ImportedFuncTable[addr]
				if funcName == "" {
					// IDA style defining funcName
					funcName = "qword_" + strings.TrimLeft(strings.TrimPrefix(tokens[3].Value, "0x"), "0")
				}
			} else {
				goto skip
			}
			var args []*FuncArgsRet
			if g.elf.Machine == elf.EM_X86_64 {
				args, err = g.analyzeFuncArgs(&blockTokens, false)
				if err != nil {
					return nil, err
				}
			}
			g.results = append(g.results, &Result{
				Addr:     runtimeAddress,
				FuncName: funcName,
				Args:     args,
			})
		} else if tokens[0].Value == "syscall" {
			// 直接系统调用
			args, err := g.analyzeFuncArgs(&blockTokens, true)
			if err != nil {
				return nil, err
			}
			g.results = append(g.results, &Result{
				Addr:     runtimeAddress,
				FuncName: "_syscall",
				Args:     args,
			})
		}

		if tokens[0].Value == "ret" || tokens[0].Value == "jmp" {
			// 清空代码块
			blockTokens = blockTokens[0:0]
		}
	skip:
		runtimeAddress += uint64(instrLength)
		decodeIdx += uint64(instrLength)
		//data = data[instrLength:]
		seekPtr += int64(instrLength)
	}
	if g.Debug {
		for _, result := range g.results {
			displayResult(result)
		}
	}
	return g.results, nil
}

func displayResult(result *Result) {
	fmt.Printf("0x%016x %s(", result.Addr, result.FuncName)
	for i, arg := range result.Args {
		if arg != nil && arg.Used {
			if arg.ArgType == "number" {
				numVal, err := Str2Uint64(arg.Value)
				if err != nil {
					fmt.Printf(arg.Value)
				}
				fmt.Printf("0x%x", numVal)
			} else if arg.ArgType == "string" {
				fmt.Printf("%s", strconv.Quote(arg.Value))
			}
		} else {
			fmt.Printf("nil")
		}
		if (i != 5 && result.FuncName != "_syscall") || (i != 6 && result.FuncName == "_syscall") {
			fmt.Printf(", ")
		} else {
			break
		}
	}
	fmt.Printf(");\n")
}
