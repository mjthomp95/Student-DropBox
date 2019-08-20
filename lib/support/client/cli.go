// Author: jliebowf
// Date: Spring 2016

package client

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// RunCLI accepts an already-authenticated Client, and runs a command-line
// interface for the user, allowing the user to interact with the Client.
//
// If any error returned implements the FatalError interface, and IsFatal
// returns true for that error, RunCLI will return that error immediately.
// Otherwise, the error will be logged, but the client will continue running.
func RunCLI(c Client) error {
	s := bufio.NewScanner(os.Stdin)

	for {
		pwd, err := c.PWD()
		if err != nil {
			if isFatal(err) {
				return err
			}
			fmt.Printf("error retrieving pwd: %v\n", err)
		}
		fmt.Printf("%s> ", pwd)
		if !s.Scan() {
			break
		}
		parts := strings.Fields(s.Text())
		if len(parts) == 0 {
			continue
		}
		args := parts[1:]
	OUTER:
		switch parts[0] {
		case "upload":
			if len(args) != 2 {
				fmt.Printf("Usage: %v <localpath> <remotepath>\n", parts[0])
				break
			}
			body, err := ioutil.ReadFile(args[0])
			if err != nil {
				fmt.Printf("error reading file: %v\n", err)
				break
			}

			err = c.Upload(args[1], body)
			if err != nil {
				if isFatal(err) {
					return err
				}
				fmt.Printf("error uploading: %v\n", err)
			}
		case "download":
			if len(args) != 2 {
				fmt.Printf("Usage: %v <remotepath> <localpath>\n", parts[0])
				break
			}
			body, err := c.Download(args[0])
			if err != nil {
				if isFatal(err) {
					return err
				}
				fmt.Printf("error downloading: %v\n", err)
				break
			}

			err = ioutil.WriteFile(args[1], body, 0664)
			if err != nil {
				fmt.Printf("error writing file: %v\n", err)
				break
			}
		case "cat":
			if len(args) != 1 {
				fmt.Printf("Usage: %v <remotepath>\n", parts[0])
				break
			}
			body, err := c.Download(args[0])
			if err != nil {
				if isFatal(err) {
					return err
				}
				fmt.Printf("error downloading: %v\n", err)
				break
			}

			os.Stdout.Write(body)
		case "ls":
			if len(args) != 0 && len(args) != 1 {
				fmt.Printf("Usage: %v [<path>]\n", parts[0])
				break
			}
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			ents, err := c.List(path)
			if err != nil {
				if isFatal(err) {
					return err
				}
				fmt.Printf("error listing: %v\n", err)
				break
			}
			for _, e := range ents {
				fmt.Println(DirEntString(e))
			}
		case "mkdir":
			if len(args) != 1 {
				fmt.Printf("Usage: %v <path>\n", parts[0])
				break
			}
			err := c.Mkdir(args[0])
			if err != nil {
				if isFatal(err) {
					return err
				}
				fmt.Printf("error making directory: %v\n", err)
			}
		case "rm":
			var dir bool
			var path string
			if len(args) != 1 && len(args) != 2 {
				fmt.Printf("Usage: %v [<path>] | %v <path>\n", parts[0], parts[0])
				break
			}
			// if len(args) != 1 {
			// 	fmt.Printf("Usage: %v <path>\n", parts[0])
			// 	break
			// }
			dir = false
			path = args[0]

			if len(args) == 2{
				if args[0] != "-r"{
					fmt.Printf("Usage: %v [<path>]\n | %v -r <path> ", parts[0], parts[0])
					break
				}
				 dir = true
				 fmt.Printf(string(len(args)))
				 path = args[1]
			}

			err := c.Remove(dir, path)
			if err != nil {
				if isFatal(err) {
					return err
				}
				fmt.Printf("error removing: %v\n", err)
			}
		case "pwd":
			if len(args) != 0 {
				fmt.Printf("Usage: %v\n", parts[0])
				break
			}
			pwd, err := c.PWD()
			if err != nil {
				if isFatal(err) {
					return err
				}
				fmt.Printf("error getting pwd: %v\n", err)
				break
			}
			fmt.Println(pwd)
		case "cd":
			if len(args) != 0 && len(args) != 1 {
				fmt.Printf("Usage: %v [<path>]\n", parts[0])
				break
			}
			path := "/"
			if len(args) == 1 {
				path = args[0]
			}

			err := c.CD(path)
			if err != nil {
				if isFatal(err) {
					return err
				}
				fmt.Printf("error cd'ing: %v\n", err)
			}
		case "share":
			var write bool
			var path, username string
			switch {
			case len(args) == 2:
				path = args[0]
				username = args[1]
			case len(args) == 3 && args[0] == "--write":
				write = true
				path = args[1]
				username = args[2]
			default:
				fmt.Printf("Usage: %v [--write] <path> <username>\n", parts[0])
				break OUTER
			}
			err := c.Share(path, username, write)
			if err != nil {
				if isFatal(err) {
					return err
				}
				fmt.Printf("error sharing: %v\n", err)
			}
		case "rm_share":
			if len(args) != 1 && len(args) != 2 {
				fmt.Printf("Usage: %v <path> [<username>]\n", parts[0])
				break
			}
			username := ""
			if len(args) == 2 {
				username = args[1]
			}
			err := c.RemoveShare(args[0], username)
			if err != nil {
				if isFatal(err) {
					return err
				}
				fmt.Printf("error removing share: %v\n", err)
			}
		case "show_shares":
			if len(args) != 1 {
				fmt.Printf("Usage: %v <path>\n", parts[0])
				break
			}
			shares, err := c.GetShares(args[0])
			if err != nil {
				if isFatal(err) {
					fmt.Printf("cibgggg: %v\n", err)
					return err
				}
				fmt.Printf("error listing shares: %v\n", err)
				break
			}
			for _, s := range shares {
				fmt.Println(ShareString(s))
			}
		case "logout":
			if len(args) != 0{
				fmt.Printf("Usage: %v\n", parts[0])
				break
			}
			msg, err := c.Logout()
			if err != nil{
				if isFatal(err) {
					return err
				}
				fmt.Printf("error logout: %v\n", err)
			}
			fmt.Printf(msg)
		case "quit", "exit":
			if len(args) != 0 {
				fmt.Printf("Usage: %v\n", parts[0])
				break
			}
			return nil
		case "help":
			if len(args) != 0 {
				fmt.Printf("Usage: %v\n", parts[0])
				break
			}
			fmt.Println("Available commands:")
			cmds := []string{
				"upload <localpath> <remotepath>",
				"download <remotepath> <localpath>",
				"cat <remotepath>",
				"ls [<path>]",
				"mkdir <path>",
				"rm <path>",
				"pwd",
				"cd [<path>]",
				"share [--write] <path> <username>",
				"rm_share <path> [<username>]",
				"show_shares <path>",
				"logout",
				"quit",
				"exit",
				"del_account",
				"help",
			}
			for _, c := range cmds {
				fmt.Println("\t" + c)
			}
		case "del_account":
			if len(args) != 0 {
				fmt.Printf("Usage: %v\n", parts[0])
				break
			}
			msg, err := c.DelAccount()
			if err != nil {
				if isFatal(err) {
					return err
				}
				fmt.Printf("error deleting account: %v\n", err)
				break
			}
			fmt.Println(msg)
		default:
			fmt.Println("Unknown command; try \"help\"")
		}
	}

	// Add a newline after the default prompt
	fmt.Println()
	if err := s.Err(); err != nil {
		fmt.Printf("error scanning stdin: %v\n", err)
		return err
	}
	return nil
}

func isFatal(err error) bool {
	if f, ok := err.(FatalError); ok {
		return f.IsFatal()
	}
	return false
}
