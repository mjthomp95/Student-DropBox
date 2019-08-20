// Author: jliebowf
// Date: Spring 2016

package main

import (
	"fmt"
	"os"
	"io/ioutil"
	"strings"
	"time"
	"golang.org/x/crypto/ssh/terminal"

	"../internal"
	"../lib/support/client"
	"../lib/support/rpc"
)
var username string

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %v <server>\n", os.Args[0])
		os.Exit(1)
	}

	// EXAMPLE CODE
	//
	// This code is meant as an example of how to use
	// our framework, not as stencil code. It is not
	// meant as a suggestion of how you should write
	// your application.

	server := rpc.NewServerRemote(os.Args[1])

	// Examples of calling various functions on the server
	// over RPC.
	var cookie string
	var input string
	var username string
	//This handles a verification for the client.
	//You can Signup on the server or you can Login.
	//A cookie is necessary for a successful login,
	//otherwise you won't be able to use the rest of the functions.
	for cookie == "" {
		fmt.Print("Type \"Login\" to login,  \"Signup\" to signup, or \"Exit\" to exit: ")
    		fmt.Scanln(&input)
		switch input {
		case "Login":
			pwd, er := os.Getwd()
			fmt.Println("Working Directory: ", pwd)
			//Login tries to use existing cookie
			if _, er = os.Stat(pwd + "/cookie.id"); er == nil {
				fmt.Println("Cookie Exists")
				content, err := ioutil.ReadFile(pwd + "/cookie.id")
				if err != nil {
					fmt.Println(err)
				} else {
					fmt.Println("Cookie Read")
					contentSplit := strings.Split(string(content), "\n")
					if len(contentSplit) != 2 {
						fmt.Println("Could Not Use Cookie")
					} else {
						fmt.Println("Expire Check")
						expire, er := time.Parse(time.RFC3339, contentSplit[1])
						if er != nil {
							fmt.Println("Error parsing time: ", er)
						} else {
							now := time.Now()
							if now.After(expire) {
								fmt.Println("Cookie Expired")
							} else {
								fmt.Println("Cookie Check")
								var ret internal.LoginReturn
								cookie = contentSplit[0]
								err := server.Call("login", &ret, "", "", cookie, -1)
								username = ret.Username
								if err != nil {
									fmt.Fprintf(os.Stderr, "Fatal: %v", err.Error())
								} else {
									if ret.Err != "" {
										fmt.Fprintf(os.Stderr, "Cookie Error: %v", ret.Err)
									} else {
										fmt.Println("Cookie Good")
										continue
									}
								}
							}
						}
					}
				}
			}
			//Cookie didn't work
			var ret internal.LoginReturn
			var password string
			var check string

   			fmt.Print("Enter Username: ")
			fmt.Scanln(&username)

			fmt.Print("Enter Password: ")
			//uses a package so password doesn't show up on terminal
    			bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
    			
    			password = string(bytePassword)			
			//Checks username and password before sending two-step verification email
			err = server.Call("loginCheck", &check, username, password)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Fatal: %v", err.Error())
				os.Exit(1)
			} 
			if check != "" {
				fmt.Println(check)
				continue
			}

			var validator int
			fmt.Print("Enter Validation Number: ")
			fmt.Scanln(&validator)
			//Second step of verification.
			err = server.Call("login", &ret, username, password, "", validator)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Fatal: %v", err.Error())
				os.Exit(1)
			}
			if ret.Err != "" {
				fmt.Fprintf(os.Stderr, "Error Logging in: %v\n", ret.Err)
				continue
			} else {
				fmt.Printf("Logged In as %v\nCookie: %v\n", username,  ret.Cookie)
				//Saves cookie to variable and to a File for later usage
				cookie = ret.Cookie
				err := ioutil.WriteFile(pwd + "/cookie.id", []byte(cookie + "\n" + ret.Expire), 0600)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error Writing cookie file: %v", err.Error())
				}
			}
		
		case "Signup":
			var retSignup string
			var username string
			var email string
			var password string
			var check string
			var validator int
			
   			fmt.Print("Enter Username (only alphanumeric characters): ")
			fmt.Scanln(&username)

			fmt.Print("Enter Email: ")
			fmt.Scanln(&email)
			//Checks to see if username and email are available
			//And sends verification email
			err1 := server.Call("check", &check, username, email)
			if err1 != nil {
				fmt.Fprintf(os.Stderr, "Check Fail: %v", err1.Error())	
			}

			if check != "" {
				fmt.Println(check)
				continue
			}

	
			fmt.Print("Enter Password: ")
    			bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))	
			fmt.Println("")
			if err == nil {
        			fmt.Print("Retype Password: ")
				checkPassword, error := terminal.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println("")
				if error != nil {
					fmt.Fprintf(os.Stderr, "Fatal: %v", error.Error())
					os.Exit(1)
				}
				if string(checkPassword) != string(bytePassword) {
					fmt.Println("Passwords do not match")
					continue
				}
    			} else {
				fmt.Fprintf(os.Stderr, "Fatal: %v", err)
				os.Exit(1)
			}
			
    			password = string(bytePassword)
			fmt.Print("Enter Validation Number: ")
			fmt.Scanln(&validator)
			//Completes Signup if correct validation number
			err = server.Call("signup", &retSignup, username, email, password, validator)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Fatal: %v", err)
				os.Exit(1)
			}
			
			fmt.Println(retSignup)
		case "Exit":
			return
		default:
			continue
		}	
	}
	
	

	// An example of how you might run a basic client.

	// In a real client, you'd have to first authenticate the user
	// (note that we don't provide any support code for this,
	// including the command-line interface). Once you the user
	// is authenticated, the client object (of the Client type
	// in this example, but it can be anything that implements
	// the client.Client interface) should somehow keep hold of
	// session information so that future requests (initiated
	// by methods being called on the object) can be authenticated.

	c := Client{cookie: cookie, server:server, currDir: "/" + username}
	err := client.RunCLI(&c)

	// c := Client{server, "/sampleUse"}
	// err = client.RunCLI(&c)

	if err != nil {
		fmt.Printf("fatal error: %v\n", err)
		os.Exit(1)
	}
}

// An implementation of a basic client to match the example server
// implementation. This client/server implementation is absurdly
// insecure, and is only meant as an example of how to implement
// the client.Client interface; it should not be taken as a suggestion
// of how to design your client or server.
type Client struct {
	cookie string
	server *rpc.ServerRemote
	currDir string
	// username string
}

func (c *Client) Upload(path string, body []byte) (err error) {
	var ret string
	err = c.server.Call("upload", &ret, path, c.currDir, body, c.cookie)
	if err != nil {
		return client.MakeFatalError(err)
	}
	if ret != "" {
		return fmt.Errorf(ret)
	}
	return nil
}

func (c *Client) Download(path string) (body []byte, err error) {
	var ret internal.DownloadReturn
	err = c.server.Call("download", &ret, path, c.currDir, c.cookie)
	if err != nil {
		return nil, client.MakeFatalError(err)
	}
	if ret.Err != "" {
		return nil, fmt.Errorf(ret.Err)
	}
	return ret.Body, nil
}

func (c *Client) List(path string) (entries []client.DirEnt, err error) {
	var ret internal.ListReturn
	err = c.server.Call("list", &ret, path, c.currDir, c.cookie)
	if err != nil {
		return nil, client.MakeFatalError(err)
	}
	if ret.Err != "" {
		return nil, fmt.Errorf(ret.Err)
	}
	var ents []client.DirEnt
	for _, e := range ret.Entries {
		ents = append(ents, e)
	}
	return ents, nil
}

func (c *Client) Mkdir(path string) (err error) {
	var ret string
	err = c.server.Call("mkdir", &ret, path, c.currDir, c.cookie)
	if err != nil {
		return client.MakeFatalError(err)
	}
	if ret != "" {
		return fmt.Errorf(ret)
	}
	return nil
}

func (c *Client) Remove(dir bool, path string) (err error) {
	var ret string
	err = c.server.Call("remove", &ret, path, c.currDir, dir, c.cookie)
	if err != nil {
		return client.MakeFatalError(err)
	}
	if ret != "" {
		return fmt.Errorf(ret)
	}
	return nil
}

func (c *Client) PWD() (path string, err error) {
	ret := internal.PWDReturn{Path: c.currDir}
	return ret.Path, nil
}

func (c *Client) CD(path string) (err error) {
	var ret internal.PWDReturn
	err = c.server.Call("cd", &ret, path, c.currDir, c.cookie)
	if ret.Err != "" {
		return fmt.Errorf(ret.Err)
	}
	if err != nil {
		return client.MakeFatalError(err)
	}
	c.currDir = ret.Path
	return nil
}

// CS166 students who are not implementing sharing
// should simply have these methods return
// client.ErrNotImplemented.

func (c *Client) Share(path, username string, write bool) (err error) {
	var ret string
	err = c.server.Call("share", &ret, path, c.currDir, username, write, c.cookie)
	if err != nil {
		return client.MakeFatalError(err)
	}
	if ret != "" {
		return fmt.Errorf(ret)
	}
	return nil
}

func (c *Client) RemoveShare(path, username string) (err error) {
	var ret string
	err = c.server.Call("rm_share", &ret, path, c.currDir, username, c.cookie)
	if err != nil {
		return client.MakeFatalError(err)
	}
	if ret != "" {
		return fmt.Errorf(ret)
	}
	return nil
}

func (c *Client) GetShares(path string) (shares []client.Share, err error) {
	var ret internal.ShareReturn
	err = c.server.Call("show_shares", &ret, path, c.currDir, c.cookie)
	if err != nil {
		return nil, client.MakeFatalError(err)
	}
	if ret.Err != "" {
		return nil, fmt.Errorf(ret.Err)
	}
	var ents []client.Share
	for _, e := range ret.Entries {
		ents = append(ents, e)
	}
	return ents, nil
}

func (c *Client) Logout() (msg string, err error) {
	var answer string
	fmt.Print("Are you sure you want to logout? (Y/N)")
	fmt.Scanln(&answer)
	if answer != "Y"{
		return "", nil
	}
	
	var ret string
	err = c.server.Call("logout", &ret, c.cookie)
	if err != nil {
		return "", client.MakeFatalError(err)
	}
	
	return ret, nil
}	

func (c *Client) DelAccount() (msg string, err error) {
	var answer string
	fmt.Print("Are you sure you want to delete your account? (Y/N)")
	fmt.Scanln(&answer)
	if answer != "Y"{
		return "", nil
	}
	var password string
	fmt.Println("You have to verify your password")
	fmt.Print("Enter Password: ")
    	bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
    	fmt.Println("")
	if err == nil {
        	fmt.Print("Retype Password: ")
		checkPassword, error := terminal.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println("")
		if error != nil {
			return "", error
		}
		if string(checkPassword) != string(bytePassword) {
			fmt.Println("Passwords do not match")
			return "", nil
		}
    	} else {
		return "", err
	}
	var ret string
	var check string
	
    	password = string(bytePassword)	
	//Checks to see if cookie is valid then sends verification email
	err = c.server.Call("delCheck", &check, c.cookie)
	if err != nil {
		return "", client.MakeFatalError(err)
	}
	if check != "" {
		return "", fmt.Errorf(check)
	}
	var validator int
	fmt.Print("Enter Validation Number: ")
	fmt.Scanln(&validator)
	//checks validation number then deletes account
	err = c.server.Call("delAccount", &ret, c.cookie, password, validator)
	if err != nil {
		return "", client.MakeFatalError(err)
	}
	return ret, nil	
}
