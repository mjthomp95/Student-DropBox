// Author: jliebowf
// Date: Spring 2016

// Package client provides support code for implementing a command-line client.
// Its two primary components are a command-line interaction wrapper that provides
// a usable interface around the logic of the client, and an auto-test framework
// that tests basic correctness properties about the client implementation.
package client

import (
	"errors"
	"fmt"
)

// Client represents an authenticated client. All methods should be carried out
// as whatever user the current client is authenticated as. This package is
// agnostic to how this authentication is implemented (it could even consist
// of the same login credentials being sent with every request).
type Client interface {
	// Upload uploads a file with the given contents to the given path,
	// creating it if it doesn't exist already, and overwriting the old
	// version if it does.
	Upload(path string, body []byte) (err error)

	// Download retrieves the contents of the file given by path.
	Download(path string) (body []byte, err error)

	// List returns a list of the entries in the given directory.
	List(path string) (entries []DirEnt, err error)

	// Creates a directory at the given path.
	Mkdir(path string) (err error)

	// Remove removes the file or directory identified by path, unless
	// that path identifies a directory which is not empty, in which
	// case an error is returned.
	Remove(dir bool, path string) (err error)

	// PWD returns the path to the current working directory.
	PWD() (path string, err error)

	// CD changes the current working directory.
	CD(path string) (err error)

	// Share shares the file at the given path with the given user.
	// If write is true, this will be a read/write share, and otherwise,
	// a read-only share. If a share for this file already existed
	// with the given user, it is overwritten with the new permissions.
	Share(path, username string, write bool) (err error)

	// RemoveShare removes the share on the given file from the given
	// user, unless username is the empty string, in which case all
	// shares for all users on this file are removed.
	RemoveShare(path, username string) (err error)

	// GetShares lists the shares that exist on the given file.
	GetShares(path string) (shares []Share, err error)
	
	// DelAccount deletes the current users account.
	DelAccount() (msg string, err error)
	
	//Invalidates their cookie to log them out
	Logout() (msg string, err error)
}

type Share interface {
	Sharee() string
	WritePerm() bool
}

// ShareString returns a string representation of s. If s's
// type implements the fmt.Stringer interface (that is, has
// a String() string method), then its String() method is
// called; otherwise, it is formatted using the two following
// formats depending on whether WritePerm returns true or not:
//  r/w sharee
//  r   sharee
func ShareString(s Share) string {
	if s, ok := s.(fmt.Stringer); ok {
		return s.String()
	}
	if s.WritePerm() {
		return fmt.Sprintf("r/w %v", s.Sharee())
	}
	return fmt.Sprintf("r   %v", s.Sharee())
}

// DirEnt represents a directory entry.
type DirEnt interface {
	// Name returns the base name of the entry (not the full path).
	Name() string
	IsDir() bool
}

// DirEntString returns a string representation of d. If d's
// type implements the fmt.Stringer interface (that is, has
// a String() string method), then its String() method is called;
// otherwise, it is formatted using one of the two following
// formats depending on whether IsDir returns true or not:
//  d foobar
//  - foobar
func DirEntString(d DirEnt) string {
	if s, ok := d.(fmt.Stringer); ok {
		return s.String()
	}
	if d.IsDir() {
		return fmt.Sprintf("d %s", d.Name())
	}
	return fmt.Sprintf("- %s", d.Name())
}

var (
	ErrNotImplemented = errors.New("not implemented")
)

// FatalError is the type of errors which can report whether
// they are fatal or not.
type FatalError interface {
	error
	IsFatal() bool
}

// MakeFatalError turns an existing error into a FatalError
// whose IsFatal method returns true.
func MakeFatalError(e error) FatalError {
	return makeFatalError(e, true)
}

// MakeNonFatalError turns an existing error into a FatalError
// whose IsFatal method returns false.
func MakeNonFatalError(e error) FatalError {
	return makeFatalError(e, false)
}

func makeFatalError(e error, fatal bool) FatalError {
	return fatalError{e, fatal}
}

type fatalError struct {
	error
	fatal bool
}

func (f fatalError) IsFatal() bool { return f.fatal }
