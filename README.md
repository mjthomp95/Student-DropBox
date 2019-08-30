# Student Dropbox

A small project with a Dropbox-like Service. It uses accounts with usernames and passwords. Email verification is used to create and delete accounts. We have sessions setup with identification cookies. The uploaded files are deduplicated to use less storage when the same file is uploaded. All account passwords are hashed and salted to prevent password leaks. Uploaded files are able to be shared with other accounts. When sharing a file, you can specify the level of privilege you give the sharee. Some security measures in place help prevent SQL injection attacks and direct object reference. Uses SQLite for storage of account information.

Run `make`, `make client`, or `make server` to build, and `make clean` to remove the builds.

Usage:
Server Password: #setup email and encrypt email password this would be the decryption key
The server password is used to decrypt the password to send emails.

server --reset should be run from top-level of any previous base directory.
Client cookies will be saved/loaded from the directory that it is run from. Filename is "cookies.id"
A baseDir for the Server should already have the folders "AllFiles", "db", and "email". Inside "db" should be a sqlite file or blank file "dropbox.db" and inside email should be the files from our email folder, "salt" and "passwordEncrypt". You can use setup.sh to make all the folders and "dropbox.db", but "salt" and "passwordEncrypt" need to be moved into the email folder.

(Absolute paths handling): Please note that any path beginning with "/" will be treated as an absolute path, and any absolute path must start with a username, that is the rootuser or owner of that path. Therefore if you try to find an absolute path looking like this "/path/to/file", you will likely not be able to access that file, because path is not a name of a user name. To access "path/to/file" with an absolute link, you will need use "/username/path/to/file". We chose to do it this way because of the way sharing works.
Only the owner of a file can delete their files. Sharees cant

All testing/verification that you have done to verify that your service is secure
We did a lot of manual testing with edge cases to check that the functionalities work
SQL injection attacks were tested with various cases. Examples: ; [Query], " [Query], ' [Query]. Some [Query] being [OR 1=1], [DROP TABLE].

