# PPPwn - PlayStation 4 PPPoE RCE (Golang Version)

A Golang rewrite of [PPPwn](https://github.com/TheOfficialFloW/PPPwn)

# Reason

I started this project when only the PPPwn Python version exists.
So I wanted two things:
  - A more portable version
  - And learn a bit of Golang

This is my first program in Golang, so there are probably many things that aren't best practices.

PR are welcome

# Usage

```
usage: pppwn [-h|--help] [-f|--fw "<value>"] [-D|--debug "<value>"]
             [-s|--stage1 "<value>"] [-S|--stage2 "<value>"]

             PlayStation 4 PPPoE RCE

Arguments:

  -h  --help    Print help information
  -f  --fw      PS5 FW version to exploit (e.g. 1100). Default: 1050
  -D  --debug   Specify a path to a file to log packets to
  -s  --stage1  Path to stage1 payload (Use embedded if not specified)
  -S  --stage2  Path to stage2 payload (Use embedded if not specified)
```

There is no interface to specify, PPPwn will guess the right one by beginning to listen on all of them the first PADI packet and then handling everything else on the right one.

Example of commands
```
./PPPwn --fw 1100
```

```
./PPPwn --stage2 ./stages/payload.bin
```

# Build for Linux / MacOS
```bash
go-bindata embedded/
go build -o PPPwn *.go
```

# Build for Windows
```bash
go-bindata embedded/
go build -o PPPwn.exe *.go
```

# TODO
- [ ] Implements GoSocket modifications outside GoSocket.
- [ ] Enhance interface detection (Don't really like how it's implemented right now)
- [ ] Provide binaries
- [ ] Implements CI / CD build with Github Actions
