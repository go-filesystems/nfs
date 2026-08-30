// Command fat32demo serves a FAT32 image over NFSv3.
//
//	fat32demo -image disk.img -addr 127.0.0.1:12049
//
//	sudo mount -t nfs -o vers=3,tcp,port=12049,mountport=12049,noresvport \
//	    127.0.0.1:/ /Volumes/img       # macOS
//	sudo mount -t nfs -o vers=3,tcp,port=12049,mountport=12049,nolock \
//	    127.0.0.1:/ /mnt/img           # Linux
//
// Everything it does lives in the demo package, which is where the tests
// reach it; this file is the shell.
package main

import (
	"os"

	"github.com/go-filesystems/nfs/fat32demo/demo"
)

func main() { os.Exit(demo.Main(os.Args[1:], os.Stdout, os.Stderr)) }
