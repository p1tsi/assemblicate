# Assemblicate

Assemblicate is a CLI tool for iOS/macOS developers and reverse engineers.
It takes an .ips crash report, the binary of the application/process and 
the binaries of the framework extracted from the dyld_shared_cache and
prints readable assembly code for each function in the stack trace of the
faulting thread.

Everything with the help of Radare2.


## Usage

1. Generate under the root of the project an `apps` folder and put the app inside;
2. Generate under the root of the project an `otas` folder and put all system frameworks needed inside;
3. Generate under the root of the project an `assemblicated` folder where you will find the output file;

```% assemblicate <ips_filepath>```
