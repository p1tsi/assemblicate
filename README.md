# Assemblicate

Assemblicate is a CLI tool for iOS/macOS developers and reverse engineers.
It takes an .ips crash report, the binary of the application/process and 
the binaries of the framework extracted from the dyld_shared_cache and
prints readable assembly code for each function in the stack trace of the
faulting thread.

Everything with the help of Radare2.


## Usage

1. Generate under the root of the project an `apps` folder and put the app inside;
2. Generate under the root of the project an `dylibs` folder and put all system frameworks needed inside;
3. Generate under the root of the project an `output` folder where you will find the output file;
``` project-root/ 
├── assemblicate/ 
      ├── apps/ 
      │ └── GlitchChat.app/
      │ |    └── Frameworks/
      │ |    |    └── libpng.framework/
      │ |    |           └── libpng
      │ |    └── GlitchChat
      │ └── tccd
      │ └── ...
      ├── dylibs/
      │    └── CoreFoundation
      │    └── CFNetwork
      │    └── libSystem.B.dylib
      │    └── ...
      ├── output/
           └── GlitchChat-2025-04-07-190351
```

Then compile with `cargo`and launch:

```% assemblicate <ips_filepath>```

## TODO
• Add support for `X86-64` register set

• ...
