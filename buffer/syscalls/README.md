# Syscall Tables

This directory contains the Linux syscall tables for: ARM, ARM64, x86, x64, as described on [syscall.sh](https://syscall.sh).

The Python script can regenerate these tables as nessessary, using the `-a` flag to define architecture. Using the `-o` flag you can specify a custom output file.

The markdown is great for note apps like obsidian that have MD table formatters. The txt is better for terminal stuff. 

*Example*

```
python3 syscall.py -a x86
python3 syscall.py -a x64 -f x64_syscall.md
```

Oh and it's nicely grepable

```
> file=syscalls_x64.md; head -n 1 $file ; grep chmod $file
```

##### Requirments

- BeautifulSoup4
- optparse
- requests
