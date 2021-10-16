# Syscall Tables

This directory contains the Linux syscall tables for: ARM, ARM64, x86, x64, as described on [syscall.sh](https://syscall.sh).

The Python script can regenerate these tables as nessessary, using the `-a` flag to define architecture. Using the `-o` flag you can specify a custom output file

*Example*

```
python3 syscall.py -a x86
python3 syscall.py -a x64 -f x64_syscall.md
```

##### Requirments

- BeautifulSoup4
- optparse
- requests