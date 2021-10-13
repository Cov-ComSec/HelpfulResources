- [GTFOBins](https://gtfobins.github.io/) - Exploit linux binaries for privesc
- [Lolbas](https://lolbas-project.github.io/#) - Exploit windows binaries for privesc

## Finding SUID Files
To search for SUID files on Linux, use the following command:

```sh
find / -perm /4000 2>/dev/null
```

Then use GTFObins to find any associated vulnerabilities.
