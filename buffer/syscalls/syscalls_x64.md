| NR | SYSCALL | NAME | references | RAX | ARG0 | (rdi) | ARG1 | (rsi) | ARG2 | (rdx) | ARG3 | (r10) | ARG4 | (r8) | ARG5 | (r9) | 
| 0 | read | man/ | cs/ | 0 | unsigned | int | fd | char | *buf | size_t | count | - | - | - | 
| 1 | write | man/ | cs/ | 1 | unsigned | int | fd | const | char | *buf | size_t | count | - | - | - | 
| 2 | open | man/ | cs/ | 2 | const | char | *filename | int | flags | umode_t | mode | - | - | - | 
| 3 | close | man/ | cs/ | 3 | unsigned | int | fd | - | - | - | - | - | 
| 4 | stat | man/ | cs/ | 4 | const | char | *filename | struct | __old_kernel_stat | *statbuf | - | - | - | - | 
| 5 | fstat | man/ | cs/ | 5 | unsigned | int | fd | struct | __old_kernel_stat | *statbuf | - | - | - | - | 
| 6 | lstat | man/ | cs/ | 6 | const | char | *filename | struct | __old_kernel_stat | *statbuf | - | - | - | - | 
| 7 | poll | man/ | cs/ | 7 | struct | pollfd | *ufds | unsigned | int | nfds | int | timeout | - | - | - | 
| 8 | lseek | man/ | cs/ | 8 | unsigned | int | fd | off_t | offset | unsigned | int | whence | - | - | - | 
| 9 | mmap | man/ | cs/ | 9 | ? | ? | ? | ? | ? | ? | 
| 10 | mprotect | man/ | cs/ | A | unsigned | long | start | size_t | len | unsigned | long | prot | - | - | - | 
| 11 | munmap | man/ | cs/ | B | unsigned | long | addr | size_t | len | - | - | - | - | 
| 12 | brk | man/ | cs/ | C | unsigned | long | brk | - | - | - | - | - | 
| 13 | rt_sigaction | man/ | cs/ | D | int | const | struct | sigaction | * | struct | sigaction | * | size_t | - | - | 
| 14 | rt_sigprocmask | man/ | cs/ | E | int | how | sigset_t | *set | sigset_t | *oset | size_t | sigsetsize | - | - | 
| 15 | rt_sigreturn | man/ | cs/ | F | ? | ? | ? | ? | ? | ? | 
| 16 | ioctl | man/ | cs/ | 10 | unsigned | int | fd | unsigned | int | cmd | unsigned | long | arg | - | - | - | 
| 17 | pread64 | man/ | cs/ | 11 | unsigned | int | fd | char | *buf | size_t | count | loff_t | pos | - | - | 
| 18 | pwrite64 | man/ | cs/ | 12 | unsigned | int | fd | const | char | *buf | size_t | count | loff_t | pos | - | - | 
| 19 | readv | man/ | cs/ | 13 | unsigned | long | fd | const | struct | iovec | *vec | unsigned | long | vlen | - | - | - | 
| 20 | writev | man/ | cs/ | 14 | unsigned | long | fd | const | struct | iovec | *vec | unsigned | long | vlen | - | - | - | 
| 21 | access | man/ | cs/ | 15 | const | char | *filename | int | mode | - | - | - | - | 
| 22 | pipe | man/ | cs/ | 16 | int | *fildes | - | - | - | - | - | 
| 23 | select | man/ | cs/ | 17 | int | n | fd_set | *inp | fd_set | *outp | fd_set | *exp | struct | timeval | *tvp | - | 
| 24 | sched_yield | man/ | cs/ | 18 | - | - | - | - | - | - | 
| 25 | mremap | man/ | cs/ | 19 | unsigned | long | addr | unsigned | long | old_len | unsigned | long | new_len | unsigned | long | flags | unsigned | long | new_addr | - | 
| 26 | msync | man/ | cs/ | 1A | unsigned | long | start | size_t | len | int | flags | - | - | - | 
| 27 | mincore | man/ | cs/ | 1B | unsigned | long | start | size_t | len | unsigned | char | * | vec | - | - | - | 
| 28 | madvise | man/ | cs/ | 1C | unsigned | long | start | size_t | len | int | behavior | - | - | - | 
| 29 | shmget | man/ | cs/ | 1D | key_t | key | size_t | size | int | flag | - | - | - | 
| 30 | shmat | man/ | cs/ | 1E | int | shmid | char | *shmaddr | int | shmflg | - | - | - | 
| 31 | shmctl | man/ | cs/ | 1F | int | shmid | int | cmd | struct | shmid_ds | *buf | - | - | - | 
| 32 | dup | man/ | cs/ | 20 | unsigned | int | fildes | - | - | - | - | - | 
| 33 | dup2 | man/ | cs/ | 21 | unsigned | int | oldfd | unsigned | int | newfd | - | - | - | - | 
| 34 | pause | man/ | cs/ | 22 | - | - | - | - | - | - | 
| 35 | nanosleep | man/ | cs/ | 23 | struct | __kernel_timespec | *rqtp | struct | __kernel_timespec | *rmtp | - | - | - | - | 
| 36 | getitimer | man/ | cs/ | 24 | int | which | struct | itimerval | *value | - | - | - | - | 
| 37 | alarm | man/ | cs/ | 25 | unsigned | int | seconds | - | - | - | - | - | 
| 38 | setitimer | man/ | cs/ | 26 | int | which | struct | itimerval | *value | struct | itimerval | *ovalue | - | - | - | 
| 39 | getpid | man/ | cs/ | 27 | - | - | - | - | - | - | 
| 40 | sendfile | man/ | cs/ | 28 | int | out_fd | int | in_fd | off_t | *offset | size_t | count | - | - | 
| 41 | socket | man/ | cs/ | 29 | int | int | int | - | - | - | 
| 42 | connect | man/ | cs/ | 2A | int | struct | sockaddr | * | int | - | - | - | 
| 43 | accept | man/ | cs/ | 2B | int | struct | sockaddr | * | int | * | - | - | - | 
| 44 | sendto | man/ | cs/ | 2C | int | void | * | size_t | unsigned | struct | sockaddr | * | int | 
| 45 | recvfrom | man/ | cs/ | 2D | int | void | * | size_t | unsigned | struct | sockaddr | * | int | * | 
| 46 | sendmsg | man/ | cs/ | 2E | int | fd | struct | user_msghdr | *msg | unsigned | flags | - | - | - | 
| 47 | recvmsg | man/ | cs/ | 2F | int | fd | struct | user_msghdr | *msg | unsigned | flags | - | - | - | 
| 48 | shutdown | man/ | cs/ | 30 | int | int | - | - | - | - | 
| 49 | bind | man/ | cs/ | 31 | int | struct | sockaddr | * | int | - | - | - | 
| 50 | listen | man/ | cs/ | 32 | int | int | - | - | - | - | 
| 51 | getsockname | man/ | cs/ | 33 | int | struct | sockaddr | * | int | * | - | - | - | 
| 52 | getpeername | man/ | cs/ | 34 | int | struct | sockaddr | * | int | * | - | - | - | 
| 53 | socketpair | man/ | cs/ | 35 | int | int | int | int | * | - | - | 
| 54 | setsockopt | man/ | cs/ | 36 | int | fd | int | level | int | optname | char | *optval | int | optlen | - | 
| 55 | getsockopt | man/ | cs/ | 37 | int | fd | int | level | int | optname | char | *optval | int | *optlen | - | 
| 56 | clone | man/ | cs/ | 38 | unsigned | long | unsigned | long | int | * | int | * | unsigned | long | - | 
| 57 | fork | man/ | cs/ | 39 | - | - | - | - | - | - | 
| 58 | vfork | man/ | cs/ | 3A | - | - | - | - | - | - | 
| 59 | execve | man/ | cs/ | 3B | const | char | *filename | const | char | *const | *argv | const | char | *const | *envp | - | - | - | 
| 60 | exit | man/ | cs/ | 3C | int | error_code | - | - | - | - | - | 
| 61 | wait4 | man/ | cs/ | 3D | pid_t | pid | int | *stat_addr | int | options | struct | rusage | *ru | - | - | 
| 62 | kill | man/ | cs/ | 3E | pid_t | pid | int | sig | - | - | - | - | 
| 63 | uname | man/ | cs/ | 3F | struct | old_utsname | * | - | - | - | - | - | 
| 64 | semget | man/ | cs/ | 40 | key_t | key | int | nsems | int | semflg | - | - | - | 
| 65 | semop | man/ | cs/ | 41 | int | semid | struct | sembuf | *sops | unsigned | nsops | - | - | - | 
| 66 | semctl | man/ | cs/ | 42 | int | semid | int | semnum | int | cmd | unsigned | long | arg | - | - | 
| 67 | shmdt | man/ | cs/ | 43 | char | *shmaddr | - | - | - | - | - | 
| 68 | msgget | man/ | cs/ | 44 | key_t | key | int | msgflg | - | - | - | - | 
| 69 | msgsnd | man/ | cs/ | 45 | int | msqid | struct | msgbuf | *msgp | size_t | msgsz | int | msgflg | - | - | 
| 70 | msgrcv | man/ | cs/ | 46 | int | msqid | struct | msgbuf | *msgp | size_t | msgsz | long | msgtyp | int | msgflg | - | 
| 71 | msgctl | man/ | cs/ | 47 | int | msqid | int | cmd | struct | msqid_ds | *buf | - | - | - | 
| 72 | fcntl | man/ | cs/ | 48 | unsigned | int | fd | unsigned | int | cmd | unsigned | long | arg | - | - | - | 
| 73 | flock | man/ | cs/ | 49 | unsigned | int | fd | unsigned | int | cmd | - | - | - | - | 
| 74 | fsync | man/ | cs/ | 4A | unsigned | int | fd | - | - | - | - | - | 
| 75 | fdatasync | man/ | cs/ | 4B | unsigned | int | fd | - | - | - | - | - | 
| 76 | truncate | man/ | cs/ | 4C | const | char | *path | long | length | - | - | - | - | 
| 77 | ftruncate | man/ | cs/ | 4D | unsigned | int | fd | unsigned | long | length | - | - | - | - | 
| 78 | getdents | man/ | cs/ | 4E | unsigned | int | fd | struct | linux_dirent | *dirent | unsigned | int | count | - | - | - | 
| 79 | getcwd | man/ | cs/ | 4F | char | *buf | unsigned | long | size | - | - | - | - | 
| 80 | chdir | man/ | cs/ | 50 | const | char | *filename | - | - | - | - | - | 
| 81 | fchdir | man/ | cs/ | 51 | unsigned | int | fd | - | - | - | - | - | 
| 82 | rename | man/ | cs/ | 52 | const | char | *oldname | const | char | *newname | - | - | - | - | 
| 83 | mkdir | man/ | cs/ | 53 | const | char | *pathname | umode_t | mode | - | - | - | - | 
| 84 | rmdir | man/ | cs/ | 54 | const | char | *pathname | - | - | - | - | - | 
| 85 | creat | man/ | cs/ | 55 | const | char | *pathname | umode_t | mode | - | - | - | - | 
| 86 | link | man/ | cs/ | 56 | const | char | *oldname | const | char | *newname | - | - | - | - | 
| 87 | unlink | man/ | cs/ | 57 | const | char | *pathname | - | - | - | - | - | 
| 88 | symlink | man/ | cs/ | 58 | const | char | *old | const | char | *new | - | - | - | - | 
| 89 | readlink | man/ | cs/ | 59 | const | char | *path | char | *buf | int | bufsiz | - | - | - | 
| 90 | chmod | man/ | cs/ | 5A | const | char | *filename | umode_t | mode | - | - | - | - | 
| 91 | fchmod | man/ | cs/ | 5B | unsigned | int | fd | umode_t | mode | - | - | - | - | 
| 92 | chown | man/ | cs/ | 5C | const | char | *filename | uid_t | user | gid_t | group | - | - | - | 
| 93 | fchown | man/ | cs/ | 5D | unsigned | int | fd | uid_t | user | gid_t | group | - | - | - | 
| 94 | lchown | man/ | cs/ | 5E | const | char | *filename | uid_t | user | gid_t | group | - | - | - | 
| 95 | umask | man/ | cs/ | 5F | int | mask | - | - | - | - | - | 
| 96 | gettimeofday | man/ | cs/ | 60 | struct | timeval | *tv | struct | timezone | *tz | - | - | - | - | 
| 97 | getrlimit | man/ | cs/ | 61 | unsigned | int | resource | struct | rlimit | *rlim | - | - | - | - | 
| 98 | getrusage | man/ | cs/ | 62 | int | who | struct | rusage | *ru | - | - | - | - | 
| 99 | sysinfo | man/ | cs/ | 63 | struct | sysinfo | *info | - | - | - | - | - | 
| 100 | times | man/ | cs/ | 64 | struct | tms | *tbuf | - | - | - | - | - | 
| 101 | ptrace | man/ | cs/ | 65 | long | request | long | pid | unsigned | long | addr | unsigned | long | data | - | - | 
| 102 | getuid | man/ | cs/ | 66 | - | - | - | - | - | - | 
| 103 | syslog | man/ | cs/ | 67 | int | type | char | *buf | int | len | - | - | - | 
| 104 | getgid | man/ | cs/ | 68 | - | - | - | - | - | - | 
| 105 | setuid | man/ | cs/ | 69 | uid_t | uid | - | - | - | - | - | 
| 106 | setgid | man/ | cs/ | 6A | gid_t | gid | - | - | - | - | - | 
| 107 | geteuid | man/ | cs/ | 6B | - | - | - | - | - | - | 
| 108 | getegid | man/ | cs/ | 6C | - | - | - | - | - | - | 
| 109 | setpgid | man/ | cs/ | 6D | pid_t | pid | pid_t | pgid | - | - | - | - | 
| 110 | getppid | man/ | cs/ | 6E | - | - | - | - | - | - | 
| 111 | getpgrp | man/ | cs/ | 6F | - | - | - | - | - | - | 
| 112 | setsid | man/ | cs/ | 70 | - | - | - | - | - | - | 
| 113 | setreuid | man/ | cs/ | 71 | uid_t | ruid | uid_t | euid | - | - | - | - | 
| 114 | setregid | man/ | cs/ | 72 | gid_t | rgid | gid_t | egid | - | - | - | - | 
| 115 | getgroups | man/ | cs/ | 73 | int | gidsetsize | gid_t | *grouplist | - | - | - | - | 
| 116 | setgroups | man/ | cs/ | 74 | int | gidsetsize | gid_t | *grouplist | - | - | - | - | 
| 117 | setresuid | man/ | cs/ | 75 | uid_t | ruid | uid_t | euid | uid_t | suid | - | - | - | 
| 118 | getresuid | man/ | cs/ | 76 | uid_t | *ruid | uid_t | *euid | uid_t | *suid | - | - | - | 
| 119 | setresgid | man/ | cs/ | 77 | gid_t | rgid | gid_t | egid | gid_t | sgid | - | - | - | 
| 120 | getresgid | man/ | cs/ | 78 | gid_t | *rgid | gid_t | *egid | gid_t | *sgid | - | - | - | 
| 121 | getpgid | man/ | cs/ | 79 | pid_t | pid | - | - | - | - | - | 
| 122 | setfsuid | man/ | cs/ | 7A | uid_t | uid | - | - | - | - | - | 
| 123 | setfsgid | man/ | cs/ | 7B | gid_t | gid | - | - | - | - | - | 
| 124 | getsid | man/ | cs/ | 7C | pid_t | pid | - | - | - | - | - | 
| 125 | capget | man/ | cs/ | 7D | cap_user_header_t | header | cap_user_data_t | dataptr | - | - | - | - | 
| 126 | capset | man/ | cs/ | 7E | cap_user_header_t | header | const | cap_user_data_t | data | - | - | - | - | 
| 127 | rt_sigpending | man/ | cs/ | 7F | sigset_t | *set | size_t | sigsetsize | - | - | - | - | 
| 128 | rt_sigtimedwait | man/ | cs/ | 80 | const | sigset_t | *uthese | siginfo_t | *uinfo | const | struct | __kernel_timespec | *uts | size_t | sigsetsize | - | - | 
| 129 | rt_sigqueueinfo | man/ | cs/ | 81 | pid_t | pid | int | sig | siginfo_t | *uinfo | - | - | - | 
| 130 | rt_sigsuspend | man/ | cs/ | 82 | sigset_t | *unewset | size_t | sigsetsize | - | - | - | - | 
| 131 | sigaltstack | man/ | cs/ | 83 | const | struct | sigaltstack | *uss | struct | sigaltstack | *uoss | - | - | - | - | 
| 132 | utime | man/ | cs/ | 84 | char | *filename | struct | utimbuf | *times | - | - | - | - | 
| 133 | mknod | man/ | cs/ | 85 | const | char | *filename | umode_t | mode | unsigned | dev | - | - | - | 
| 134 | uselib | man/ | cs/ | 86 | const | char | *library | - | - | - | - | - | 
| 135 | personality | man/ | cs/ | 87 | unsigned | int | personality | - | - | - | - | - | 
| 136 | ustat | man/ | cs/ | 88 | unsigned | dev | struct | ustat | *ubuf | - | - | - | - | 
| 137 | statfs | man/ | cs/ | 89 | const | char | * | path | struct | statfs | *buf | - | - | - | - | 
| 138 | fstatfs | man/ | cs/ | 8A | unsigned | int | fd | struct | statfs | *buf | - | - | - | - | 
| 139 | sysfs | man/ | cs/ | 8B | int | option | unsigned | long | arg1 | unsigned | long | arg2 | - | - | - | 
| 140 | getpriority | man/ | cs/ | 8C | int | which | int | who | - | - | - | - | 
| 141 | setpriority | man/ | cs/ | 8D | int | which | int | who | int | niceval | - | - | - | 
| 142 | sched_setparam | man/ | cs/ | 8E | pid_t | pid | struct | sched_param | *param | - | - | - | - | 
| 143 | sched_getparam | man/ | cs/ | 8F | pid_t | pid | struct | sched_param | *param | - | - | - | - | 
| 144 | sched_setscheduler | man/ | cs/ | 90 | pid_t | pid | int | policy | struct | sched_param | *param | - | - | - | 
| 145 | sched_getscheduler | man/ | cs/ | 91 | pid_t | pid | - | - | - | - | - | 
| 146 | sched_get_priority_max | man/ | cs/ | 92 | int | policy | - | - | - | - | - | 
| 147 | sched_get_priority_min | man/ | cs/ | 93 | int | policy | - | - | - | - | - | 
| 148 | sched_rr_get_interval | man/ | cs/ | 94 | pid_t | pid | struct | __kernel_timespec | *interval | - | - | - | - | 
| 149 | mlock | man/ | cs/ | 95 | unsigned | long | start | size_t | len | - | - | - | - | 
| 150 | munlock | man/ | cs/ | 96 | unsigned | long | start | size_t | len | - | - | - | - | 
| 151 | mlockall | man/ | cs/ | 97 | int | flags | - | - | - | - | - | 
| 152 | munlockall | man/ | cs/ | 98 | - | - | - | - | - | - | 
| 153 | vhangup | man/ | cs/ | 99 | - | - | - | - | - | - | 
| 154 | modify_ldt | man/ | cs/ | 9A | ? | ? | ? | ? | ? | ? | 
| 155 | pivot_root | man/ | cs/ | 9B | const | char | *new_root | const | char | *put_old | - | - | - | - | 
| 156 | _sysctl | man/ | cs/ | 9C | ? | ? | ? | ? | ? | ? | 
| 157 | prctl | man/ | cs/ | 9D | int | option | unsigned | long | arg2 | unsigned | long | arg3 | unsigned | long | arg4 | unsigned | long | arg5 | - | 
| 158 | arch_prctl | man/ | cs/ | 9E | ? | ? | ? | ? | ? | ? | 
| 159 | adjtimex | man/ | cs/ | 9F | struct | __kernel_timex | *txc_p | - | - | - | - | - | 
| 160 | setrlimit | man/ | cs/ | A0 | unsigned | int | resource | struct | rlimit | *rlim | - | - | - | - | 
| 161 | chroot | man/ | cs/ | A1 | const | char | *filename | - | - | - | - | - | 
| 162 | sync | man/ | cs/ | A2 | - | - | - | - | - | - | 
| 163 | acct | man/ | cs/ | A3 | const | char | *name | - | - | - | - | - | 
| 164 | settimeofday | man/ | cs/ | A4 | struct | timeval | *tv | struct | timezone | *tz | - | - | - | - | 
| 165 | mount | man/ | cs/ | A5 | char | *dev_name | char | *dir_name | char | *type | unsigned | long | flags | void | *data | - | 
| 166 | umount2 | man/ | cs/ | A6 | ? | ? | ? | ? | ? | ? | 
| 167 | swapon | man/ | cs/ | A7 | const | char | *specialfile | int | swap_flags | - | - | - | - | 
| 168 | swapoff | man/ | cs/ | A8 | const | char | *specialfile | - | - | - | - | - | 
| 169 | reboot | man/ | cs/ | A9 | int | magic1 | int | magic2 | unsigned | int | cmd | void | *arg | - | - | 
| 170 | sethostname | man/ | cs/ | AA | char | *name | int | len | - | - | - | - | 
| 171 | setdomainname | man/ | cs/ | AB | char | *name | int | len | - | - | - | - | 
| 172 | iopl | man/ | cs/ | AC | ? | ? | ? | ? | ? | ? | 
| 173 | ioperm | man/ | cs/ | AD | unsigned | long | from | unsigned | long | num | int | on | - | - | - | 
| 174 | create_module | man/ | cs/ | AE | ? | ? | ? | ? | ? | ? | 
| 175 | init_module | man/ | cs/ | AF | void | *umod | unsigned | long | len | const | char | *uargs | - | - | - | 
| 176 | delete_module | man/ | cs/ | B0 | const | char | *name_user | unsigned | int | flags | - | - | - | - | 
| 177 | get_kernel_syms | man/ | cs/ | B1 | ? | ? | ? | ? | ? | ? | 
| 178 | query_module | man/ | cs/ | B2 | ? | ? | ? | ? | ? | ? | 
| 179 | quotactl | man/ | cs/ | B3 | unsigned | int | cmd | const | char | *special | qid_t | id | void | *addr | - | - | 
| 180 | nfsservctl | man/ | cs/ | B4 | ? | ? | ? | ? | ? | ? | 
| 181 | getpmsg | man/ | cs/ | B5 | ? | ? | ? | ? | ? | ? | 
| 182 | putpmsg | man/ | cs/ | B6 | ? | ? | ? | ? | ? | ? | 
| 183 | afs_syscall | man/ | cs/ | B7 | ? | ? | ? | ? | ? | ? | 
| 184 | tuxcall | man/ | cs/ | B8 | ? | ? | ? | ? | ? | ? | 
| 185 | security | man/ | cs/ | B9 | ? | ? | ? | ? | ? | ? | 
| 186 | gettid | man/ | cs/ | BA | - | - | - | - | - | - | 
| 187 | readahead | man/ | cs/ | BB | int | fd | loff_t | offset | size_t | count | - | - | - | 
| 188 | setxattr | man/ | cs/ | BC | const | char | *path | const | char | *name | const | void | *value | size_t | size | int | flags | - | 
| 189 | lsetxattr | man/ | cs/ | BD | const | char | *path | const | char | *name | const | void | *value | size_t | size | int | flags | - | 
| 190 | fsetxattr | man/ | cs/ | BE | int | fd | const | char | *name | const | void | *value | size_t | size | int | flags | - | 
| 191 | getxattr | man/ | cs/ | BF | const | char | *path | const | char | *name | void | *value | size_t | size | - | - | 
| 192 | lgetxattr | man/ | cs/ | C0 | const | char | *path | const | char | *name | void | *value | size_t | size | - | - | 
| 193 | fgetxattr | man/ | cs/ | C1 | int | fd | const | char | *name | void | *value | size_t | size | - | - | 
| 194 | listxattr | man/ | cs/ | C2 | const | char | *path | char | *list | size_t | size | - | - | - | 
| 195 | llistxattr | man/ | cs/ | C3 | const | char | *path | char | *list | size_t | size | - | - | - | 
| 196 | flistxattr | man/ | cs/ | C4 | int | fd | char | *list | size_t | size | - | - | - | 
| 197 | removexattr | man/ | cs/ | C5 | const | char | *path | const | char | *name | - | - | - | - | 
| 198 | lremovexattr | man/ | cs/ | C6 | const | char | *path | const | char | *name | - | - | - | - | 
| 199 | fremovexattr | man/ | cs/ | C7 | int | fd | const | char | *name | - | - | - | - | 
| 200 | tkill | man/ | cs/ | C8 | pid_t | pid | int | sig | - | - | - | - | 
| 201 | time | man/ | cs/ | C9 | time_t | *tloc | - | - | - | - | - | 
| 202 | futex | man/ | cs/ | CA | u32 | *uaddr | int | op | u32 | val | struct | __kernel_timespec | *utime | u32 | *uaddr2 | u32 | val3 | 
| 203 | sched_setaffinity | man/ | cs/ | CB | pid_t | pid | unsigned | int | len | unsigned | long | *user_mask_ptr | - | - | - | 
| 204 | sched_getaffinity | man/ | cs/ | CC | pid_t | pid | unsigned | int | len | unsigned | long | *user_mask_ptr | - | - | - | 
| 205 | set_thread_area | man/ | cs/ | CD | ? | ? | ? | ? | ? | ? | 
| 206 | io_setup | man/ | cs/ | CE | unsigned | nr_reqs | aio_context_t | *ctx | - | - | - | - | 
| 207 | io_destroy | man/ | cs/ | CF | aio_context_t | ctx | - | - | - | - | - | 
| 208 | io_getevents | man/ | cs/ | D0 | aio_context_t | ctx_id | long | min_nr | long | nr | struct | io_event | *events | struct | __kernel_timespec | *timeout | - | 
| 209 | io_submit | man/ | cs/ | D1 | aio_context_t | long | struct | iocb | * | * | - | - | - | 
| 210 | io_cancel | man/ | cs/ | D2 | aio_context_t | ctx_id | struct | iocb | *iocb | struct | io_event | *result | - | - | - | 
| 211 | get_thread_area | man/ | cs/ | D3 | ? | ? | ? | ? | ? | ? | 
| 212 | lookup_dcookie | man/ | cs/ | D4 | u64 | cookie64 | char | *buf | size_t | len | - | - | - | 
| 213 | epoll_create | man/ | cs/ | D5 | int | size | - | - | - | - | - | 
| 214 | epoll_ctl_old | man/ | cs/ | D6 | ? | ? | ? | ? | ? | ? | 
| 215 | epoll_wait_old | man/ | cs/ | D7 | ? | ? | ? | ? | ? | ? | 
| 216 | remap_file_pages | man/ | cs/ | D8 | unsigned | long | start | unsigned | long | size | unsigned | long | prot | unsigned | long | pgoff | unsigned | long | flags | - | 
| 217 | getdents64 | man/ | cs/ | D9 | unsigned | int | fd | struct | linux_dirent64 | *dirent | unsigned | int | count | - | - | - | 
| 218 | set_tid_address | man/ | cs/ | DA | int | *tidptr | - | - | - | - | - | 
| 219 | restart_syscall | man/ | cs/ | DB | - | - | - | - | - | - | 
| 220 | semtimedop | man/ | cs/ | DC | int | semid | struct | sembuf | *sops | unsigned | nsops | const | struct | __kernel_timespec | *timeout | - | - | 
| 221 | fadvise64 | man/ | cs/ | DD | int | fd | loff_t | offset | size_t | len | int | advice | - | - | 
| 222 | timer_create | man/ | cs/ | DE | clockid_t | which_clock | struct | sigevent | *timer_event_spec | timer_t | * | created_timer_id | - | - | - | 
| 223 | timer_settime | man/ | cs/ | DF | timer_t | timer_id | int | flags | const | struct | __kernel_itimerspec | *new_setting | struct | __kernel_itimerspec | *old_setting | - | - | 
| 224 | timer_gettime | man/ | cs/ | E0 | timer_t | timer_id | struct | __kernel_itimerspec | *setting | - | - | - | - | 
| 225 | timer_getoverrun | man/ | cs/ | E1 | timer_t | timer_id | - | - | - | - | - | 
| 226 | timer_delete | man/ | cs/ | E2 | timer_t | timer_id | - | - | - | - | - | 
| 227 | clock_settime | man/ | cs/ | E3 | clockid_t | which_clock | const | struct | __kernel_timespec | *tp | - | - | - | - | 
| 228 | clock_gettime | man/ | cs/ | E4 | clockid_t | which_clock | struct | __kernel_timespec | *tp | - | - | - | - | 
| 229 | clock_getres | man/ | cs/ | E5 | clockid_t | which_clock | struct | __kernel_timespec | *tp | - | - | - | - | 
| 230 | clock_nanosleep | man/ | cs/ | E6 | clockid_t | which_clock | int | flags | const | struct | __kernel_timespec | *rqtp | struct | __kernel_timespec | *rmtp | - | - | 
| 231 | exit_group | man/ | cs/ | E7 | int | error_code | - | - | - | - | - | 
| 232 | epoll_wait | man/ | cs/ | E8 | int | epfd | struct | epoll_event | *events | int | maxevents | int | timeout | - | - | 
| 233 | epoll_ctl | man/ | cs/ | E9 | int | epfd | int | op | int | fd | struct | epoll_event | *event | - | - | 
| 234 | tgkill | man/ | cs/ | EA | pid_t | tgid | pid_t | pid | int | sig | - | - | - | 
| 235 | utimes | man/ | cs/ | EB | char | *filename | struct | timeval | *utimes | - | - | - | - | 
| 236 | vserver | man/ | cs/ | EC | ? | ? | ? | ? | ? | ? | 
| 237 | mbind | man/ | cs/ | ED | unsigned | long | start | unsigned | long | len | unsigned | long | mode | const | unsigned | long | *nmask | unsigned | long | maxnode | unsigned | flags | 
| 238 | set_mempolicy | man/ | cs/ | EE | int | mode | const | unsigned | long | *nmask | unsigned | long | maxnode | - | - | - | 
| 239 | get_mempolicy | man/ | cs/ | EF | int | *policy | unsigned | long | *nmask | unsigned | long | maxnode | unsigned | long | addr | unsigned | long | flags | - | 
| 240 | mq_open | man/ | cs/ | F0 | const | char | *name | int | oflag | umode_t | mode | struct | mq_attr | *attr | - | - | 
| 241 | mq_unlink | man/ | cs/ | F1 | const | char | *name | - | - | - | - | - | 
| 242 | mq_timedsend | man/ | cs/ | F2 | mqd_t | mqdes | const | char | *msg_ptr | size_t | msg_len | unsigned | int | msg_prio | const | struct | __kernel_timespec | *abs_timeout | - | 
| 243 | mq_timedreceive | man/ | cs/ | F3 | mqd_t | mqdes | char | *msg_ptr | size_t | msg_len | unsigned | int | *msg_prio | const | struct | __kernel_timespec | *abs_timeout | - | 
| 244 | mq_notify | man/ | cs/ | F4 | mqd_t | mqdes | const | struct | sigevent | *notification | - | - | - | - | 
| 245 | mq_getsetattr | man/ | cs/ | F5 | mqd_t | mqdes | const | struct | mq_attr | *mqstat | struct | mq_attr | *omqstat | - | - | - | 
| 246 | kexec_load | man/ | cs/ | F6 | unsigned | long | entry | unsigned | long | nr_segments | struct | kexec_segment | *segments | unsigned | long | flags | - | - | 
| 247 | waitid | man/ | cs/ | F7 | int | which | pid_t | pid | struct | siginfo | *infop | int | options | struct | rusage | *ru | - | 
| 248 | add_key | man/ | cs/ | F8 | const | char | *_type | const | char | *_description | const | void | *_payload | size_t | plen | key_serial_t | destringid | - | 
| 249 | request_key | man/ | cs/ | F9 | const | char | *_type | const | char | *_description | const | char | *_callout_info | key_serial_t | destringid | - | - | 
| 250 | keyctl | man/ | cs/ | FA | int | cmd | unsigned | long | arg2 | unsigned | long | arg3 | unsigned | long | arg4 | unsigned | long | arg5 | - | 
| 251 | ioprio_set | man/ | cs/ | FB | int | which | int | who | int | ioprio | - | - | - | 
| 252 | ioprio_get | man/ | cs/ | FC | int | which | int | who | - | - | - | - | 
| 253 | inotify_init | man/ | cs/ | FD | - | - | - | - | - | - | 
| 254 | inotify_add_watch | man/ | cs/ | FE | int | fd | const | char | *path | u32 | mask | - | - | - | 
| 255 | inotify_rm_watch | man/ | cs/ | FF | int | fd | __s32 | wd | - | - | - | - | 
| 256 | migrate_pages | man/ | cs/ | 100 | pid_t | pid | unsigned | long | maxnode | const | unsigned | long | *from | const | unsigned | long | *to | - | - | 
| 257 | openat | man/ | cs/ | 101 | int | dfd | const | char | *filename | int | flags | umode_t | mode | - | - | 
| 258 | mkdirat | man/ | cs/ | 102 | int | dfd | const | char | * | pathname | umode_t | mode | - | - | - | 
| 259 | mknodat | man/ | cs/ | 103 | int | dfd | const | char | * | filename | umode_t | mode | unsigned | dev | - | - | 
| 260 | fchownat | man/ | cs/ | 104 | int | dfd | const | char | *filename | uid_t | user | gid_t | group | int | flag | - | 
| 261 | futimesat | man/ | cs/ | 105 | int | dfd | const | char | *filename | struct | timeval | *utimes | - | - | - | 
| 262 | newfstatat | man/ | cs/ | 106 | int | dfd | const | char | *filename | struct | stat | *statbuf | int | flag | - | - | 
| 263 | unlinkat | man/ | cs/ | 107 | int | dfd | const | char | * | pathname | int | flag | - | - | - | 
| 264 | renameat | man/ | cs/ | 108 | int | olddfd | const | char | * | oldname | int | newdfd | const | char | * | newname | - | - | 
| 265 | linkat | man/ | cs/ | 109 | int | olddfd | const | char | *oldname | int | newdfd | const | char | *newname | int | flags | - | 
| 266 | symlinkat | man/ | cs/ | 10A | const | char | * | oldname | int | newdfd | const | char | * | newname | - | - | - | 
| 267 | readlinkat | man/ | cs/ | 10B | int | dfd | const | char | *path | char | *buf | int | bufsiz | - | - | 
| 268 | fchmodat | man/ | cs/ | 10C | int | dfd | const | char | * | filename | umode_t | mode | - | - | - | 
| 269 | faccessat | man/ | cs/ | 10D | int | dfd | const | char | *filename | int | mode | - | - | - | 
| 270 | pselect6 | man/ | cs/ | 10E | int | fd_set | * | fd_set | * | fd_set | * | struct | __kernel_timespec | * | void | * | 
| 271 | ppoll | man/ | cs/ | 10F | struct | pollfd | * | unsigned | int | struct | __kernel_timespec | * | const | sigset_t | * | size_t | - | 
| 272 | unshare | man/ | cs/ | 110 | unsigned | long | unshare_flags | - | - | - | - | - | 
| 273 | set_robust_list | man/ | cs/ | 111 | struct | robust_list_head | *head | size_t | len | - | - | - | - | 
| 274 | get_robust_list | man/ | cs/ | 112 | int | pid | struct | robust_list_head | * | *head_ptr | size_t | *len_ptr | - | - | - | 
| 275 | splice | man/ | cs/ | 113 | int | fd_in | loff_t | *off_in | int | fd_out | loff_t | *off_out | size_t | len | unsigned | int | flags | 
| 276 | tee | man/ | cs/ | 114 | int | fdin | int | fdout | size_t | len | unsigned | int | flags | - | - | 
| 277 | sync_file_range | man/ | cs/ | 115 | int | fd | loff_t | offset | loff_t | nbytes | unsigned | int | flags | - | - | 
| 278 | vmsplice | man/ | cs/ | 116 | int | fd | const | struct | iovec | *iov | unsigned | long | nr_segs | unsigned | int | flags | - | - | 
| 279 | move_pages | man/ | cs/ | 117 | pid_t | pid | unsigned | long | nr_pages | const | void | * | *pages | const | int | *nodes | int | *status | int | flags | 
| 280 | utimensat | man/ | cs/ | 118 | int | dfd | const | char | *filename | struct | __kernel_timespec | *utimes | int | flags | - | - | 
| 281 | epoll_pwait | man/ | cs/ | 119 | int | epfd | struct | epoll_event | *events | int | maxevents | int | timeout | const | sigset_t | *sigmask | size_t | sigsetsize | 
| 282 | signalfd | man/ | cs/ | 11A | int | ufd | sigset_t | *user_mask | size_t | sizemask | - | - | - | 
| 283 | timerfd_create | man/ | cs/ | 11B | int | clockid | int | flags | - | - | - | - | 
| 284 | eventfd | man/ | cs/ | 11C | unsigned | int | count | - | - | - | - | - | 
| 285 | fallocate | man/ | cs/ | 11D | int | fd | int | mode | loff_t | offset | loff_t | len | - | - | 
| 286 | timerfd_settime | man/ | cs/ | 11E | int | ufd | int | flags | const | struct | __kernel_itimerspec | *utmr | struct | __kernel_itimerspec | *otmr | - | - | 
| 287 | timerfd_gettime | man/ | cs/ | 11F | int | ufd | struct | __kernel_itimerspec | *otmr | - | - | - | - | 
| 288 | accept4 | man/ | cs/ | 120 | int | struct | sockaddr | * | int | * | int | - | - | 
| 289 | signalfd4 | man/ | cs/ | 121 | int | ufd | sigset_t | *user_mask | size_t | sizemask | int | flags | - | - | 
| 290 | eventfd2 | man/ | cs/ | 122 | unsigned | int | count | int | flags | - | - | - | - | 
| 291 | epoll_create1 | man/ | cs/ | 123 | int | flags | - | - | - | - | - | 
| 292 | dup3 | man/ | cs/ | 124 | unsigned | int | oldfd | unsigned | int | newfd | int | flags | - | - | - | 
| 293 | pipe2 | man/ | cs/ | 125 | int | *fildes | int | flags | - | - | - | - | 
| 294 | inotify_init1 | man/ | cs/ | 126 | int | flags | - | - | - | - | - | 
| 295 | preadv | man/ | cs/ | 127 | unsigned | long | fd | const | struct | iovec | *vec | unsigned | long | vlen | unsigned | long | pos_l | unsigned | long | pos_h | - | 
| 296 | pwritev | man/ | cs/ | 128 | unsigned | long | fd | const | struct | iovec | *vec | unsigned | long | vlen | unsigned | long | pos_l | unsigned | long | pos_h | - | 
| 297 | rt_tgsigqueueinfo | man/ | cs/ | 129 | pid_t | tgid | pid_t | pid | int | sig | siginfo_t | *uinfo | - | - | 
| 298 | perf_event_open | man/ | cs/ | 12A | struct | perf_event_attr | *attr_uptr | pid_t | pid | int | cpu | int | group_fd | unsigned | long | flags | - | 
| 299 | recvmmsg | man/ | cs/ | 12B | int | fd | struct | mmsghdr | *msg | unsigned | int | vlen | unsigned | flags | struct | __kernel_timespec | *timeout | - | 
| 300 | fanotify_init | man/ | cs/ | 12C | unsigned | int | flags | unsigned | int | event_f_flags | - | - | - | - | 
| 301 | fanotify_mark | man/ | cs/ | 12D | int | fanotify_fd | unsigned | int | flags | u64 | mask | int | fd | const | char | *pathname | - | 
| 302 | prlimit64 | man/ | cs/ | 12E | pid_t | pid | unsigned | int | resource | const | struct | rlimit64 | *new_rlim | struct | rlimit64 | *old_rlim | - | - | 
| 303 | name_to_handle_at | man/ | cs/ | 12F | int | dfd | const | char | *name | struct | file_handle | *handle | int | *mnt_id | int | flag | - | 
| 304 | open_by_handle_at | man/ | cs/ | 130 | int | mountdirfd | struct | file_handle | *handle | int | flags | - | - | - | 
| 305 | clock_adjtime | man/ | cs/ | 131 | clockid_t | which_clock | struct | __kernel_timex | *tx | - | - | - | - | 
| 306 | syncfs | man/ | cs/ | 132 | int | fd | - | - | - | - | - | 
| 307 | sendmmsg | man/ | cs/ | 133 | int | fd | struct | mmsghdr | *msg | unsigned | int | vlen | unsigned | flags | - | - | 
| 308 | setns | man/ | cs/ | 134 | int | fd | int | nstype | - | - | - | - | 
| 309 | getcpu | man/ | cs/ | 135 | unsigned | *cpu | unsigned | *node | struct | getcpu_cache | *cache | - | - | - | 
| 310 | process_vm_readv | man/ | cs/ | 136 | pid_t | pid | const | struct | iovec | *lvec | unsigned | long | liovcnt | const | struct | iovec | *rvec | unsigned | long | riovcnt | unsigned | long | flags | 
| 311 | process_vm_writev | man/ | cs/ | 137 | pid_t | pid | const | struct | iovec | *lvec | unsigned | long | liovcnt | const | struct | iovec | *rvec | unsigned | long | riovcnt | unsigned | long | flags | 
| 312 | kcmp | man/ | cs/ | 138 | pid_t | pid1 | pid_t | pid2 | int | type | unsigned | long | idx1 | unsigned | long | idx2 | - | 
| 313 | finit_module | man/ | cs/ | 139 | int | fd | const | char | *uargs | int | flags | - | - | - | 
| 314 | sched_setattr | man/ | cs/ | 13A | pid_t | pid | struct | sched_attr | *attr | unsigned | int | flags | - | - | - | 
| 315 | sched_getattr | man/ | cs/ | 13B | pid_t | pid | struct | sched_attr | *attr | unsigned | int | size | unsigned | int | flags | - | - | 
| 316 | renameat2 | man/ | cs/ | 13C | int | olddfd | const | char | *oldname | int | newdfd | const | char | *newname | unsigned | int | flags | - | 
| 317 | seccomp | man/ | cs/ | 13D | unsigned | int | op | unsigned | int | flags | void | *uargs | - | - | - | 
| 318 | getrandom | man/ | cs/ | 13E | char | *buf | size_t | count | unsigned | int | flags | - | - | - | 
| 319 | memfd_create | man/ | cs/ | 13F | const | char | *uname_ptr | unsigned | int | flags | - | - | - | - | 
| 320 | kexec_file_load | man/ | cs/ | 140 | int | kernel_fd | int | initrd_fd | unsigned | long | cmdline_len | const | char | *cmdline_ptr | unsigned | long | flags | - | 
| 321 | bpf | man/ | cs/ | 141 | int | cmd | union | bpf_attr | *attr | unsigned | int | size | - | - | - | 
| 322 | execveat | man/ | cs/ | 142 | int | dfd | const | char | *filename | const | char | *const | *argv | const | char | *const | *envp | int | flags | - | 
| 323 | userfaultfd | man/ | cs/ | 143 | int | flags | - | - | - | - | - | 
| 324 | membarrier | man/ | cs/ | 144 | int | cmd | int | flags | - | - | - | - | 
| 325 | mlock2 | man/ | cs/ | 145 | unsigned | long | start | size_t | len | int | flags | - | - | - | 
| 326 | copy_file_range | man/ | cs/ | 146 | int | fd_in | loff_t | *off_in | int | fd_out | loff_t | *off_out | size_t | len | unsigned | int | flags | 
| 327 | preadv2 | man/ | cs/ | 147 | unsigned | long | fd | const | struct | iovec | *vec | unsigned | long | vlen | unsigned | long | pos_l | unsigned | long | pos_h | rwf_t | flags | 
| 328 | pwritev2 | man/ | cs/ | 148 | unsigned | long | fd | const | struct | iovec | *vec | unsigned | long | vlen | unsigned | long | pos_l | unsigned | long | pos_h | rwf_t | flags | 
| 329 | pkey_mprotect | man/ | cs/ | 149 | unsigned | long | start | size_t | len | unsigned | long | prot | int | pkey | - | - | 
| 330 | pkey_alloc | man/ | cs/ | 14A | unsigned | long | flags | unsigned | long | init_val | - | - | - | - | 
| 331 | pkey_free | man/ | cs/ | 14B | int | pkey | - | - | - | - | - | 
| 332 | statx | man/ | cs/ | 14C | int | dfd | const | char | *path | unsigned | flags | unsigned | mask | struct | statx | *buffer | - | 
