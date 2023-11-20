# 윈도우에 리눅스를 설치하는 과정과, 리눅스 커널 위에 qemu 설치를 진행해서 boot 하는 방법

## 순서
1. 환경설정 <br>
2. 윈도우에 리눅스 설치과정  <br>
3. qemu 설치과정  <br>
4. 커널 이미지 빌드와 쉘 파일 작성 후 linux 위에 linux 실행 <br>
5. gdb를 사용해 linux 위의 linux와 연결 <br>
6. 이번 과제에 사용된 파일과 용어 간략히 정리 <br>
7. 추후 진행할 것 <br> <br>

## 1. 환경 설정 (윈도우 10기준)
bios의 vt-d를 켜주고 <br>
hyper-v를 꺼준다. <br> <br>

## 2. 윈도우에 리눅스 설치과정
(1). virtualbox를 통해 ubuntu 22.04를 다운받음 <br>
https://www.virtualbox.org/wiki/Linux_Downloads <br> <br>
(2). oracle vm virtualbox extension pack를 통해 확장팩을 다운받음 <br>
https://www.virtualbox.org/wiki/Downloads <br>
VirtualBox 7.0.12 Software Developer Kit (SDK) <br>
​All platforms <br> <br>
(3). 진행방법 <br>
1. 다운받은 linux file (ubuntu-22.04.3-desktop-amd64.iso)를 삽입 <br>
2. cpu개수 4개, Nested VT-x/AMD-V on, memory 4096MB, ext 40GB, video memory 48GB, 가상화 on -> start <br> <br>

## 3. qemu 설치과정
* qemu version : v6.2.0, linux version : v6.0.0 <br> <br>
$ sudo apt install libvirt-daemon <br>
$ sudo apt install -y qemu qemu-kvm libvirt-daemon libvirt-clients bridge-utils virt-manager <br>
$ sudo systemctl enable libvirtd <br>
$ sudo systemctl start libvirtd <br>
$ sudo apt install git <br>
$ git clone https://gitlab.com/qemu-project/qemu.git <br>
$ cd qemu <br>
$ git submodule init <br>
$ git submodule update --recursive <br>
$ python -m ensurepip --upgrade <br>
$ sudo apt-get install python3-sphinx <br>
$ pip install sphinx-rtd-theme <br>
$ sudo apt-get install ninja-build <br>
$ sudo apt-get install pkg-config <br>
$ sudo apt install flex <br>
$ sudo apt-get install bison <br>
$ ./configure <br>
$ make <br> <br>

## 4. 커널 이미지 빌드와 쉘 파일 작성 후 linux 위에 linux 실행
* 1. 커널 이미지 빌드 <br>
$ sudo apt-get install build-essential libncurses5 libncurses5-dev bin86 kernelpackage libssl-dev bison flex libelf-dev  <br>
$ wget https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-6.0.tar.gz <br>
$ tar -xzvf linux-6.0.tar.gz <br>
$ cd linux-6.0 <br>
$ make defconfig <br>
$ make menuconfig <br>
kernel hacking -> Generic Kernel Debbuging Instruments -> KGDB: kernel deugger : on <br>
-> KCSAN : dynamic data race <br>
detector : on <br>
$ vi .config # CONFIG_KCSAN_EARLY_ENABLE=N (따로 별도의 vi 이용법을 검색해서 해당 위치의 파일을 수정하였다.)  <br>
$ make <br> <br>
linux 커널 이미지는 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git를 통해 v6.0.0을 build 하였다.  <br>
이 결과로 linux-6.0에 kernel image인 bzimage가 생성된 것을 확일할 수 있었다. <br>
rootfs.img 파일로 boot를 진행시키려고 했지만 file공간과 disk 공간을 할당하는 방법을 몰라서 <br>
이 모든 것이 포함된 stretch.img를 실행하였다. <br> <br>
$ wget https://storage.googleapis.com/syzkaller/stretch.img <br> <br>
Poc file이 linux 내부에 있어야 해서 stretch.img에 넣어서 진행하였다. <br>
$ sudo mkdir /mnt <br>
$ sudo mount -o loop stretch.img /mnt <br>
$ sudo cp -r /home/han/bpf_2nd_primitive_PoC_230924_fin /mnt <br>
$ sudo unmount /mnt <br> <br> <br>

* 2. 쉘 파일 작성 후 linux 위에 linux 실행 <br>
쉘 파일 이름을 root.sh로 지정하고 사용함. <br>
$ vi root.sh <br>
qemu-system-x86_64 \ <br>
  -kernel /home/han/linux-6.0/arch/x86/boot/bzImage \ <br>
  -nographic \ <br>
  -smp 4 \ <br>
  -append "console=ttyS0 nokaslr root=/dev/sda rdinit=/bin/sh kgdboc=ttyS0" \ <br>
  -drive file=/home/han/stretch.img,format=raw \ <br>
  -m 2G \ <br>
  -enable-kvm \ <br>
  -cpu host \ <br>
  -s <br>
$ chmod 755 root.sh <br>
$ sudo ./root.sh을 진행하면 linux위에 리눅스가 build 된다. <br> <br>

## 5. gdb를 사용해 linux 위의 linux와 연결 
* home 파일에서 linux Terminal을 실행시킨 후에 명령어로 gdb vmlinux를 진행함 <br>
* target remote:1234를 통해 attach를 진행하였고 gdb와 linux를 attach 시키는데에 성공함. <br>
* gdb가 사용된 이유는 실행 파일 분석을 위해서이다. <br>

## 6. 이번 과제에 사용된 파일과 용어 간략히 정리
(1). 드라이브 파일 : bpf_2nd_primitive_PoC_230924_fin, bzImage, System.map, vmlinux <br> <br>
(2). 주요 키워드 : <br>
  1. Improper synchronization <br>
  2. Improper locking <br>
  3. Data race / Race condition <br>
  4. Use-After-Free <br>
  5. KCSAN <br>
  6. KASAN <br> <br>
(3). linux 위에 linux를 띄우기 위해 사용된 git:  <br>
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git <br> <br>
(4). 간략한 용어 정리 <br>
qemu: rom에 저장된 ASUS처럼 부팅시켜주는 역할을 함 (emulation qemu) <br>
rootfs에는 root에 대한 파일 시스템이 저장되있는 것 <br>
stretch.img안에도 똑같음 <br>
BzImage : 리눅스 커널의 핵심 <br>
vmlinux : 리눅스 커널의 구성요소 파일 <br>
gdb:  실행파일 관찰도구 <br>
.sh : 텍스트를 입력할 수 있는 쉘 파일 <br>
img  파일 안에 pocfile → HDD역할(보조기억장치) <br><br>
(5). 필요 용어 다시 정리
pocfile: Proof of Concept(POC) 파일의 약어로, 소프트웨어나 시스템의 기능이나 취약점을 검증하기 위해 작성된 파일입니다. <br>
bzimage: Linux 커널 이미지 파일의 압축된 형식 중 하나입니다.<br>
**system map :**  시스템의 구성 요소와 그들 간의 관계를 시각적으로 보여주는 도구입니다. <br>
data race : **다른 곳에서 읽을 가능성이 있는 어떤 메모리 위치에 쓰기 작업을 하는 것, 특히 그것이 위험한 상황** <br>
race condition : **현재 작업이 제어할 수 없는 또다른 작업과의 진행 순서, 즉 타이밍에 따라 결과가 달라져 여러 결과를 만들어낼 수 있는 바람직하지 않은 상황** <br>
UAF : 프로그래머가 코드를 작성시 실수를 하여 발생하는 것을 말한다. Heap 영역에 할당하여 사용 후에 free를 하면 해제가 되는 것이 맞지만 같은 크기로 다시 할당하는 겨우 한번 할당된 영역을 다시 재사용 됨으로써 발생하는 것을 뜻한다. <br>
Debugging : 프로그램이나 시스템에서 발생하는 오류를 찾아내고 수정하는 과정을 말합니다. <br>
reversing : 프로그램이나 소프트웨어의 동작 원리를 파악하고 분석하는 기술을 말합니다. <br>
improper synchronization : 멀티스레드 환경에서 동기화를 제대로 수행하지 않아 발생하는 문제입니다. <br>
Improper locking : 잠금을 부적절하게 처리하여 다른 스레드가 접근할 수 있도록 하는 것을 의미합니다. <br>
KCSAN : "Kernel Concurrency Sanitizer"의 약자로, 리눅스 커널에서 발생할 수 있는 동시성 버그를 감지하고 보고하는 도구 및 기술입니다. <br>
AddressSanitizer(ASan) : **런타임 시 C/C++ 코드에서 여러 유형의 메모리 오류를 감지하는 컴파일러 기반의 계측 기능**입니다. <br>
KASAN은 **커널을 위한 address sanitizer**이다. KASAN은 use-after-free, out-of-bounds access 등의 버그를 잡아낼 수 있다. CONFIG_KASAN=y로 활성화할 수 있다. <br>
KVM(커널 기반 가상 머신용)은 가상화 확장(Intel VT 또는 AMD-V)이 포함된 x86 하드웨어 기반 Linux용 전체 가상화 솔루션입니다. 이는 핵심 가상화 인프라를 제공하는 로드 가능한 커널 모듈 kvm.ko와 프로세서별 모듈 kvm-intel.ko 또는 kvm-amd.ko로 구성됩니다. <br>
KVM을 사용하면 수정되지 않은 Linux 또는 Windows 이미지를 실행하는 여러 가상 머신을 실행할 수 있습니다. 각 가상 머신에는 네트워크 카드, 디스크, 그래픽 어댑터 등 개인 가상화 하드웨어가 있습니다.<br>
FIFO는 "First-In, First-Out"의 약자로, 어떤 프로세스나 데이터가 처리되거나 저장될 때, 먼저 도착한 것이 먼저 처리되는 원칙을 나타내는 용어입니다. <br>
LIFO(Last In Frist Out) 스택에 마지막으로 입력된 자료가 제일 먼저 삭제 하는 방식 <br>
syzkaller는 커널 버그 및 보안 취약점을 찾기 위한 오픈 소스 툴이며, 주로 리눅스 커널과 다른 운영 체제의 커널에서 사용됩니다. <br>
컴퓨터 프로그래밍 언어에서 심볼(Symbol)과 그에 대응하는 정보를 저장하는 데이터 구조입니다. 심볼은 **변수, 함수, 클래스 등의 식별자(identifier)**를 말하며, 심볼 테이블은 이러한 식별자와 관련된 정보를 기록하고 유지합니다. <br>
**컴퓨터 KASLR란? :** KASLR은 커널 주소 공간 랜덤화(Kernel Address Space Layout Randomization)의 약자로, 커널의 주소 공간을 랜덤하게 배치하여 해커가 공격에 이용할 수 있는 취약점을 어렵게 만드는 보안 기술입니다. <br>
LILO는 Linux Loader의 약자로, 리눅스 운영체제를 부팅하기 위한 부트로더입니다. <br>
GRUB이란? **GNU프로젝트의 부트로더(간단히 말해서 컴퓨터를 켰을 때 가장 먼저 실행되는 프로그램)**이다. <br>
메모리 덤프는 **애플리케이션 또는 시스템 크래시 발생시에 메모리 내용을 표시하고 저장하는 일련의 프로세스**를 의미합니다. <br>
TCP, UDP 포트 : TCP 3 hand shake 방식 중요한 정보 전송, UDP : 단순한 정보 전송 <br>
GCC는 "GNU Compiler Collection"의 약어로, C, C++, 그리고 다른 프로그래밍 언어를 컴파일하는 데 사용되는 무료 오픈 소스 컴파일러 컬렉션입니다. <br>
Clang(클랭)은 C, C++, 그리고 Objective-C 프로그래밍 언어를 위한 오픈 소스 컴파일러입니다. <br> <br>

## 7. data race 방지 기법 및 커널 디버깅
1. 뮤텍스 (Mutex): 스레드 간에 공유 자원에 접근할 때 뮤텍스를 사용하여 동기화를 수행합니다. 이를 통해 한 스레드가 자원에 접근하고 수정 중일 때 다른 스레드가 접근하지 못하도록 할 수 있습니다. <br>
2. 세마포어 (Semaphore): 세마포어는 뮤텍스와 유사한 목적으로 사용됩니다. 여러 스레드가 특정 리소스에 동시에 접근하지 못하도록 하는데 도움을 줍니다.  <br>
3. 락 프리 데이터 구조: 락 프리 데이터 구조는 데이터 레이스를 방지하기 위해 뮤텍스나 세마포어를 사용하지 않고도 안전하게 다중 스레드 환경에서 사용할 수 있는 데이터 구조를 말합니다.  <br>
커널 디버깅을 위해서는 먼저 해당 커널에 디버깅 기능이 활성화되어 있어야 합니다. 이를 위해서는 .config 파일에서 CONFIG_DEBUG_KERNEL 옵션을 활성화하고, make menuconfig에서 "Kernel hacking" 항목에서 "Compile-time checks and compiler options" 아래 "Compile the kernel with debug info" 옵션을 활성화해주어야 합니다. 그리고 gdb와 같은 디버깅 도구를 사용하여 디버깅을 진행할 수 있습니다. <br>

**QEMU에 gdb 디버거를 어떻게 연결하나요?** <br>

먼저 QEMU를 -s -S 옵션으로 실행시키고, 다른 터미널에서 gdb를 실행시킨 후, target remote localhost:1234 명령어로 연결하면 됩니다. 디버깅을 시작하려면 (gdb) continue을 입력해서 디버깅을 시작하면 된다. <br>
stretch.img 파일 만들고 마운트 시키기  <br>
$ wget https://storage.googleapis.com/syzkaller/stretch.img <br>
$ sudo mkdir /mnt <br>
$ sudo mount -o loop stretch.img /mnt <br> 
$ sudo cp -r /home/han/bpf_2nd_primitive_PoC_230924_fin /mnt <br>
$ sudo unmount /mnt <br>
--- <br>
data race를 감지하는 방법을 키는 법 <br>
$ cd linux-6.0 <br>
$ make defconfig : default config 커널의 기본세팅을 생성해줌,  <br>
$ make menuconfig : vi .config를 통해 설정을 할 수 있지만 menuconfig을 통해 설정을 할 수 있다. <br>
:' <br>
kernel hacking -> Generic Kernel Debbuging Instruments -> KGDB: kernel deugger : on <br>
-> KCSAN : dynamic data race <br>
$ vi .config <br>
CONFIG_KCSAN_EARLY_ENABLE=n , CONFIG_KCSAN_STRICT=y , CONFIG_KCSAN=y <br>
캐뮤 실행 sudo ./root.sh // 캐뮤 닫기 ctrl a + c  (qemu) q <br>
echo on | tee /sys/kernel/debug/kcsan (on) <br>
cd /  <br>
ls <br>
./bpf_2nd_primitive_PoC_230924_fin <br>
make <br>
data race <br>
root@syzkaller:/# ./bpf_2nd_primitive_PoC_230924_fin > e.txt <br>

## 8. 발견된 data race (14개, 조금 이상한 것 2개)

data race

1. 

[   70.882557] =================================================================

[   70.884469] BUG: KCSAN: data-race in tick_sched_do_timer / tick_sched_do_timr

[   70.887622]

[   70.888352] read to 0xffffffff83491930 of 4 bytes by interrupt on cpu 1:

[   70.891253]  tick_sched_do_timer+0x2b/0x140

[   70.893021]  tick_sched_timer+0x39/0xc0

[   70.894609]  __hrtimer_run_queues+0x2c5/0x500

[   70.896423]  hrtimer_interrupt+0x1e0/0x3d0

[   70.898091]  __sysvec_apic_timer_interrupt+0xb9/0x220

[   70.901077]  sysvec_apic_timer_interrupt+0x8e/0xc0

[   70.903838]  asm_sysvec_apic_timer_interrupt+0x16/0x20

[   70.906100]  default_idle+0xb/0x10

[   70.907823]  default_idle_call+0x33/0xe0

[   70.909548]  do_idle+0x205/0x270

[   70.911022]  cpu_startup_entry+0x14/0x20

[   70.912769]  start_secondary+0xe8/0xf0

[   70.914414]  secondary_startup_64_no_verify+0xe0/0xeb

[   70.916519]

[   70.917177] write to 0xffffffff83491930 of 4 bytes by interrupt on cpu 2:

[   70.919958]  tick_sched_do_timer+0x122/0x140

[   70.921815]  tick_sched_timer+0x39/0xc0

[   70.923491]  __hrtimer_run_queues+0x2c5/0x500

[   70.925236]  hrtimer_interrupt+0x1e0/0x3d0

[   70.926970]  __sysvec_apic_timer_interrupt+0xb9/0x220

[   70.929120]  sysvec_apic_timer_interrupt+0x8e/0xc0

[   70.931096]  asm_sysvec_apic_timer_interrupt+0x16/0x20

[   70.933229]  default_idle+0xb/0x10

[   70.934641]  default_idle_call+0x33/0xe0

[   70.936277]  do_idle+0x205/0x270

[   70.937622]  cpu_startup_entry+0x14/0x20

[   70.939122]  start_secondary+0xe8/0xf0

[   70.940639]  secondary_startup_64_no_verify+0xe0/0xeb

[   70.942717]

[   70.943368] value changed: 0xffffffff -> 0x00000003

[   70.945377]

[   70.946021] Reported by Kernel Concurrency Sanitizer on:

[   70.948083] CPU: 2 PID: 0 Comm: swapper/2 Not tainted 6.0.0 #3

[   70.950260] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.154

[   70.953927] =================================================================

2. 

[   71.403529] =================================================================

[   71.404893] BUG: KCSAN: data-race in netlink_insert / netlink_insert

[   71.406659]

[   71.407304] read-write (marked) to 0xffff888005c14040 of 8 bytes by task 437:

[   71.410781]  netlink_insert+0x2bd/0x820

[   71.412372]  netlink_autobind.isra.0+0xc4/0x120

[   71.414210]  netlink_bind+0x3e2/0x580

[   71.416262]  __sys_bind+0x149/0x180

[   71.417722]  __x64_sys_bind+0x41/0x60

[   71.419229]  do_syscall_64+0x39/0x90

[   71.420751]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[   71.422799]

[   71.423467] read to 0xffff888005c14040 of 8 bytes by task 4375 on cpu 2:

[   71.426547]  netlink_insert+0x2e8/0x820

[   71.428166]  netlink_autobind.isra.0+0xc4/0x120

[   71.430672]  netlink_bind+0x3e2/0x580

[   71.432064]  __sys_bind+0x149/0x180

[   71.433448]  __x64_sys_bind+0x41/0x60

[   71.435353]  do_syscall_64+0x39/0x90

[   71.437055]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[   71.439125]

[   71.439763] Reported by Kernel Concurrency Sanitizer on:

[   71.442064] CPU: 2 PID: 4375 Comm: bpf_2nd_primiti Not tainted 6.0.0 #3

[   71.444867] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.154

[   71.448055] =================================================================

3. 

[   77.097513] =================================================================

[   77.099843] BUG: KCSAN: data-race in __alloc_file / copy_creds

[   77.101330]

[   77.101875] write to 0xffff88800432c9a0 of 4 bytes by task 10339 on cpu 2:

[   77.103515]  __alloc_file+0x53/0x170

[   77.104441]  alloc_empty_file+0x5e/0x110

[   77.106052]  alloc_file+0x47/0x2f0

[   77.107026]  alloc_file_pseudo+0x108/0x180

[   77.108809]  sock_alloc_file+0x5b/0x110

[   77.110045]  __sys_socket+0xe7/0x140

[   77.111466]  __x64_sys_socket+0x41/0x60

[   77.113607]  do_syscall_64+0x39/0x90

[   77.115445]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[   77.117962]

[   77.118783] write to 0xffff88800432c9a0 of 4 bytes by task 2954 on cpu 3:

[   77.122457]  copy_creds+0x19a/0x290

[   77.124164]  copy_process+0x803/0x2e40

[   77.125116]  kernel_clone+0xba/0x570

[   77.125949]  __do_sys_clone3+0x119/0x160

[   77.127058]  __x64_sys_clone3+0x32/0x50

[   77.128031]  do_syscall_64+0x39/0x90

[   77.128904]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[   77.130106]

[   77.130438] Reported by Kernel Concurrency Sanitizer on:

[   77.131754] CPU: 3 PID: 2954 Comm: bpf_2nd_primiti Not tainted 6.0.0 #3

[   77.133660] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.154

[   77.136714] =================================================================

4. 

[   79.294240] BUG: KCSAN: data-race in __hrtimer_run_queues / hrtimer_active

[   79.297827]

[   79.298115] read to 0xffff88807dc1df58 of 8 bytes by interrupt on cpu 3:

[   79.299290]  hrtimer_active+0x79/0xf0

[   79.299961]  task_tick_fair+0x2f/0x2a0

[   79.300627]  scheduler_tick+0x79/0xd0

[   79.301285]  update_process_times+0xb7/0xe0

[   79.302054]  tick_sched_handle+0x6f/0xb0

[   79.302752]  tick_sched_timer+0x91/0xc0

[   79.303495]  __hrtimer_run_queues+0x2c5/0x500

[   79.304530]  hrtimer_interrupt+0x1e0/0x3d0

[   79.305485]  __sysvec_apic_timer_interrupt+0xb9/0x220

[   79.306404]  sysvec_apic_timer_interrupt+0x3b/0xc0

[   79.307257]  asm_sysvec_apic_timer_interrupt+0x16/0x20

[   79.308191]

[   79.308485] write to 0xffff88807dc1df58 of 8 bytes by interrupt on cpu 0:

[   79.309705]  __hrtimer_run_queues+0x165/0x500

[   79.310523]  hrtimer_interrupt+0x1e0/0x3d0

[   79.311251]  __sysvec_apic_timer_interrupt+0xb9/0x220

[   79.312116]  sysvec_apic_timer_interrupt+0x8e/0xc0

[   79.312963]  asm_sysvec_apic_timer_interrupt+0x16/0x20

[   79.313884]  smp_call_function_many_cond+0x114/0x530

[   79.314758]  on_each_cpu_cond_mask+0x41/0x80

[   79.315515]  flush_tlb_mm_range+0x157/0x180

[   79.316247]  tlb_finish_mmu+0x226/0x3a0

[   79.316877]  zap_page_range+0x237/0x2b0

[   79.317481]  do_madvise.part.0+0x4da/0x1290

[   79.318548]  __x64_sys_madvise+0x89/0xb0

[   79.319278]  do_syscall_64+0x39/0x90

[   79.319975]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[   79.320863]

[   79.321146] Reported by Kernel Concurrency Sanitizer on:

[   79.322108] CPU: 0 PID: 12576 Comm: bpf_2nd_primiti Not tainted 6.0.0 #3

[   79.323250] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.154

[   79.324729] =================================================================

5. 

[   81.387320] BUG: KCSAN: data-race in ns_capable / rcu_core

[   81.389712]

[   81.390426] read to 0xffff888007eb102c of 4 bytes by interrupt on cpu 0:

[   81.393238]  rcu_core+0x558/0xfd0

[   81.394951]  rcu_core_si+0x12/0x20

[   81.396402]  __do_softirq+0xe4/0x2de

[   81.397967]  __irq_exit_rcu+0xba/0x100

[   81.399540]  sysvec_apic_timer_interrupt+0x93/0xc0

[   81.401683]  asm_sysvec_apic_timer_interrupt+0x16/0x20

[   81.404471]  delay_tsc+0x45/0xb0

[   81.405861]  kcsan_setup_watchpoint+0x1fd/0x4e0

[   81.407750]  ns_capable+0x6b/0x90

[   81.409566]  netlink_net_capable+0x97/0xb0

[   81.411366]  rtnetlink_rcv_msg+0xb9/0x570

[   81.413260]  netlink_rcv_skb+0x8b/0x190

[   81.414870]  rtnetlink_rcv+0x1d/0x30

[   81.416375]  netlink_unicast+0x354/0x4c0

[   81.418095]  netlink_sendmsg+0x4de/0x6e0

[   81.419780]  sock_sendmsg+0xb5/0xc0

[   81.421287]  ____sys_sendmsg+0x35d/0x3a0

[   81.423053]  ___sys_sendmsg+0xa2/0x100

[   81.424649]  __sys_sendmsg+0x70/0xf0

[   81.426177]  __x64_sys_sendmsg+0x47/0x60

[   81.427816]  do_syscall_64+0x39/0x90

[   81.429408]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[   81.431780]

[   81.432555] write to 0xffff888007eb102c of 4 bytes by task 14646 on cpu 0:

[   81.435419]  ns_capable+0x6b/0x90

[   81.437234]  netlink_net_capable+0x97/0xb0

[   81.438962]  rtnetlink_rcv_msg+0xb9/0x570

[   81.440628]  netlink_rcv_skb+0x8b/0x190

[   81.442346]  rtnetlink_rcv+0x1d/0x30

[   81.443867]  netlink_unicast+0x354/0x4c0

[   81.445564]  netlink_sendmsg+0x4de/0x6e0

[   81.447177]  sock_sendmsg+0xb5/0xc0

[   81.448764]  ____sys_sendmsg+0x35d/0x3a0

[   81.450397]  ___sys_sendmsg+0xa2/0x100

[   81.451987]  __sys_sendmsg+0x70/0xf0

[   81.453581]  __x64_sys_sendmsg+0x47/0x60

[   81.455192]  do_syscall_64+0x39/0x90

[   81.456589]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[   81.458513]

[   81.459439] Reported by Kernel Concurrency Sanitizer on:

[   81.461688] CPU: 0 PID: 14646 Comm: bpf_2nd_primiti Not tainted 6.0.0 #3

[   81.464555] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.154

[   81.468016] =================================================================

6. 

[   95.398721] =================================================================

[   95.400698] BUG: KCSAN: data-race in copy_process / rcu_core

[   95.401994]

[   95.402388] read to 0xffff888007fce02c of 4 bytes by interrupt on cpu 3:

[   95.404282]  rcu_core+0x8ab/0xfd0

[   95.405189]  rcu_core_si+0x12/0x20

[   95.406001]  __do_softirq+0xe4/0x2de

[   95.406806]  __irq_exit_rcu+0xba/0x100

[   95.407643]  sysvec_apic_timer_interrupt+0x93/0xc0

[   95.408801]  asm_sysvec_apic_timer_interrupt+0x16/0x20

[   95.410130]  delay_tsc+0x45/0xb0

[   95.411075]  kcsan_setup_watchpoint+0x1fd/0x4e0

[   95.412200]  copy_process+0x8fc/0x2e40

[   95.413309]  kernel_clone+0xba/0x570

[   95.414108]  __do_sys_clone3+0x119/0x160

[   95.415026]  __x64_sys_clone3+0x32/0x50

[   95.416008]  do_syscall_64+0x39/0x90

[   95.417083]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[   95.419225]

[   95.419557] write to 0xffff888007fce02c of 4 bytes by task 2954 on cpu 3:

[   95.420800]  copy_process+0x8fc/0x2e40

[   95.421535]  kernel_clone+0xba/0x570

[   95.422228]  __do_sys_clone3+0x119/0x160

[   95.422993]  __x64_sys_clone3+0x32/0x50

[   95.423755]  do_syscall_64+0x39/0x90

[   95.424462]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[   95.425468]

[   95.425886] Reported by Kernel Concurrency Sanitizer on:

[   95.426991] CPU: 3 PID: 2954 Comm: bpf_2nd_primiti Not tainted 6.0.0 #3

[   95.432337] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.154

[   95.434276] =================================================================

7. 

[   98.062007] =================================================================

[   98.063514] BUG: KCSAN: data-race in lru_add_fn / page_remove_rmap

[   98.064681]

[   98.065001] read-write (marked) to 0xffffea0000205640 of 8 bytes by task 322:

[   98.066600]  lru_add_fn+0x3a/0x470

[   98.067279]  folio_batch_move_lru+0x10f/0x1a0

[   98.068085]  folio_batch_add_and_move+0x7c/0xc0

[   98.068922]  folio_add_lru+0x6d/0xb0

[   98.069616]  lru_cache_add+0x29/0xa0

[   98.070280]  lru_cache_add_inactive_or_unevictable+0x34/0x60

[   98.071305]  __handle_mm_fault+0xccb/0x16c0

[   98.072082]  handle_mm_fault+0xb2/0x270

[   98.072828]  do_user_addr_fault+0x1c3/0x660

[   98.073696]  exc_page_fault+0x62/0x150

[   98.074381]  asm_exc_page_fault+0x22/0x30

[   98.075119]

[   98.075621] read to 0xffffea0000205640 of 8 bytes by task 32219 on cpu 0:

[   98.077026]  page_remove_rmap+0xf7/0x220

[   98.077802]  unmap_page_range+0x7b1/0x1640

[   98.078540]  unmap_single_vma+0xc4/0x1a0

[   98.079266]  zap_page_range+0x1e5/0x2b0

[   98.079989]  do_madvise.part.0+0x4da/0x1290

[   98.080780]  __x64_sys_madvise+0x89/0xb0

[   98.081497]  do_syscall_64+0x39/0x90

[   98.082153]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[   98.083061]

[   98.083369] value changed: 0x01000000000a0004 -> 0x01000000000a0014

[   98.084506]

[   98.084836] Reported by Kernel Concurrency Sanitizer on:

[   98.085771] CPU: 0 PID: 32219 Comm: bpf_2nd_primiti Not tainted 6.0.0 #3

[   98.086997] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.154

[   98.088444] =================================================================

8. 

[   99.218596] =================================================================

[   99.222670] BUG: KCSAN: data-race in __alloc_file / __alloc_file

[   99.226015]

[   99.226883] write to 0xffff88800432c9a0 of 4 bytes by task 959 on cpu 1:

[   99.231190]  __alloc_file+0x53/0x170

[   99.233978]  alloc_empty_file+0x5e/0x110

[   99.236300]  alloc_file+0x47/0x2f0

[   99.238191]  alloc_file_pseudo+0x108/0x180

[   99.240364]  sock_alloc_file+0x5b/0x110

[   99.243239]  __sys_socket+0xe7/0x140

[   99.245755]  __x64_sys_socket+0x41/0x60

[   99.247911]  do_syscall_64+0x39/0x90

[   99.249854]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[   99.252673]

[   99.253515] write to 0xffff88800432c9a0 of 4 bytes by task 958 on cpu 2:

[   99.257567]  __alloc_file+0x53/0x170

[   99.259482]  alloc_empty_file+0x5e/0x110

[   99.261562]  alloc_file+0x47/0x2f0

[   99.263596]  alloc_file_pseudo+0x108/0x180

[   99.266068]  sock_alloc_file+0x5b/0x110

[   99.268141]  __sys_socket+0xe7/0x140

[   99.270213]  __x64_sys_socket+0x41/0x60

[   99.272325]  do_syscall_64+0x39/0x90

[   99.274830]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[   99.277494]

[   99.278335] Reported by Kernel Concurrency Sanitizer on:

[   99.281186] CPU: 2 PID: 958 Comm: bpf_2nd_primiti Not tainted 6.0.0 #3

[   99.285848] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.154

[   99.290427] =================================================================

(1). [ 108.622561] bpf_2nd_primiti (10929) used greatest stack depth: 11808 bytes lt
9. 

[  120.079581] =================================================================

[  120.082070] BUG: KCSAN: data-race in tick_sched_do_timer / tick_sched_do_timr

[  120.084535]

[  120.085093] write to 0xffffffff83491930 of 4 bytes by interrupt on cpu 1:

[  120.087420]  tick_sched_do_timer+0x122/0x140

[  120.088679]  tick_sched_timer+0x39/0xc0

[  120.089758]  __hrtimer_run_queues+0x2c5/0x500

[  120.091238]  hrtimer_interrupt+0x1e0/0x3d0

[  120.092747]  __sysvec_apic_timer_interrupt+0xb9/0x220

[  120.094528]  sysvec_apic_timer_interrupt+0x8e/0xc0

[  120.095966]  asm_sysvec_apic_timer_interrupt+0x16/0x20

[  120.097496]  __tsan_read8+0x29/0x1b0

[  120.098584]  do_exit+0xd49/0x12b0

[  120.099506]  __x64_sys_exit+0x29/0x30

[  120.100585]  do_syscall_64+0x39/0x90

[  120.101601]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[  120.103050]

[  120.103534] read to 0xffffffff83491930 of 4 bytes by interrupt on cpu 2:

[  120.105677]  tick_sched_do_timer+0x2b/0x140

[  120.106711]  tick_sched_timer+0x39/0xc0

[  120.107886]  __hrtimer_run_queues+0x2c5/0x500

[  120.109436]  hrtimer_interrupt+0x1e0/0x3d0

[  120.110670]  __sysvec_apic_timer_interrupt+0xb9/0x220

[  120.112139]  sysvec_apic_timer_interrupt+0x3b/0xc0

[  120.113902]  asm_sysvec_apic_timer_interrupt+0x16/0x20

[  120.115452]

[  120.115978] value changed: 0xffffffff -> 0x00000001

[  120.117427]

[  120.117870] Reported by Kernel Concurrency Sanitizer on:

[  120.119590] CPU: 2 PID: 22629 Comm: bpf_2nd_primiti Not tainted 6.0.0 #3

[  120.121556] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.154

[  120.124188] =================================================================

10. 

[  125.605595] =================================================================

[  125.608483] BUG: KCSAN: data-race in lru_add_fn / unmap_page_range

[  125.610797]

[  125.611373] read (marked) to 0xffffea00001e15c8 of 8 bytes by task 28550 on :

[  125.614149]  unmap_page_range+0x695/0x1640

[  125.616340]  unmap_single_vma+0xc4/0x1a0

[  125.617107]  zap_page_range+0x1e5/0x2b0

[  125.618023]  do_madvise.part.0+0x4da/0x1290

[  125.619402]  __x64_sys_madvise+0x89/0xb0

[  125.620861]  do_syscall_64+0x39/0x90

[  125.622430]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[  125.624446]

[  125.625064] write to 0xffffea00001e15c8 of 8 bytes by task 2954 on cpu 0:

[  125.627540]  lru_add_fn+0x2cf/0x470

[  125.628882]  folio_batch_move_lru+0x10f/0x1a0

[  125.630778]  folio_batch_add_and_move+0x7c/0xc0

[  125.632444]  folio_add_lru+0x6d/0xb0

[  125.633783]  lru_cache_add+0x29/0xa0

[  125.635239]  lru_cache_add_inactive_or_unevictable+0x34/0x60

[  125.637332]  __handle_mm_fault+0xccb/0x16c0

[  125.638939]  handle_mm_fault+0xb2/0x270

[  125.640391]  do_user_addr_fault+0x1c3/0x660

[  125.642041]  exc_page_fault+0x62/0x150

[  125.643431]  asm_exc_page_fault+0x22/0x30

[  125.644915]

[  125.645492] Reported by Kernel Concurrency Sanitizer on:

[  125.647505] CPU: 0 PID: 2954 Comm: bpf_2nd_primiti Not tainted 6.0.0 #3

[  125.650844] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.154

[  125.653983] =================================================================

11. 

[  147.713395] ==================================================================

[  147.716494] BUG: KCSAN: data-race in __tcf_qdisc_find.part.0 / qdisc_offload_dump_helper

[  147.720038]

[  147.720768] read to 0xffff888004315c10 of 4 bytes by task 17354 on cpu 2:

[  147.723666]  __tcf_qdisc_find.part.0+0xb8/0x350

[  147.725985]  tc_new_tfilter+0xea/0x10c0

[  147.727868]  rtnetlink_rcv_msg+0x471/0x570

[  147.729664]  netlink_rcv_skb+0x8b/0x190

[  147.731172]  rtnetlink_rcv+0x1d/0x30

[  147.733043]  netlink_unicast+0x354/0x4c0

[  147.733790]  netlink_sendmsg+0x4de/0x6e0

[  147.734500]  sock_sendmsg+0xb5/0xc0

[  147.735129]  ____sys_sendmsg+0x35d/0x3a0

[  147.735836]  ___sys_sendmsg+0xa2/0x100

[  147.736571]  __sys_sendmsg+0x70/0xf0

[  147.737224]  __x64_sys_sendmsg+0x47/0x60

[  147.737938]  do_syscall_64+0x39/0x90

[  147.738567]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[  147.740245]

[  147.740951] write to 0xffff888004315c10 of 4 bytes by task 17355 on cpu 1:

[  147.742836]  qdisc_offload_dump_helper+0x4e/0xf0

[  147.744376]  fifo_dump+0xab/0x130

[  147.745730]  tc_fill_qdisc+0x297/0x6f0

[  147.747216]  qdisc_notify.isra.0+0x100/0x160

[  147.748783]  qdisc_graft+0x7f8/0x920

[  147.750119]  tc_modify_qdisc+0x652/0xc90

[  147.751465]  rtnetlink_rcv_msg+0x1dd/0x570

[  147.752937]  netlink_rcv_skb+0x8b/0x190

[  147.754113]  rtnetlink_rcv+0x1d/0x30

[  147.755080]  netlink_unicast+0x354/0x4c0

[  147.756237]  netlink_sendmsg+0x4de/0x6e0

[  147.758479]  sock_sendmsg+0xb5/0xc0

[  147.759448]  ____sys_sendmsg+0x35d/0x3a0

[  147.760635]  ___sys_sendmsg+0xa2/0x100

[  147.762674]  __sys_sendmsg+0x70/0xf0

[  147.763954]  __x64_sys_sendmsg+0x47/0x60

[  147.765408]  do_syscall_64+0x39/0x90

[  147.766857]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[  147.768695]

[  147.769812] Reported by Kernel Concurrency Sanitizer on:

[  147.770852] CPU: 1 PID: 17355 Comm: bpf_2nd_primiti Not tainted 6.0.0 #3

[  147.771939] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014

[  147.773360] ==================================================================

(2). [ 147.780071] bpf_2nd_primiti (17355) used greatest stack depth: 11368 bytes left
12. 

[  149.674931] ==================================================================

[  149.678033] BUG: KCSAN: data-race in netlink_release / rht_deferred_worker

[  149.681240]

[  149.681886] read-write (marked) to 0xffff888004a62c50 of 8 bytes by task 262 on cpu 3:

[  149.685239]  rht_deferred_worker+0x212/0x790

[  149.687572]  process_one_work+0x483/0x800

[  149.689278]  worker_thread+0x2f6/0x7d0

[  149.690820]  kthread+0x183/0x1b0

[  149.692180]  ret_from_fork+0x22/0x30

[  149.693716]

[  149.694327] read to 0xffff888004a62c50 of 8 bytes by task 19176 on cpu 1:

[  149.697168]  netlink_release+0x15a/0xb10

[  149.701587]  __sock_release+0x77/0x140

[  149.704146]  sock_close+0x1a/0x30

[  149.705908]  __fput+0x109/0x420

[  149.707372]  ____fput+0x16/0x30

[  149.708680]  task_work_run+0x9f/0xe0

[  149.710136]  exit_to_user_mode_prepare+0x197/0x1a0

[  149.712031]  syscall_exit_to_user_mode+0x16/0x30

[  149.713986]  do_syscall_64+0x46/0x90

[  149.715534]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[  149.717958]

[  149.719023] Reported by Kernel Concurrency Sanitizer on:

[  149.721193] CPU: 1 PID: 19176 Comm: bpf_2nd_primiti Not tainted 6.0.0 #3

[  149.723847] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014

[  149.727463] ==================================================================

13. 

[  155.579884] ==================================================================

[  155.581454] BUG: KCSAN: data-race in qdisc_offload_dump_helper / qdisc_put_unlocked

[  155.582884]

[  155.583196] write to 0xffff888005986c10 of 4 bytes by task 25499 on cpu 3:

[  155.584648]  qdisc_offload_dump_helper+0x4e/0xf0

[  155.585556]  fifo_dump+0xab/0x130

[  155.586177]  tc_fill_qdisc+0x297/0x6f0

[  155.586960]  qdisc_notify.isra.0+0x100/0x160

[  155.587880]  qdisc_graft+0x7f8/0x920

[  155.588620]  tc_modify_qdisc+0x652/0xc90

[  155.589342]  rtnetlink_rcv_msg+0x1dd/0x570

[  155.590106]  netlink_rcv_skb+0x8b/0x190

[  155.590811]  rtnetlink_rcv+0x1d/0x30

[  155.592288]  netlink_unicast+0x354/0x4c0

[  155.593499]  netlink_sendmsg+0x4de/0x6e0

[  155.594720]  sock_sendmsg+0xb5/0xc0

[  155.595816]  ____sys_sendmsg+0x35d/0x3a0

[  155.597123]  ___sys_sendmsg+0xa2/0x100

[  155.598534]  __sys_sendmsg+0x70/0xf0

[  155.599989]  __x64_sys_sendmsg+0x47/0x60

[  155.601619]  do_syscall_64+0x39/0x90

[  155.603030]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[  155.604886]

[  155.605478] read to 0xffff888005986c10 of 4 bytes by task 25500 on cpu 0:

[  155.607984]  qdisc_put_unlocked+0x17/0x50

[  155.610416]  __tcf_qdisc_find.part.0+0x2d3/0x350

[  155.612116]  tc_new_tfilter+0xea/0x10c0

[  155.613732]  rtnetlink_rcv_msg+0x471/0x570

[  155.616094]  netlink_rcv_skb+0x8b/0x190

[  155.617687]  rtnetlink_rcv+0x1d/0x30

[  155.618280]  netlink_unicast+0x354/0x4c0

[  155.618916]  netlink_sendmsg+0x4de/0x6e0

[  155.620382]  sock_sendmsg+0xb5/0xc0

[  155.621638]  ____sys_sendmsg+0x35d/0x3a0

[  155.623118]  ___sys_sendmsg+0xa2/0x100

[  155.624676]  __sys_sendmsg+0x70/0xf0

[  155.625960]  __x64_sys_sendmsg+0x47/0x60

[  155.627377]  do_syscall_64+0x39/0x90

[  155.628919]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[  155.630687]

[  155.631208] Reported by Kernel Concurrency Sanitizer on:

[  155.633172] CPU: 0 PID: 25500 Comm: bpf_2nd_primiti Not tainted 6.0.0 #3

[  155.636171] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014

[  155.642960] ==================================================================

14. 

[  156.855874] ==================================================================

[  156.857671] BUG: KCSAN: data-race in delayacct_add_tsk+0xfa/0x550

[  156.859129]

[  156.859619] race at unknown origin, with read to 0xffff888008c470c8 of 8 bytes by task 26726 on cpu 1:

[  156.862975]  delayacct_add_tsk+0xfa/0x550

[  156.864862]  taskstats_exit+0xf2/0x5d0

[  156.866606]  do_exit+0x495/0x12b0

[  156.868011]  __x64_sys_exit+0x29/0x30

[  156.869609]  do_syscall_64+0x39/0x90

[  156.871147]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

[  156.873310]

[  156.873960] value changed: 0x0000000001eab0ec -> 0x0000000001edb253

[  156.877070]

[  156.877750] Reported by Kernel Concurrency Sanitizer on:

[  156.879941] CPU: 1 PID: 26726 Comm: bpf_2nd_primiti Not tainted 6.0.0 #3

[  156.882520] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014

[  156.885969] ==================================================================

---

발견된 KCSAN data race 개수 14개

BUG: KCSAN: data-race in tick_sched_do_timer
BUG: KCSAN: data-race in netlink_insert / netlink_insert
BUG: KCSAN: data-race in __alloc_file / copy_creds
BUG: KCSAN: data-race in __hrtimer_run_queues / hrtimer_active
BUG: KCSAN: data-race in ns_capable / rcu_core
BUG: KCSAN: data-race in copy_process / rcu_core
BUG: KCSAN: data-race in lru_add_fn / page_remove_rmap
BUG: KCSAN: data-race in __alloc_file / __alloc_file
BUG: KCSAN: data-race in tick_sched_do_timer / tick_sched_do_timr
BUG: KCSAN: data-race in lru_add_fn / unmap_page_range
BUG: KCSAN: data-race in __tcf_qdisc_find.part.0 / qdisc_offload_dump_helper
BUG: KCSAN: data-race in netlink_release / rht_deferred_worker
BUG: KCSAN: data-race in qdisc_offload_dump_helper / qdisc_put_unlocked
BUG: KCSAN: data-race in delayacct_add_tsk+0xfa/0x550
