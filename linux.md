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
img  파일 안에 pocfile → HDD역할(보조기억장치) <br> <br>

## 7. 추후 진행할 것
* ida 사용 : 일단 IDA는 디스어셈블러의 일종으로, 디스어셈블러는 바이너리 파일을 역으로 어셈블리어로 재구성해주는 툴  <br>
  IDA는 바이너리 >> 어셈블리어 >> 프로그래밍 언어 까지 변환시켜 준다. <br>
  ida 설치 후 bpf_2nd_primitive_PoC_230924_fin 파일을 입력후에 ida에 들어간다. <br>
  옆에 나와 있는 아무 목록에 들어가서 우클릭 후 main을 검색 한 후에 main 바탕으로 gdb와 비교 분석을 할 것이다. <br>
