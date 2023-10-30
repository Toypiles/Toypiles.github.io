# 윈도우에 리눅스를 설치하는 과정과, 리눅스 커널 위에 qemu 설치를 진행해서 boot 하는 방법

## 순서
1. 환경설정
2. 윈도우에 리눅스 설치과정
3. qemu 설치과정
4. 커널 이미지 빌드와 쉘 파일 작성 후 linux 위에 linux 실행
5. gdb를 사용해 linux 위의 linux와 연결
6. 이번 과제에 사용된 파일과 용어 간략히 정리
7. 추후 진행할 것

## 1. 환경 설정 (윈도우 10기준)
bios의 vt-d를 켜주고
hyper-v를 꺼준다.

## 2. 윈도우에 리눅스 설치과정
(1). virtualbox를 통해 ubuntu 22.04를 다운받음
https://www.virtualbox.org/wiki/Linux_Downloads
(2). oracle vm virtualbox extension pack를 통해 확장팩을 다운받음
https://www.virtualbox.org/wiki/Downloads
VirtualBox 7.0.12 Software Developer Kit (SDK)
​All platforms
(3). 진행방법
1. 다운받은 linux file (ubuntu-22.04.3-desktop-amd64.iso)를 삽입
2. cpu개수 4개, Nested VT-x/AMD-V on, memory 4096MB, ext 40GB, video memory 48GB, 가상화 on -> start

## 3. qemu 설치과정
qemu version : v6.2.0, linux version : v6.0.0
$ sudo apt install libvirt-daemon
$ sudo apt install -y qemu qemu-kvm libvirt-daemon libvirt-clients bridge-utils virt-manager
$ sudo systemctl enable libvirtd
$ sudo systemctl start libvirtd
$ sudo apt install git
$ git clone https://gitlab.com/qemu-project/qemu.git
$ cd qemu
$ git submodule init
$ git submodule update --recursive
$ python -m ensurepip --upgrade
$ sudo apt-get install python3-sphinx
$ pip install sphinx-rtd-theme
$ sudo apt-get install ninja-build
$ sudo apt-get install pkg-config
$ sudo apt install flex
$ sudo apt-get install bison
$ ./configure
$ make

## 4. 커널 이미지 빌드와 쉘 파일 작성 후 linux 위에 linux 실행
* 1. 커널 이미지 빌드
$ sudo apt-get install build-essential libncurses5 libncurses5-dev bin86 kernelpackage libssl-dev bison flex libelf-dev
$ wget https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-6.0.tar.gz
$ tar -xzvf linux-6.0.tar.gz
$ cd linux-6.0
$ make defconfig
$ make menuconfig
kernel hacking -> Generic Kernel Debbuging Instruments -> KGDB: kernel deugger : on
-> KCSAN : dynamic data race
detector : on
$ vi .config # CONFIG_KCSAN_EARLY_ENABLE=N (따로 별도의 vi 이용법을 검색해서 해당 위치의 파일을 수정하였다.)
$ make
linux 커널 이미지는 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git를 통해 v6.0.0을 build 하였다.
이 결과로 linux-6.0에 kernel image인 bzimage가 생성된 것을 확일할 수 있었다.
rootfs.img 파일로 boot를 진행시키려고 했지만 file공간과 disk 공간을 할당하는 방법을 몰라서
이 모든 것이 포함된 stretch.img를 실행하였다.
$ wget https://storage.googleapis.com/syzkaller/stretch.img
Poc file이 linux 내부에 있어야 해서 stretch.img에 넣어서 진행하였다.
$ sudo mkdir /mnt
$ sudo mount -o loop stretch.img /mnt
$ sudo cp -r /home/han/bpf_2nd_primitive_PoC_230924_fin /mnt
$ sudo unmount /mnt

* 2. 쉘 파일 작성 후 linux 위에 linux 실행
쉘 파일 이름을 root.sh로 지정하고 사용함.
$ vi root.sh
qemu-system-x86_64 \
  -kernel /home/han/linux-6.0/arch/x86/boot/bzImage \
  -nographic \
  -smp 4 \
  -append "console=ttyS0 nokaslr root=/dev/sda rdinit=/bin/sh kgdboc=ttyS0" \
  -drive file=/home/han/stretch.img,format=raw \
  -m 2G \
  -enable-kvm \
  -cpu host \
  -s
$ chmod 755 root.sh
$ sudo ./root.sh을 진행하면 linux위에 리눅스가 build 된다.

## 5. gdb를 사용해 linux 위의 linux와 연결
home 파일에서 linux Terminal을 실행시킨 후에 명령어로 gdb vmlinux를 진행함
target remote:1234를 통해 attach를 진행하였고 gdb와 linux를 attach 시키는데에 성공함.
gdb가 사용된 이유는 실행 파일 분석을 위해서이다.

## 6. 이번 과제에 사용된 파일과 용어 간략히 정리
(1). 드라이브 파일 : bpf_2nd_primitive_PoC_230924_fin, bzImage, System.map, vmlinux
(2). 주요 키워드 :
1. Improper synchronization
2. Improper locking
3. Data race / Race condition
4. Use-After-Free
5. KCSAN
6. KASAN
(3). linux 위에 linux를 띄우기 위해 사용된 git: 
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
(4). 간략한 용어 정리
qemu: rom에 저장된 ASUS처럼 부팅시켜주는 역할을 함 (emulation qemu)
rootfs에는 root에 대한 파일 시스템이 저장되있는 것
stretch.img안에도 똑같음
BzImage : 리눅스 커널의 핵심
vmlinux : 리눅스 커널의 구성요소 파일
gdb:  실행파일 관찰도구
.sh : 텍스트를 입력할 수 있는 쉘 파일
img  파일 안에 pocfile → HDD역할(보조기억장치)

## 7. 추후 진행할 것
ida 사용 : 일단 IDA는 디스어셈블러의 일종으로, 디스어셈블러는 바이너리 파일을 역으로 어셈블리어로 재구성해주는 툴
IDA는 바이너리 >> 어셈블리어 >> 프로그래밍 언어 까지 변환시켜 준다.
ida 설치 후 bpf_2nd_primitive_PoC_230924_fin 파일을 입력후에 ida에 들어간다.
옆에 나와 있는 아무 목록에 들어가서 우클릭 후 main을 검색 한 후에 main 바탕으로 gdb와 비교 분석을 할 것이다.