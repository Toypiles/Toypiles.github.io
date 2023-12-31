# Toypiles.github.io
Debug 
<ol>
<p><li>리눅스 명령어 -vm</li></p>

pwd : 현재 작업중인 디렉토리 정보 출력

cd : 경로이동 

- 절대경로

절대경로로 경로를 기술할 때에는 항상 맨 앞에 최상위 디렉토리 (/)가 붙는다는 것을 명심하자

- 상대경로

ls : 디렉토리 목록 확인

cp : 파일 혹은 디렉토리를 복사 (단 복사할 때는 -r옵션을 주어야함)

mv : 파일 혹은 디렉토리 이동 (실제 원하는 위치로 이동할때도 사용하지만, 이름을 변경하는 용도로도 사용한다.)

동기화  <br>  <br>

<p><li>용어 및 정리</li></p>  <br>  

커널 은 프로세스와 가상 메모리를 관리하기 위해 전체 시스템 권한으로 실행되는 OS의 핵심 프로그램

프로세스끼리는 서로 독립되어 메모리를 관리한다.(기본적으로는 맞지만 조금 더 효율적인 처리를 위해 공유 메모리, 메세지 등(IPC)의 기능이 있다.)

- 같은 프로세스의 스레드는 stack과 register을 제외하면 서로 메모리를 공유한다.

synchronization(동기화) : 다양한 프로세스와 스레드가 서로 충돌하거나 예상치 못한 값 변경을 막기위해 서로의 정보를 공유하는 것

프로세스 : 실행되고있는 프로그램

프로세스 상태 : new, ready, running, waiting, terminated, and suspended

new : 프로세스가 만들어지는 상태(아직 만들어지지 않음)

ready : 프로세스가 할당되기를 기다리는 상태

running : 실행되는 중

Blocked or Wait : 어떤 event가 발생하는 것을 대기하는 상태

Terminated or Completed : 프로세스가 종료되고 PCB가 삭제

Suspend Ready : 인터럽트등이 발생했을때 스케줄러에 의해 외부 저장소에 배치된 상태

Suspend wait or suspend blocked :  I/O 작업을 수행 중이며 해당 I/O 작업이 완료될 때까지 기다리는 상태

- PCB(Process Control Block) : 프로세스를 관리할때 필요한 정보가 담겨져있는 블록/ 프로세스의 생성과 소멸때 같이 생성,소멸 된다. / 이 안에 PID(프로세스 식별 번호), 프로세스 상태 등등이 있다.
- ps : 프로세스 확인 명령어 / cat /proc/<pid>/status : pcb정보 확인 명령어

critical section : 자원 공유의 문제가 발생하는 걸 방지하기 위해 하나의 프로세스나 스레드에 독점권을 보장해주는 영역이다.

동시성에 대한 4가지 전략(java긴 함)

- Confinement(제한) : 스레드간의 변수 공유 불가
    - 스레드는 stack이 서로 분리되어있고 변수는 stack에 저장되므로 서로 변수 공유는 불가하며 그로 인해 발생할 수 있는 동시성 가능성을 없앨수있다. / 전역 변수는 여기에 해당이 되지 않기 때문에 주의해야한다.
- Immutability(불변성) : 공유 데이터를 변경할수없게 만드는 것(ex. 상수)
- Threadsafe data type(항상 올바른 동작을 하며 추가적인 조정이 없는 데이터 타입) : 타입확인은 나중에 자바가면 확인하자
- Synchronization(동기화)
    - Deadlock:서로 하나의 리소스를 가지고 있으면서 다른 리소스를 원하는데 그게 상대방의 리소스인 상태(종속성의 순환)
        
        	해결방법
        
        1. lock ordering : 순서를 정하면 Deadlock 미발생
        2. coarse-grained locking : 거친 잠금을 한다. / 하나의 큰 락으로 전체를 보호(성능적 저하)
- Context Switching : 한 프로세스를 저장하고 다른 프로세스를 로드하는 것
- Mode Switch : 프로세스가 유저에서 커널로 갈때 실행권한을 변경시켜주는 기능
- Process Switch : 프로세스가 종료되었을때 다른 프로세스로 변경되는 것(종료되어야함 중단이 아니라)
- CPU-Bound : CPU에 중점을 둔 프로세스(ex.계산 집약적인 작업, 데이터 처리, 알고리즘 실행 등)
- I/O-Bound : I/O에 중점을 둔 프로세스(ex.파일에서 데이터를 읽고 처리하는 작업, 웹 서버에서 클라이언트 요청)
- Scheduling : 프로세스를 조율하는 프로세스
- Scheduling Algorithms : 프로세스를 조율하는 프로세스를 규정하는 알고리즘
    1. First-come, first-served (FCFS) : 선착순 알고리즘
    2. Shortest Job First (SJF) : 버스트 시간(프로세스 실행 완료 시간)이 가장 짧은 프로세스를 택한다
    3. Round Robin (RR) : 각 프로세스에 고정된 시간을 제공/ 미완료시 제일 뒤로 이동
    4. Priority Scheduling : 우선순위를 할당하고 그 우선순위대로 진행
    5. Multilevel queue : 다중의 큐로 우선순위 배열 / 각 대기열은 자체 예약 알고리즘 사용
- process의 두가지 유형 : Independent process/Co-operating process
- Inter Process Communication (IPC) : process가 통신하는 매커니즘
    1. Shared Memory(공유 메모리) : 두 프로세스가 메모리 공유 영역을 만들어 사용하는 것
    2. Message passing(메시지 전달) : 커널을 통해 서로 메세지를 주고 받는 것
- spin lock : 프로세스나 스레드가 대기상대로 가지않고 사용가능해질때까지 계속 확인하는 것
    
    spin lock이 기간이 길어지게되면 오버헤드가 많아진다.
    
    TestAndSet 인자를 통해 진입여부를 확인하는데 이 인자는 CPU atomic 명령어다.
    
    - 실행 중간에 간섭받거나 중단되지 않음
    - 같은 메모리 영역에 대해 동시에 실행되지 않는다.
    
    위의 이유로 동시에 접근되는 문제는 걱정할 필요가 없다.
    
- synchronization services in kernel os 2가지
- Mutex : 하나의 프로세스만 허용하여 잠금 상태로 유지 / 다른 프로세스가 와도 대기 상태로 전환

```
우선순위 반전 문제 방지를 위해 우선순위 상속 매커니즘을 사용(하지만 완전히 예방은 불가)

Mutual Exclusion(상호 배제) : 하나의 스레드/프로세스가 사용중이면 다른건 접근 불가

```

- Semaphore : 이진은 Mutex와 실행은 같다 / 카운팅은 1개 이상 스레드 접근이 가능하다.
    
    우선순위 반전은 물론 있다.
    
- Difference Between Mutex and Semaphore
1. Mutex는 잠금 메커니즘에 따라 작동하지만 Semaphore는 신호 메커니즘을 사용한다.
2. Mutex는 소유하지만 Semaphore는 소유하지 않는다.
- r/w lock : r끼리는 동시성을 해치지 않아 그 부분까지 계산한 lock방식
- interleaving : 처리기가 하나여도 병렬적으로 처리해서 여러개가 동시에 실행되는 것처럼 보이게 하는 것
- overlapping : 처리기가 여러개여서 동시에 처리하는 것
- plain access 조건
    1. 두 메모리 접근이 메모리의 동일한 위치에 접근합니다.
    2. 두 메모리 접근 중 적어도 하나는 쓰기(write) 작업입니다.
- Race window : race condition이 발생한 시간
- memory wall : CPU의 속도가 데이터 버스의 속도보다 빨라 CPU의 자원이 낭비되는 현상
- memory barrier : CPU나 컴파일러에게 barrier 명령문 전 후의 메모리 연산을 순서에 맞게 실행하도록 강제하는 기능
- UAF(Use-after-free) : 프로그램 실행중 이미 free가 된 메모리 위치에 접근하려할때 발생하는 오류
    
    메모리는 free처리를 했는데 그걸 가리키는 포인터가 있어서 발생하는 문제
    
- data race : 같은 메모리 공간에 두개의 스레드가 동시 접근을 해 문제가 발생하는 것
- Sanitizer : 버퍼 오버플로, 부호 있는 정수 오버플로, 초기화되지 않은 메모리 읽기 등과 같은 컴퓨터 프로그램 버그를 감지하는 프로그래밍 도구
- instrumentation(계측) : 어떤 것을 모니터링하거나 조작하는 도구
- The Kernel Address Sanitizer (KASAN) :out-of-bounds와 use-after-free bugs를 찾기위해 설계된 dynamic memory safety error detector이다.
- KASAN 의 three modes
    1. Generic KASAN : ASAN(Address Sanitizer)과 유사하게 디버깅을 위한 모드이다.
    많은 CPU 아키텍처에서 지원하지만 상당한 성능과 메모리 오버헤드가 발생한다.
    all of slab, page_alloc, vmap, vmalloc, stack, and global memory을 지원
    2. Software Tag-Based KASAN : HWASan과 유사하게 디버깅 및 Dogfood 테스트에 모두 사용가능
        
        arm64에서만 지원되지만 중간 정도의 오버헤드로 실제 작업 부화가 있는 메모리 제한 장치 테스트 가능 / 모든 메모리 접근 앞에 유효성 검사를 삽입하는데 compile-time instrumentation를 이용하여 한다.
        때문에 compile-time instrumentation를 지원하는 버전에서 실시해야한다.
        slab, page_alloc, vmalloc, and stack memory을 지원
        
    3. Hardware Tag-Based KASAN : 현장 메모리 버그 감지기 또는 보안 완화로 사용하기 위한 모드
    MTE(Memory Tagged Extension)를 지원하는 arm64 CPU에서만 작동하지만 메모리와 성능 오버헤드가 낮아 프로덕션에서 사용가능 / memory tagging instructions을 지원하는 버전이 필요하다.
    slab, page_alloc, and non-executable vmalloc memory을 지워
- The Kernel Concurrency Sanitizer (KCSAN) : dynamic race detector이다
    - 주된 목적은 data races 감지이다.
- Improper synchronization(CWE-662) : 하나의 critical section에 두개의 스레드가 들어가 충돌되는 취약점
- Improper locking(CWE-667) : 제대로 locking이 되지 않아 발생하는 취약점
- vmlinux : Linux 커널의 이미지 파일로, 컴파일된 커널 코드와 데이터를 포함 / ELF형식 / 정적링크 / 디버깅용
- System.map : 커널을 컴파일 할 때마다 새로 생성되는 파일로 커널에 들어 있는 심벌에 대한 정보를 담고있음
- bzImage : 부트 로더가 부팅하는 데 사용되는 압축된 Linux 커널 이미지

  IOCTL(입출력 제어) 드라이버는 Windows 운영 체제에서 사용되는 중요한 시스템 드라이버 중 하나입니다. IOCTL 드라이버는 입출력 제어 코드(IOCTL)를 사용하여 하드웨어 디바이스와 통신합니다.

  이 드라이버는 주로 하드웨어 디바이스와 상호 작용하고 제어하는 데 사용되며, 사용자 모드 및 커널 모드 프로그램에서 이 드라이버에 액세스할 수 있습니다.

프로세스를 잘게 나눈것이 스레드다.

프로세스 안에 스레드는 독립이 되는 것이 아니다.

스레드 안에 있는 스택이나 힙은 독립이 되어 있는데 나머지는 연결 되어 있음.  <br>  <br>

ref

- [https://velog.io/@dodozee/OS-메모리-영역-코드-영역-데이터-영역-힙-영역-스택-영역-대해서feat.스레드](https://velog.io/@dodozee/OS-%EB%A9%94%EB%AA%A8%EB%A6%AC-%EC%98%81%EC%97%AD-%EC%BD%94%EB%93%9C-%EC%98%81%EC%97%AD-%EB%8D%B0%EC%9D%B4%ED%84%B0-%EC%98%81%EC%97%AD-%ED%9E%99-%EC%98%81%EC%97%AD-%EC%8A%A4%ED%83%9D-%EC%98%81%EC%97%AD-%EB%8C%80%ED%95%B4%EC%84%9Cfeat.%EC%8A%A4%EB%A0%88%EB%93%9C)
- https://web.mit.edu/6.005/www/fa15/classes/20-thread-safety/#strategy_1_confinement
- https://web.mit.edu/6.005/www/fa15/classes/23-locks/
- https://docs.kernel.org/dev-tools/kasan.html
-https://blog.k3170makan.com/2020/11/linux-kernel-exploitation-0x0-debugging.html
-https://vccolombo.github.io/cybersecurity/linux-kernel-qemu-setup/
-https://dev.to/alexeyden/quick-qemu-setup-for-linux-kernel-module-debugging-2nde
-https://jeongzero.oopy.io/73084e52-54fa-43e2-986b-072ee2a4f80d
 <br> <br>

<p><li>qemu를 진행할때의 방법과 만날 수 있는 문제점들</li></p>  <br>


https://www.makeuseof.com/how-to-install-qemu-ubuntu-set-up-virtual-machine/

allz@allz-VirtualBox:~$ sudo systemctl enable libvirtd

Failed to enable unit: Unit file libvirtd.service does not exist.

allz@allz-VirtualBox:~$ sudo systemctl start libvirtd

Failed to start libvirtd.service: Unit libvirtd.service not found.

문제

해결 https://unix.stackexchange.com/questions/609241/creating-vms-using-kvm-error-unit-libvirtd-service-could-not-be-found

allz@allz-VirtualBox:~/qemu$ ./configure

Using './build' as the directory for build output

WARNING: unrecognized host CPU, proceeding with 'uname -m' output 'x86_64'

python determined to be '/usr/bin/python3'

python version: Python 3.10.12

- ** Ouch! ***

Python's ensurepip module is not found.

It's normally part of the Python standard library, maybe your distribution packages it separately?

Either install ensurepip, or alleviate the need for it in the first place by installing pip and setuptools for '/usr/bin/python3'.

(Hint: Debian puts ensurepip in its python3-venv package.)

ERROR: python venv creation failed

문제

해결 : [https://ioflood.com/blog/python-install-pip/#:~:text=The simplest way to install,for installing and upgrading pip](https://ioflood.com/blog/python-install-pip/#:~:text=The%20simplest%20way%20to%20install,for%20installing%20and%20upgrading%20pip).

'sphinx==5.3.0' not found:

• Python package 'sphinx' was not found nor installed.

• mkvenv was configured to operate offline and did not check PyPI.

Sphinx not found/usable, disabling docs.

ERROR: Cannot find Ninja
문제

해결 : https://www.sphinx-doc.org/en/master/usage/installation.html

Using './build' as the directory for build output

python determined to be '/usr/bin/python3'

python version: Python 3.10.12

mkvenv: Creating non-isolated virtual environment at 'pyvenv'

mkvenv: checking for tomli>=1.2.0

mkvenv: installing tomli>=1.2.0

mkvenv: checking for meson>=0.63.0

mkvenv: installing meson==0.63.3

mkvenv: checking for sphinx>=1.6

mkvenv: checking for sphinx_rtd_theme>=0.5

'sphinx_rtd_theme==1.1.1' not found:

• Python package 'sphinx_rtd_theme' was not found nor installed.

• mkvenv was configured to operate offline and did not check PyPI.

Sphinx not found/usable, disabling docs.

ERROR: Cannot find Ninja

문제

해결 : https://pypi.org/project/sphinx-rtd-theme/

Using './build' as the directory for build output

python determined to be '/usr/bin/python3'

python version: Python 3.10.12

mkvenv: Creating non-isolated virtual environment at 'pyvenv'

mkvenv: checking for tomli>=1.2.0

mkvenv: installing tomli>=1.2.0

mkvenv: checking for meson>=0.63.0
mkvenv: installing meson==0.63.3
mkvenv: checking for sphinx>=1.6
mkvenv: checking for sphinx_rtd_theme>=0.5

ERROR: Cannot find Ninja
문제

해결 : https://zoomadmin.com/HowToInstall/UbuntuPackage/ninja-build

allz@allz-VirtualBox:~/qemu$ ./configure

Using './build' as the directory for build output

python determined to be '/usr/bin/python3'

python version: Python 3.10.12

mkvenv: Creating non-isolated virtual environment at 'pyvenv'

mkvenv: checking for tomli>=1.2.0

mkvenv: installing tomli>=1.2.0

mkvenv: checking for meson>=0.63.0

mkvenv: installing meson==0.63.3

mkvenv: checking for sphinx>=1.6

mkvenv: checking for sphinx_rtd_theme>=0.5

The Meson build system

Version: 0.63.3

Source dir: /home/allz/qemu

Build dir: /home/allz/qemu/build

Build type: native build

Project name: qemu

Project version: 8.1.50

C compiler for the host machine: cc -m64 -mcx16 (gcc 11.4.0 "cc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0")

C linker for the host machine: cc -m64 -mcx16 ld.bfd 2.38

Host machine cpu family: x86_64

Host machine cpu: x86_64

Program scripts/symlink-install-tree.py found: YES (/home/allz/qemu/build/pyvenv/bin/python3 /home/allz/qemu/scripts/symlink-install-tree.py)

Program sh found: YES (/usr/bin/sh)

Program python3 found: YES (/home/allz/qemu/build/pyvenv/bin/python3)

Program bzip2 found: YES (/usr/bin/bzip2)

Program iasl found: NO

Compiler for C supports link arguments -Wl,-z,relro: YES

Compiler for C supports link arguments -Wl,-z,now: YES

Compiler for C supports link arguments -Wl,--warn-common: YES

Compiler for C supports arguments -Wundef: YES

Compiler for C supports arguments -Wwrite-strings: YES

Compiler for C supports arguments -Wmissing-prototypes: YES

Compiler for C supports arguments -Wstrict-prototypes: YES

Compiler for C supports arguments -Wredundant-decls: YES

Compiler for C supports arguments -Wold-style-declaration: YES

Compiler for C supports arguments -Wold-style-definition: YES

Compiler for C supports arguments -Wtype-limits: YES

Compiler for C supports arguments -Wformat-security: YES

Compiler for C supports arguments -Wformat-y2k: YES

Compiler for C supports arguments -Winit-self: YES

Compiler for C supports arguments -Wignored-qualifiers: YES

Compiler for C supports arguments -Wempty-body: YES

Compiler for C supports arguments -Wnested-externs: YES

Compiler for C supports arguments -Wendif-labels: YES

Compiler for C supports arguments -Wexpansion-to-defined: YES

Compiler for C supports arguments -Wimplicit-fallthrough=2: YES

Compiler for C supports arguments -Wmissing-format-attribute: YES

Compiler for C supports arguments -Wno-initializer-overrides: NO

Compiler for C supports arguments -Wno-missing-include-dirs: YES

Compiler for C supports arguments -Wno-shift-negative-value: YES

Compiler for C supports arguments -Wno-string-plus-int: NO

Compiler for C supports arguments -Wno-typedef-redefinition: NO

Compiler for C supports arguments -Wno-tautological-type-limit-compare: NO

Compiler for C supports arguments -Wno-psabi: YES

Compiler for C supports arguments -Wno-gnu-variable-sized-type-not-at-end: NO

Compiler for C supports arguments -Wthread-safety: NO

Program cgcc found: NO

Library m found: YES

Run-time dependency threads found: YES

Library util found: YES

Run-time dependency appleframeworks found: NO (tried framework)

Did not find pkg-config by name 'pkg-config'

Found Pkg-config: NO

Run-time dependency glib-2.0 found: NO

../meson.build:721:0: ERROR: Pkg-config binary for machine 1 not found. Giving up.

A full log can be found at /home/allz/qemu/build/meson-logs/meson-log.txt

ERROR: meson setup failed
문제

해결 :  sudo apt-get install pkg-config

Run-time dependency glib-2.0 found: NO (tried pkgconfig)

../meson.build:721:0: ERROR: Dependency "glib-2.0" not found, tried pkgconfig

A full log can be found at /home/allz/qemu/build/meson-logs/meson-log.txt

ERROR: meson setup failed
문제

해결 : sudo apt-get install libgtk2.0-dev

Program scripts/decodetree.py found: YES (/home/allz/qemu/build/pyvenv/bin/python3 /home/allz/qemu/scripts/decodetree.py)
Program flex found: NO

../target/hexagon/meson.build:179:4: ERROR: Program 'flex' not found or not executable

A full log can be found at /home/allz/qemu/build/meson-logs/meson-log.txt

ERROR: meson setup failed
문제

해결 : sudo apt install flex

Program scripts/decodetree.py found: YES (/home/allz/qemu/build/pyvenv/bin/python3 /home/allz/qemu/scripts/decodetree.py)
Program flex found: YES (/usr/bin/flex)
Program bison found: NO

../target/hexagon/meson.build:185:4: ERROR: Program 'bison' not found or not executable

A full log can be found at /home/allz/qemu/build/meson-logs/meson-log.txt

ERROR: meson setup failed
문제

해결 : sudo apt-get install bison

qemu-system-x86_64 \
-kernel /home/allz/kernel_dbg/bzImage \
-nographic \
-append "console=ttyS0 nokaslr" \
-initrd ramdisk.img \
-m 512 \
--enable-kvm \
-cpu host \
-s -S

qemu-system-x86_64 -kernel /home/allz/kernel_dbg/bzImage -nographic \
-append "console=ttyS0 nokaslr" -initrd ramdisk.img -m 512 --enable-kvm -s -S

- -enable-kvm 불가
- cpu host 불가

qemu-system-x86_64 -kernel /home/allz/kernel_dbg/bzImage -nographic \
-append "kgdboc=ttyS0,115200,115200 nokaslr" -initrd ramdisk.img \
-m 512 --enable-kvm -cpu host -s -S

disass start_kernel

tui enable

make kvm_guest.config 해야함
<br> <br>
<li>CLI,GUI</li>
CLI 란 ?

▷ Command Line Interface

▷ 명령어를 줄로 입력하여 소통(상호 작용)한다 라는 뜻을 가진다.

▷ 운영체제안에 있는 쉘이 가지고 있는 특정 명령어를 통해 운영체제를 컨트롤 한다.

▷ 윈도우에 'cmd' 나 리눅스에 '터미널'이 대표적이다.

▷ 키보드 + 명령어 사용 가능

TUI 란 ?

▷ Text User Interface

▷ 글로 사용자가 소통(상호 작용)을 한다 라는 뜻을 가진다.

▷ 리눅스 안에 'vi(vim) 편집기'가 대표적이다.

▷ CLI와 비슷하지만 다릅니다. 명령어를 사용해도 전혀 안된다.

메모장과 비슷합니다. 메모장과 다른점은 키보드로만 컨트롤 할 수 있다.

▷ 키보드만 사용 가능

GUI 란?

▷ Graphic User Interface

▷ 그래픽으로 사용자가 소통(상호 작용)을 한다 라는 뜻을 가진다.

▷ 키보드 + 마우스 모두 사용 가능

▷ 한 눈에 보이고 제일 편하다.

※ 제일 편한데 왜 GUI를 리눅스에서는 잘 쓰지 않을까 ? 리눅스를 왜 쓸까 ?

- 보통 리눅스를 서버용으로 CLI환경을 많이 사용한다.

그래픽으로 사용하면 자원을 많이 잡아먹어 부하가 많이 걸리기 때문이다.

- 실제 회사에서 리눅스가 서버로도 좋지만 무료이기 때문에 많이 사용한다.

- 리눅스가 윈도우에 비해 되게 가볍고, 빠르고, 안정성이 높다고 한다.

CLI → GUI 로 바꾸는 법

이 방법은 나중에 인터넷에서 다운로드를 받거나 할 때 불편한 상황에서 간단하게 바꿔

사용하기 위해 사용하시는 사람들이 있다.

하기 전 알아야 할 용어

런 레벨 (Run Level) : init 데몬에 의해 수행하게 되는 시스템 설정 모드

- init 0 : 시스템 종료
- init 1 : 단일 사용자 모드
- init 2 : 네트워크 지원 X, 다중 사용자 모드
- init 3 : 네트워크 지원 O, 다중 사용자 모드 = TUI
- init 4 : 사용자 지정 레벨 (사용하지 않는 레벨)
- init 5 : X-window 사용하는 다중 사용자 모드 = GUI
- init 6 : 시스템 재부팅 = reboot

※ X-window는 네트워크를 기반으로 하는 그래픽 사용자 인터페이스, GUI를 말함

이제 CLI에서 GUI로 바꾼다.

사용자는 root로 하시면 된다.

① **# yum -y groupinstall "GNOME Desktop" "Graphical Administration Tools"**

!https://blog.kakaocdn.net/dn/PyN4y/btqNMMGx0xc/5uEa0eKKmCK8yF77G2upq0/img.jpg

명령어로 -y로 설치 모두 yes선택, groupinstall로 그룹에 있는 모든 패키지를 다운

무료 오픈 소스 데스크톱 GUI환경 패키지 + 그래픽 관리 도구 패키지 다운

(설치 하는데 시간이 5분 정도 걸립니다.)

② 설치가 완료되면 Complete! 라는 문구가 뜬다.

!https://blog.kakaocdn.net/dn/MlZSm/btqNLQimt0u/d43CcodEEpHKGkZhSzej1K/img.jpg

③  **# ln -sf /lib/systemd/system/runlevel5.target /etc/systemd/system/default.target**

!https://blog.kakaocdn.net/dn/bArBVW/btqNJwY1eKo/iRUaBqch3m7PVmfowMFAT0/img.jpg

ln 파일 링크를 생성

- s는 링크할 원본이 심볼릭 링크된 파일이면 그 파일을 링크
- f는 링크 생성할 대상 파일이 있어도 강제로 새로운 링크 생성

이 명령어로 그래픽 모드인 런레벨5를 default(기본)으로 변경

④ 이제 런레벨이 그래픽 모드로 잘 변경되었는지 확인

**# systemctl get-default** 명령어로 기본 설정되어있는 모드를 확인

graphical.target으로 바뀌는것 확인

!https://blog.kakaocdn.net/dn/C7JQx/btqNLQJqCMH/qEFvm3NIgrBfeeszR5bkv0/img.jpg

⑤ 이제 재부팅하면 CLI에서 GUI로 바뀐다.

**# reboot** 또 는 **# init 6** 적용
<br> <br>
<li>iso 파일 추출</li>
https://www.makeuseof.com/tag/extract-iso-files-linux/

[https://ko.wikihow.com/리눅스에서-ISO-파일-만드는-방법](https://ko.wikihow.com/%EB%A6%AC%EB%88%85%EC%8A%A4%EC%97%90%EC%84%9C-ISO-%ED%8C%8C%EC%9D%BC-%EB%A7%8C%EB%93%9C%EB%8A%94-%EB%B0%A9%EB%B2%95)

dest에 iso 파일 설정

스크립트 파일 생성

스크립트 명령어

https://rhrhth23.tistory.com/147

root.sh

https://rhrhth23.tistory.com/20

<li>BusyBox</li>
.cpio를 만들고 img를 hda로 잡아서 만들어봄 하지만 적용이 안됨
busy box로 img를 만들어서 hda로 잡아서 만들어봄 이것 또한 적용 중간에 진행이 안됨.
BusyBox를 빌드하는 과정은 일반적으로 리눅스 시스템에서 다음과 같이 수행됩니다.

1. 필요한 도구 설치:
BusyBox를 빌드하려면 빌드 도구와 컴파일러가 필요합니다. 일반적으로 'gcc'와 'make'를 포함한 개발 도구를 설치해야 합니다. 아래 명령어를 사용하여 필요한 도구를 설치
    
    ```bash
    bashCopy code
    sudo apt-get install build-essential
    
    ```
    
    또한 BusyBox를 빌드하는 데 필요한 다른 종속성에 따라 추가 패키지가 필요할 수 있다.
    
2. BusyBox 소스 코드 다운로드:
BusyBox 소스 코드를 공식 웹사이트나 Git 저장소에서 다운로드합니다. 예를 들어, 공식 웹사이트에서 소스 코드를 다운로드하려면 다음과 같이 실행한다.
    
    ```bash
    bashCopy code
    wget https://busybox.net/downloads/busybox-x.y.z.tar.bz2
    
    ```
    
    'x.y.z'는 BusyBox의 버전 번호에 해당한다.
    
3. 압축 해제:
다운로드한 소스 코드를 압축 해제
    
    ```bash
    bashCopy code
    tar -xjf busybox-x.y.z.tar.bz2
    
    ```
    
4. 빌드 디렉토리로 이동:
압축 해제한 디렉토리로 이동
    
    ```bash
    bashCopy code
    cd busybox-x.y.z
    
    ```
    
5. BusyBox 설정:
BusyBox를 빌드하기 전에 설정을 구성해야 합니다. 다음 명령어를 실행하여 설정을 시작
    
    ```bash
    bashCopy code
    make menuconfig
    
    ```
    
    이 명령어는 BusyBox 빌드 구성을 위한 대화형 메뉴를 열고, 여기서 필요한 옵션을 선택하고 설정을 마침
    
6. BusyBox 빌드:
설정이 완료되면 다음 명령어를 사용하여 BusyBox를 빌드
    
    ```bash
    bashCopy code
    make
    
    ```
    
    이 명령어는 BusyBox를 컴파일하고 실행 파일을 생성

7. BusyBox 실행 파일 복사:

빌드된 BusyBox 실행 파일을 원하는 위치로 복사한다.

예를 들어, '/bin/busybox'와 같은 경로로 복사할 수 있다.

    
    ```bash
    bashCopy code
    cp busybox /bin/busybox
    
    ```
    
    필요에 따라 실행 파일 이름을 변경하거나 경로를 조정할 수 있다.
    
9. BusyBox 사용:
BusyBox를 사용할 준비가 끝났고 필요한 명령어를 실행하려면 BusyBox를 활성화하고 실행 파일을 사용하면 됨.

이제 BusyBox를 빌드하고 사용할 수 있다. 이 과정은 BusyBox를 커스터마이징하고 리눅스 시스템에서 사용하는 일반적인 방법이다. BusyBox 설정 단계에서 원하는 기능을 활성화 또는 비활성화하여 필요에 맞게 빌드할 수 있다.
<br> <br>
<p><li>roofts 디렉토리 생성</li></p>
1. 필요한 도구 설치:
먼저 **`debootstrap`** 패키지를 설치해야 합니다. 다음 명령을 사용하여 설치할 수 있다.
    
    ```bash
    bashCopy code
    sudo apt-get install debootstrap
    
    ```
    
2. rootfs 디렉토리 생성:
rootfs 이미지를 만들기 위한 디렉토리를 생성한다.
    
    ```bash
    bashCopy code
    mkdir my_rootfs
    
    ```
    
3. 기본 파일 시스템 구성:
**`debootstrap`** 명령을 사용하여 Debian 계열의 기본 파일 시스템을 생성한다.
    
    ```bash
    bashCopy code
    sudo debootstrap --arch=amd64 buster my_rootfs http://deb.debian.org/debian
    
    ```
    
    위 명령에서 "buster"는 Debian 10 (Buster)의 코드 이름입니다. 원하는 Debian 버전을 선택할 수 있다.
    
4. QEMU를 사용하여 실행:
이제 QEMU를 사용하여 rootfs 이미지를 실행할 수 있다. QEMU를 설치하지 않았다면 먼저 설치해야 한다.
    
    ```bash
    bashCopy code
    sudo apt-get install qemu-system-x86
    
    ```
    
    그런 다음, 다음 명령으로 QEMU를 사용하여 rootfs 이미지 실행
    
    ```bash
    bashCopy code
    qemu-system-x86_64 -m 512M -hda my_rootfs -netdev user,id=network0 -device e1000,netdev=network0
    
    ```
    
    이 명령은 512MB RAM을 할당하고, **`my_rootfs`**를 하드 디스크로 사용하며, 가상 네트워크를 설정한다.
    

이제 QEMU가 rootfs 이미지를 실행하고 가상 머신을 시작한다. 이를 통해 생성한 root 파일 시스템을 테스트하고 필요한 패키지 및 설정을 추가할 수 있다.

---

1. 루트 파일 시스템 준비:
루트 파일 시스템은 커널 이미지와는 별도로 관리된다. 필요한 경우 새로운 루트 파일 시스템을 생성하거나 기존의 루트 파일 시스템을 사용한다. 이전 답변에서 설명한 방법을 사용하여 루트 파일 시스템을 구성한다.
2. 루트 파일 시스템 디렉토리 마운트:
루트 파일 시스템을 임시로 마운트하고, 필요한 파일과 설정을 추가한다.
    
    ```bash
    bashCopy code
    sudo mount /dev/sdX /mnt  # 여기서 /dev/sdX는 루트 파일 시스템 장치를 가리킨다.
    sudo cp -a [루트 파일 시스템 파일 및 설정] /mnt
    sudo umount /mnt
    
    ```
    
3. rootfs 이미지 파일 생성:
마운트한 루트 파일 시스템을 사용하여 **`rootfs.img`** 파일을 생성한다. 이렇게 하려면 다음 명령을 사용한다.
    
    ```bash
    bashCopy code
    dd if=/dev/zero of=rootfs.img bs=1M count=[이미지 크기(MB)]
    mkfs.ext4 rootfs.img
    sudo mount rootfs.img /mnt
    sudo cp -a [루트 파일 시스템 파일 및 설정] /mnt
    sudo umount /mnt
    
    ```
    
    **`[이미지 크기(MB)]`**를 원하는 이미지 크기로 대체하고, **`[루트 파일 시스템 파일 및 설정]`**을 실제로 루트 파일 시스템의 파일과 설정으로 대체한다.

    
4. rootfs 이미지 사용:
이제 생성한 **`rootfs.img`** 파일을 사용할 수 있다. 필요한 장치에 복사하거나 QEMU 등을 사용하여 실행할 수 있다.

이렇게 하면 **`vmlinux`**와 **`bzImage`** 파일을 사용하여 루트 파일 시스템과 함께 **`rootfs.img`**를 생성하고 사용할 수 있다. 

이러한 작업은 커널과 루트 파일 시스템이 분리되어 있는 일반적인 시스템에서 사용되며, 커널 이미지와 루트 파일 시스템을 하나의 이미지로 통합하려면 다른 방식을 고려해야 한다.

<br> <br>

<p><li>전반적으로 구상해야 할 것을 정리</li></p>
qemu를 통해 커널을 열어라

qemu sysytem을 바탕으로 캠핑장을 간다고 생각해라

장소를 정해야하고, 장소를 정한 다음에 불판 같은게 필요하고, 그 위에 고기를 올려야한다. 

그러면 먹을 수 있다.

[root.sh](http://root.sh) 를 통해 먹는 과정이다.

./root.sh를 실행하는 것을 기반으로 진행해라.

---

vm를 구성할 때  필요한 것 vm 프로그램, 원하는 리눅스 버전을 포함하는 커널을 포함하는 iso이미지 파일이 필요하다.

ram이나 다른 요소들을 포함한다. 이러한 과정들을 리눅스 안에서 한번 더 한다고 생각을 해라. 

리눅스에서는 gui를 쓰는 것을 많이 제안한다. cli를 쓰게 만들 껀데, 우리에게는 vm이 필요한데 vm은 케뮤가 필요하다. 

동적 디버깅이 필요해서 kgdb가 필요하다. 우리가 가지고 있는 것이 vmlinux,와 bzimg다, 이 2개를 가지고 이걸 어떻게 잘 구워야지 iso 파일 처럼 하나의 커널 이미지 자체가 나올지, 검색앤진을 통해 알 수 있다. 

케뮤안에서 실행시키기 위해서 스크립트 파일이 필요하다. 여기서 스크립트 파일이란 vm을 실행시키기 위해 옵션을 주는 것을 말한다. 

램을 주거나 디버거를 주던가 등등을 하는 것이다. 가상머신을 띄우기 위해서는 도화지가 필요하다. 도화지를 흔히 이미지라고 하는데 도와지를 구성하는 요소도 필요하다. 

(네트워크 통신을 역할을 하기 위한 기본vm과의 연결 포트를 따야하는 것)- c파일을 실행시키려면 포트는 따야한다. 

이걸 통해서 공격이 진행하고 쉘이 따지는 것을 볼 수 있다. 이걸 또 나의 vm안으로 옮겨야하는데 케뮤는 gui가 아니여서 마우스로 옮길 수 없다. 포트를 따로 열어줘서 ssh를 따로 따주던지  csp라는 ssh와 비슷한 파일 전송 도구를 통해 이동시켜야 한다. 

이를 하려면 포트포워딩도 있어야 한다. 이러한 모든 요소들을 구성시켜 줄 수 있는 파일을 짜야한다. 

<br> <br>
<p><li>ubuntu에서 실시한 것을 정리</li></p>

oracle vm virtual box 설치

ubuntu- 22.04 desktop.iso 디스크 이미지 다운

virtualbox extension pack 다운 이후 장치에서 게스트 확장 이미지 삽입을 진행한후 터미널을 열고 autorun.sh를 찾아
./autorun.sh를 진행

이후 구글 드라이브에 있는 파일 4개를 firefox을 통해 다운
qemu 다운을 진행하고 위의 qemu를 진행할 때의 문제점과 해결 방안을 통해 문제를 진행함 이후 make를 통해 qemu를 만들었다.

busybox-1.31.1tar.bz2 - 위에 busybox 설정을 참고

make defconfig

make menuconfig

setting → —Build Options 에서 Build static binary 체크

qemu로 리눅스 커널을 올릴때, 디폴트 라이브러리들이 없으므로, 모두 static으로 라이브러리를 빌드되게 하는 옵션이다. 따라서 qemu에서 실행시킬 바이너리들을 빌드할땐 gcc - static 옵션을 무조건 붙여야한다.

menuconfig 화면을 나오면, .config 파일에 CONFIG_STATIC=y 가 설정되어 있는것을 볼수있다.

make busybos → 빌드

mkdir _install

make CONFIG_PREFIX =_install install

~/Desktop/kernel_study/for_qemu/for_busybox/busybox-1.31.1

$ cd _install 

~/Desktop/kernel_study/for_qemu/for_busybox/busybox-1.31.0/_install 

$ ls

bin  linuxrc  sbin  user

이렇게 나오면 정상적인 빌드가 완료된것이다. 이제 위 4개의 디렉토리를 묶어서 rootfs를 만들기 전에 여기서 공부한 커널 모듈을 디버깅하기 위해 요 안에 아래의 코드를 빌드해서 넣어보자.

chardev.c

makefile

find . | cpio -H newc -o | gzip > rootfs.img.gz

cpio는 파일 시스템 압축을 위한 명령어라고 보면 된다. 위 명령어를 치면 rootfs.img.gz가 생성되고, 이게 바로 rootfs이다.

여기서 gz는 오류가 진행되서 gz는 빼고 진행하였다.

linux-6.0.tar.gz - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git의 홈페이지에 v6.0을 통해 링크를 복사하고 wget명령을 사용해 터미널에서 사용

root.sh 리눅스 실행파일 touch root.sh, 실행권한 부여 chmod 755 root.sh, 쉘 확인 echo $SHELL 이후 쉘을 선언하기 위해 vi root.sh를 사용했다.

vi를 통해 들어간 쉘 안에서는 i가 input을 할 수 있는 것이고, x가 지우는 것 esc를 통해 저장을 할 수 있고 이후에 esc shift :wq를 통해 나갈 수 있다.

rootfs.img : 커널에 대한 이미지 만들기 <br>
명령어는 <br>
sudo apt-get install debootstrap<br>
mkdir image && cd image<br>
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh<br>
chmod +x create-image.sh<br>
./create-image.sh<br>

make defconfig

각 arch 마다 기본 config 가 존재하는데, 이것이 바로 defconfig 파일이다.

arch/x86/configs/*   --> x86 기반 arch 의 defconfig 파일들 모음.

arch/arm/configs/*  --> arm 기반 arch 의 defconfig 파일들 모음.

make meuconfig

kernel hacking → Compile-time checks and compiler options → 맨위에꺼 체크

kernel hacking → KGDB: kernel debugger 체크
위 옵션들을 체크하고 저장하고 나오면 체크한 설정들을 기반으로 .config 파일이 생성된다.

make → 커널 빌드

makefile을 보면 .config 파일을 참조하여 커널을 빌드하게끔 되어있다. 여기서 나는 gcc 관련 에러가 나와서 기존 gcc 버전을 7에서 6으로 낮추니까 됐다. 빌드에 성공하면 커널이미지 파일이 arch/x86/boot 하위에 bzimage 이름으로 생긴다.

~/Desktop/kernel_study/for_qemu/linux/arch/x86/boot ‹523d939ef98f*› 

$ file bzImage 

bzImage: Linux kernel x86 boot executable bzImage, version 4.7.0+ (wogh8732@ubuntu) #

이후에 커널 실행 <br>

qemu-system-x86_64 \
        -m 2G \
        -smp 4 \
        -kernel /home/linux-6.0/arch/x86_64/boot/bzImage \
        -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 nokaslr" \
        -drive file=/home/linux-6.0/arch/x86_64/boot/stretch.img,format=raw \
        -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
        -net nic,model=e1000 \
        -enable-kvm \
        -nographic \
        -pidfile vm.pid \
        2>&1 | tee vm.log
        이 코드를 실재 root.sh에 넣으면 된다.
        
roots.iso 

ISO를 만드는 명령어를 입력한다. mkisofs -o destination-filename.iso /home/username/folder-name을 입력하고, "destination-filename" 에는 원하는 ISO 파일 이름을 넣고, "folder-name" 은 ISO 파일이 저장되는 폴더로, 원하는 폴더 이름을 넣으면 된다.

mkisofs -o roots.iso /home/username/qemu를 통해 만들었다.

vm.log 
wm.pid 

home/linux6.0/arch/x86_64/boot 파일 내에 bzImage와 stretch.img 파일 삽입

han@han-VirtualBox:~/linux-6.0$ gdb -q ./vmlinux

Reading symbols from ./vmlinux...

(No debugging symbols found in ./vmlinux)

(gdb) c

The program is not being run.

(gdb) b *start_kernel

Breakpoint 1 at 0xffffffff82fbac19

(gdb) target remote localhost:1234

localhost:1234: Connection timed out.

(gdb) target remote localhost:1234

Remote debugging using localhost:1234

0x0000000003611ff9 in ?? ()

(gdb) c

->

Continuing.

end Kernel panic - not syncing: VFS: Unable to mount root f-

까지 진행했습니다.

</ol>
