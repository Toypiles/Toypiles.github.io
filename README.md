# Toypiles.github.io
Debug <br>
시작하기 앞서 정리한 용어들
<ol>
  <li>리눅스 명령어</li>  <br>
  pwd : 현재 작업중인 디렉토리 정보 출력 <br>
  cd : 경로이동 <br>
  - 절대경로 : 절대경로로 경로를 기술할 때에는 항상 맨 앞에 최상위 디렉토리 (/)가 붙는다는 것을 명심하자 <br>
  - 상대경로 : <br>
  ls : 디렉토리 목록 확인 <br>
  cp : 파일 혹은 디렉토리를 복사 (단 복사할 때는 -r옵션을 주어야함) <br>
  mv : 파일 혹은 디렉토리 이동 (실제 원하는 위치로 이동할때도 사용하지만, 이름을 변경하는 용도로도 사용한다.) <br>
  동기화  <br>  <br>
 <li>과제에 앞서 정리한 개념들</li> <br>
  커널 은 프로세스와 가상 메모리를 관리하기 위해 전체 시스템 권한으로 실행되는 OS의 핵심 프로그램 <br>
프로세스끼리는 서로 독립되어 메모리를 관리한다.(기본적으로는 맞지만 조금 더 효율적인 처리를 위해 공유 메모리, 메세지 등(IPC)의 기능이 있다.) <br>
- 같은 프로세스의 스레드는 stack과 register을 제외하면 서로 메모리를 공유한다. <br>
synchronization(동기화) : 다양한 프로세스와 스레드가 서로 충돌하거나 예상치 못한 값 변경을 막기위해 서로의 정보를 공유하는 것 <br>
프로세스 : 실행되고있는 프로그램 <br>
프로세스 상태 : new, ready, running, waiting, terminated, and suspended <br>
new : 프로세스가 만들어지는 상태(아직 만들어지지 않음) <br>
ready : 프로세스가 할당되기를 기다리는 상태 <br>
running : 실행되는 중 <br>
Blocked or Wait : 어떤 event가 발생하는 것을 대기하는 상태 <br>
Terminated or Completed : 프로세스가 종료되고 PCB가 삭제 <br>
Suspend Ready : 인터럽트등이 발생했을때 스케줄러에 의해 외부 저장소에 배치된 상태 <br>
Suspend wait or suspend blocked :  I/O 작업을 수행 중이며 해당 I/O 작업이 완료될 때까지 기다리는 상태 <br>
  - PCB(Process Control Block) : 프로세스를 관리할때 필요한 정보가 담겨져있는 블록/ 프로세스의 생성과 소멸때 같이 생성,소멸 된다. / 이 안에 PID(프로세스 식별 번호), 프로세스 상태 등등이 있다. <br>
- ps : 프로세스 확인 명령어 / cat /proc/<pid>/status : pcb정보 확인 명령어 <br>
critical section : 자원 공유의 문제가 발생하는 걸 방지하기 위해 하나의 프로세스나 스레드에 독점권을 보장해주는 영역이다. <br>
동시성에 대한 4가지 전략(java긴 함) <br>
- Confinement(제한) : 스레드간의 변수 공유 불가 <br>
    - 스레드는 stack이 서로 분리되어있고 변수는 stack에 저장되므로 서로 변수 공유는 불가하며 그로 인해 발생할 수 있는 동시성 가능성을 없앨수있다. / 전역 변수는 여기에 해당이 되지 않기 때문에 주의해야한다. <br>
- Immutability(불변성) : 공유 데이터를 변경할수없게 만드는 것(ex. 상수) <br>
- Threadsafe data type(항상 올바른 동작을 하며 추가적인 조정이 없는 데이터 타입) : 타입확인은 나중에 자바가면 확인하자 <br>
- Synchronization(동기화) <br>
    - Deadlock:서로 하나의 리소스를 가지고 있으면서 다른 리소스를 원하는데 그게 상대방의 리소스인 상태(종속성의 순환)
  해결방법 <br>
  1. lock ordering : 순서를 정하면 Deadlock 미발생 <br>
  2. coarse-grained locking : 거친 잠금을 한다. / 하나의 큰 락으로 전체를 보호(성능적 저하) <br>
- Context Switching : 한 프로세스를 저장하고 다른 프로세스를 로드하는 것 <br>
- Mode Switch : 프로세스가 유저에서 커널로 갈때 실행권한을 변경시켜주는 기능 <br>
- Process Switch : 프로세스가 종료되었을때 다른 프로세스로 변경되는 것(종료되어야함 중단이 아니라) <br>
- CPU-Bound : CPU에 중점을 둔 프로세스(ex.계산 집약적인 작업, 데이터 처리, 알고리즘 실행 등) <br>
- I/O-Bound : I/O에 중점을 둔 프로세스(ex.파일에서 데이터를 읽고 처리하는 작업, 웹 서버에서 클라이언트 요청) <br>
- Scheduling : 프로세스를 조율하는 프로세스 <br>
- Scheduling Algorithms : 프로세스를 조율하는 프로세스를 규정하는 알고리즘 <br>
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
    
    TestAndSet 인자를 통해 진입여부를 확인하는데 이 인자는 CPU atomic 명령어이다.
    
    - 실행 중간에 간섭받거나 중단되지 않는다
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
3. slab, page_alloc, and non-executable vmalloc memory을 지워
- The Kernel Concurrency Sanitizer (KCSAN) : dynamic race detector이다
    - 주된 목적은 data races 감지이다.
- Improper synchronization(CWE-662) : 하나의 critical section에 두개의 스레드가 들어가 충돌되는 취약점
- Improper locking(CWE-667) : 제대로 locking이 되지 않아 발생하는 취약점
- vmlinux : Linux 커널의 이미지 파일로, 컴파일된 커널 코드와 데이터를 포함 / ELF형식 / 정적링크 / 디버깅용
- System.map : 커널을 컴파일 할 때마다 새로 생성되는 파일로 커널에 들어 있는 심벌에 대한 정보를 담고있음
- bzImage : 부트 로더가 부팅하는 데 사용되는 압축된 Linux 커널 이미지
프로세스를 잘게 나눈것이 스레드다.
프로세스 안에 스레드는 독립이 되는 것이 아니다.
스레드 안에 있는 스택이나 힙은 독립이 되어 있는데 나머지는 연결 되어 있음.
ref

- [https://velog.io/@dodozee/OS-메모리-영역-코드-영역-데이터-영역-힙-영역-스택-영역-대해서feat.스레드](https://velog.io/@dodozee/OS-%EB%A9%94%EB%AA%A8%EB%A6%AC-%EC%98%81%EC%97%AD-%EC%BD%94%EB%93%9C-%EC%98%81%EC%97%AD-%EB%8D%B0%EC%9D%B4%ED%84%B0-%EC%98%81%EC%97%AD-%ED%9E%99-%EC%98%81%EC%97%AD-%EC%8A%A4%ED%83%9D-%EC%98%81%EC%97%AD-%EB%8C%80%ED%95%B4%EC%84%9Cfeat.%EC%8A%A4%EB%A0%88%EB%93%9C)
- https://web.mit.edu/6.005/www/fa15/classes/20-thread-safety/#strategy_1_confinement
- https://web.mit.edu/6.005/www/fa15/classes/23-locks/
- https://docs.kernel.org/dev-tools/kasan.html
</ol>
