# Windows Honeypot Solution (윈도우 허니팟 솔루션)

C# (.NET 8+), WPF, Windows API를 사용하여 구축된 종합 방어형 사이버 보안 플랫폼으로, 사이버 공격을 탐지하고 분석하기 위한 격리된 샌드박스 환경을 생성합니다.

## 🎯 개요

Windows Honeypot Solution은 기만 기술을 활용하여 사이버 공격을 탐지, 분석하고 증거를 수집합니다. Windows Sandbox API를 사용하여 공격자에게는 합법적인 비즈니스 워크스테이션처럼 보이지만 호스트 시스템에는 전혀 위험이 없는 완전히 격리된 환경을 만듭니다.

## 🏗️ 아키텍처

### 프로젝트 구조

```
WindowsHoneypot/
├── src/
│   ├── WindowsHoneypot.Core/          # 핵심 비즈니스 로직 및 인터페이스
│   │   ├── Interfaces/                # 핵심 서비스 인터페이스
│   │   ├── Models/                    # 데이터 모델 및 DTO
│   │   └── Services/                  # 서비스 구현
│   └── WindowsHoneypot.UI/            # ModernWpf를 사용한 WPF 사용자 인터페이스
├── tests/
│   └── WindowsHoneypot.Tests/         # 단위 테스트 및 속성 기반 테스트
└── docs/                              # 문서
```

### 핵심 구성 요소

- **Honeypot Manager**: 모든 허니팟 활동의 중앙 조율
- **File Monitor**: 실시간 파일 시스템 조작 탐지
- **Network Blocker**: Windows 방화벽 API를 사용한 완전한 네트워크 격리
- **Deception Engine**: VM 탐지 회피를 위한 하드웨어 스푸핑
- **Process Camouflage**: 현실적인 환경을 위한 가짜 비즈니스 프로세스
- **Honey Account System**: 공격자 프로파일링을 위한 자격 증명 트랩
- **Visual Replay Engine**: 활동 기록 및 시각화
- **Community Intelligence**: 위협 공유 및 집단 방어

## 🚀 주요 기능

### 🛡️ 완전한 격리
- Windows Sandbox API로 호스트 시스템에 대한 위험 제로 보장
- 분석 중 네트워크 트래픽 완전 차단
- 권한 제한을 통한 샌드박스 탈출 방지

### 🎭 고급 기만 기술
- VM 탐지 우회를 위한 하드웨어 정보 스푸핑
- 가짜 비즈니스 프로세스 (Slack, Teams, Chrome 등)
- 브라우저 및 파일에 심어진 허니 자격 증명
- 현실적인 시스템 환경 시뮬레이션

### 📊 인텔리전스 수집
- 실시간 파일 시스템 모니터링
- 포괄적인 공격자 프로파일링 및 지문 채취
- 타임라인을 통한 공격자 활동의 시각적 재생
- 암호화된 포렌식 증거 수집

### 🌐 커뮤니티 방어
- 익명 위협 인텔리전스 공유
- 글로벌 공격 패턴 분석
- 자동 블랙리스트 업데이트
- 집단 보안 생태계

### ⚡ 즉시 복구
- 원클릭 완전 시스템 정리
- 자동 방화벽 규칙 복원
- 레지스트리 및 임시 파일 정리
- 긴급 대응 기능

## 🛠️ 기술 스택

- **프레임워크**: .NET 8+ with C#
- **UI**: ModernWpf 다크 모드 스타일링을 사용한 WPF
- **샌드박스**: Windows Sandbox API
- **보안**: Windows 방화벽 API, 레지스트리 조작
- **모니터링**: FileSystemWatcher, Win32 API
- **테스팅**: xUnit, FsCheck (속성 기반 테스팅)
- **로깅**: 구조화된 로깅을 사용한 Serilog
- **DI**: Microsoft.Extensions.DependencyInjection

## 📋 요구 사항

### 시스템 요구 사항
- Windows 10 Pro/Enterprise (버전 1903 이상) 또는 Windows 11
- Windows Sandbox 기능 활성화
- .NET 8 런타임
- 방화벽 및 레지스트리 작업을 위한 관리자 권한

### 하드웨어 요구 사항
- 최소 4GB RAM (8GB 권장)
- 2GB 여유 디스크 공간
- 가상화 지원 (Intel VT-x 또는 AMD-V)

## 🚦 시작하기

### 1. Windows Sandbox 활성화
```powershell
# 관리자 권한으로 실행
Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online
```

### 2. 솔루션 빌드
```bash
# 저장소 클론
git clone <repository-url>
cd WindowsHoneypot

# 종속성 복원 및 빌드
dotnet restore
dotnet build --configuration Release
```

### 3. 테스트 실행
```bash
# 속성 기반 테스트를 포함한 모든 테스트 실행
dotnet test
```

### 4. 애플리케이션 시작
```bash
# UI 애플리케이션 실행
dotnet run --project src/WindowsHoneypot.UI
```

## 🧪 테스팅 전략

프로젝트는 이중 테스팅 접근 방식을 사용합니다:

### 단위 테스트
- 특정 예제 및 엣지 케이스
- 구성 요소 간 통합
- UI 구성 요소 검증
- 오류 처리 시나리오

### 속성 기반 테스트 (FsCheck)
- 보편적 정확성 속성
- 무작위 테스트 데이터 생성
- 포괄적인 입력 공간 커버리지
- 시스템 동작의 형식적 검증

## 🔒 보안 고려 사항

### 격리 보장
- 샌드박스 실행 중 완전한 네트워크 격리
- 프로세스 권한 제한 및 모니터링
- 샌드박스 탈출 시도 탐지 및 방지
- 무결성 보호를 통한 암호화된 증거 저장

### 개인정보 보호
- 익명 위협 인텔리전스 공유
- 개인 데이터 수집 또는 전송 없음
- 선택적 클라우드 기능을 갖춘 로컬 우선 아키텍처
- GDPR 준수 데이터 처리

## 📖 문서

- [요구사항 문서](.kiro/specs/windows-honeypot-solution/requirements.md)
- [설계 문서](.kiro/specs/windows-honeypot-solution/design.md)
- [구현 작업](.kiro/specs/windows-honeypot-solution/tasks.md)

## 🤝 기여하기

1. 저장소 포크
2. 기능 브랜치 생성
3. 테스트와 함께 변경 사항 구현
4. 모든 테스트 통과 확인
5. Pull Request 제출

## 📄 라이선스

이 프로젝트는 MIT 라이선스에 따라 라이선스가 부여됩니다 - 자세한 내용은 LICENSE 파일을 참조하세요.

## ⚠️ 법적 고지

이 소프트웨어는 합법적인 사이버 보안 방어 목적으로만 사용됩니다. 사용자는 해당 관할권의 모든 관련 법률 및 규정을 준수할 책임이 있습니다. 저자는 이 소프트웨어의 오용에 대해 책임을 지지 않습니다.

## 🆘 지원

문제, 질문 또는 기여를 위해:
- 저장소에 이슈 생성
- `docs/` 폴더의 문서 확인
- 사용 예제는 테스트 케이스 검토

---

**상태**: 🚧 개발 중 - 작업 1 완료 (프로젝트 구조 및 핵심 인터페이스)

**다음 단계**: Windows Sandbox 통합 및 프로세스 관리 구현 (작업 2)
