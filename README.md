# Windows Honeypot Solution (윈도우 허니팟 솔루션)

## 👥 Key Root 팀

| 이름 | 역할 | 담당 업무 |
|------|------|-----------|
| Dangel | 프로젝트 리더 & 보안 개발 |  네트워크 격리, 방화벽 API, Deception Engine, VM 탐지 회피를 위한 하드웨어 스푸핑 개발 |
| 743R | 백엔드 개발 | 아키텍처 설계, 핵심 서비스 구현|
| Nyx | 시스템 개발자 | Windows Sandbox 통합, 파일 모니터링 |
| SC | UI/UX 개발자 | WPF 인터페이스, Visual Replay Engine, 대시보드 |
| HCK | 데이터 분석가 | 위협 인텔리전스, 행동 분석, Community Intelligence |
| POE | QA & 테스트 엔지니어 | 단위 테스트, 속성 기반 테스트, 통합 테스트 |

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

## 📄 라이선스

이 프로젝트는 Key Root 저작권으로 보호되며 무단 복제, 배포 및 사용이 금지됩니다.

## ⚠️ 법적 고지

이 소프트웨어는 합법적인 사이버 보안 방어 목적으로만 사용됩니다. 사용자는 해당 관할권의 모든 관련 법률 및 규정을 준수할 책임이 있습니다. 저희팀은 이 소프트웨어의 오용에 대해 책임을 지지 않습니다.
