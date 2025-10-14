# JWT Encoder/Decoder

실시간으로 JWT 토큰을 인코딩/디코딩할 수 있는 웹 애플리케이션입니다.

## 주요 기능

- 🔄 **실시간 양방향 동기화**: JWT 토큰 ↔ Header/Payload 자동 동기화
- 🔐 **서명 검증**: Secret 키를 통한 JWT 서명 검증 기능
- ⏰ **편리한 만료시간 편집**: Epoch, GMT, Local Time 형식으로 exp 값 손쉽게 편집
- 🎨 **시각적 토큰 구분**: Header, Payload, Signature를 색상으로 구분
- ⚡ **즉시 반영**: 별도의 Encode/Decode 버튼 없이 자동으로 변경사항 반영

## 기술 스택

- **Frontend**: React 18 + Vite
- **Styling**: Tailwind CSS
- **JWT 라이브러리**: jose
- **Icons**: lucide-react
- **Deployment**: Cloudflare Workers

## 설치 및 실행

### 1. 의존성 설치

```bash
npm install
```

### 2. 로컬 개발 서버 실행

```bash
npm run dev
```

또는 Wrangler를 통한 개발:

```bash
npx wrangler dev
```

### 3. 프로덕션 빌드

```bash
npm run build
```

### 4. Cloudflare Workers 배포

```bash
npx wrangler deploy
```

## 사용 방법

### JWT 토큰 디코딩
1. JWT 토큰 입력 필드에 토큰을 붙여넣기
2. Header와 Payload가 자동으로 디코딩되어 표시됨
3. Secret 키를 입력하면 서명 검증 결과 확인 가능

### JWT 토큰 생성/수정
1. Header 또는 Payload 필드를 JSON 형식으로 편집
2. 변경 즉시 새로운 JWT 토큰이 자동 생성됨
3. Secret 키를 변경하면 토큰이 새로운 키로 서명됨

### 만료시간(exp) 편집
1. Expiration Editor 섹션에서 원하는 형식 선택 (Epoch/GMT/Local)
2. 시간 값 입력 또는 선택
3. Payload의 exp 값과 토큰이 자동으로 업데이트됨

## 프로젝트 구조

```
jwt-huny-dev/
├── src/
│   ├── App.jsx          # 메인 애플리케이션 컴포넌트
│   ├── main.jsx         # React 진입점
│   └── index.css        # Tailwind CSS 설정
├── public/
│   ├── robots.txt       # 검색 엔진 크롤러 설정
│   └── sitemap.xml      # 사이트맵
├── workers-site/
│   └── index.js         # Cloudflare Workers 진입점
├── index.html           # HTML 템플릿 (SEO 메타 태그 포함)
├── vite.config.js       # Vite 설정
├── wrangler.toml        # Cloudflare Workers 설정 (커스텀 도메인)
├── tailwind.config.js   # Tailwind 설정
├── postcss.config.js    # PostCSS 설정
└── package.json         # 프로젝트 의존성
```

## SEO 최적화

이 프로젝트는 구글 검색 노출을 위해 다음과 같은 SEO 최적화가 적용되어 있습니다:

### ✅ 이미 적용된 항목

- **메타 태그**: title, description, keywords, author
- **Open Graph 태그**: Facebook 공유 최적화
- **Twitter Card 태그**: Twitter 공유 최적화
- **Canonical URL**: 중복 콘텐츠 방지
- **Structured Data (JSON-LD)**: 검색 엔진 이해도 향상
- **robots.txt**: 검색 엔진 크롤링 허용
- **sitemap.xml**: 사이트 구조 제공
- **Semantic HTML**: 적절한 HTML5 태그 사용
- **언어 설정**: lang="ko" 속성
- **반응형 디자인**: 모바일 친화적

### 📋 추가 권장 사항

1. **Google Search Console 등록**
   - https://search.google.com/search-console
   - 사이트 추가 및 소유권 확인
   - sitemap.xml 제출 (https://jwt.huny.dev/sitemap.xml)

2. ~~**Open Graph 이미지**~~ ✅
   - `public/logo.png` 추가 완료
   - SNS 공유 시 표시되는 썸네일

3. ~~**Favicon**~~ ✅
   - `public/logo-64x64.ico` 추가 완료
   - 브라우저 탭 아이콘

4. **성능 최적화**
   - Lighthouse 점수 확인 및 개선
   - Core Web Vitals 최적화

5. **백링크 구축**
   - 관련 커뮤니티에 공유
   - 개인 블로그/포트폴리오에서 링크

6. **콘텐츠 업데이트**
   - 정기적인 기능 추가 및 개선
   - 변경사항 블로그 게시

## 배포 후 체크리스트

- [ ] `npm run build` 빌드 성공 확인
- [ ] `npx wrangler deploy` 배포 완료
- [ ] https://jwt.huny.dev 접속 확인
- [ ] Cloudflare DNS 설정 확인
- [ ] Favicon 추가 (logo-64x64.ico)
- [ ] Open Graph 이미지 추가 (logo.png)
- [ ] robots.txt 최적화 완료
- [ ] Cache 헤더 추가로 성능 개선
- [ ] Lighthouse 점수 확인 및 개선 완료
- [ ] Google Search Console 등록
- [ ] sitemap.xml 제출

## 라이선스

MIT

---

Powered by jose • JavaScript module for JSON Web Tokens

Made with ❤️ by [huny.dev](https://huny.dev)
