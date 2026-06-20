package config

import _ "embed"

// SRERootCA 는 *.sre.local 사설 CA 루트 인증서다.
// 바이너리에 내장되어 Vault·Postgres TLS 검증에 쓰인다 — 신규 멤버가 CA 를 따로 설치할 필요가 없다.
//
//go:embed innogrid-sre-root-ca.crt
var SRERootCA []byte
