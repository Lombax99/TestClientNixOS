module github.com/securityresearchlab/nebula-est/nest_client

go 1.24

require (
	github.com/go-playground/assert/v2 v2.2.0
	github.com/pquerna/otp v1.4.0
	github.com/securityresearchlab/nebula-est/nest_ca v0.0.0-00010101000000-000000000000
	github.com/securityresearchlab/nebula-est/nest_config v0.0.0-00010101000000-000000000000
	github.com/securityresearchlab/nebula-est/nest_service v0.0.0-00010101000000-000000000000
	github.com/slackhq/nebula v1.9.5
	google.golang.org/protobuf v1.36.5
)

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/bytedance/sonic v1.11.6 // indirect
	github.com/bytedance/sonic/loader v0.1.1 // indirect
	github.com/cloudwego/base64x v0.1.4 // indirect
	github.com/cloudwego/iasm v0.2.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/gin-gonic/gin v1.10.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.20.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.7 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	golang.org/x/arch v0.8.0 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/securityresearchlab/nebula-est/nest_service => ../nest_service

replace github.com/securityresearchlab/nebula-est/nest_ca => ../nest_ca

replace github.com/securityresearchlab/nebula-est/nest_config => ../nest_config
