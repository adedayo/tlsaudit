package tlsmodel

import (
	"reflect"
	"strings"
	"testing"
)

type args struct {
	cipher string
}

type testdata struct {
	name       string
	args       args
	wantConfig CipherConfig
	wantErr    bool
}

func TestGetCipherConfig(t *testing.T) {

	tests := []testdata{
		{
			name: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
			args: args{
				cipher: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
			},
			wantConfig: CipherConfig{
				Cipher:         "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
				Authentication: "ECDSA",
				IsExport:       false,
				KeyExchange:    "ECDHE",
				Encryption:     "CAMELLIA_256_GCM",
				MACPRF:         "SHA384",
			},
			wantErr: false,
		},
		{
			name: "TLS_ECDHE_ECDSA_CAMELLIA_256_GCM_SHA384",
			args: args{
				cipher: "TLS_ECDHE_ECDSA_CAMELLIA_256_GCM_SHA384",
			},
			wantConfig: CipherConfig{
				Cipher: "TLS_ECDHE_ECDSA_CAMELLIA_256_GCM_SHA384",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotConfig, err := GetCipherConfig(tt.args.cipher)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCipherConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotConfig, tt.wantConfig) {
				t.Errorf("GetCipherConfig() = %v, want %v", gotConfig, tt.wantConfig)
			}
		})
	}
}

func TestIANACiphersNotErroring(t *testing.T) {
	for _, x := range enumerateCipherParseErrors() {
		t.Run(x.cipher, func(t *testing.T) {
			if x.err != nil {
				t.Errorf("Parsing of %s fails because %s", x.cipher, x.err.Error())
			}
		})
	}
}

type parseError struct {
	cipher string
	err    error
}

func enumerateCipherParseErrors() (data []parseError) {
	for _, c := range CipherSuiteMap {
		_, err := GetCipherConfig(c)
		data = append(data, parseError{
			cipher: c,
			err:    err,
		})
	}
	return
}

func TestCipherConfig_IsAuthenticated(t *testing.T) {
	type fields struct {
		Cipher         string
		KeyExchange    string
		Authentication string
		IsExport       bool
		Encryption     string
		MAC            string
	}
	tests := []struct {
		name   string
		cipher string
		want   bool
	}{
		{
			name:   "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
			cipher: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
			want:   true,
		},
		{
			name:   "TLS_KRB5_WITH_RC4_128_MD5",
			cipher: "TLS_KRB5_WITH_RC4_128_MD5",
			want:   true,
		},
		{
			name:   "TLS_DH_anon_WITH_DES_CBC_SHA",
			cipher: "TLS_DH_anon_WITH_DES_CBC_SHA",
			want:   false,
		},
		{
			name:   "TLS_NULL_WITH_NULL_NULL",
			cipher: "TLS_NULL_WITH_NULL_NULL",
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc, _ := GetCipherConfig(tt.cipher)
			if got := cc.IsAuthenticated(); got != tt.want {
				t.Errorf("CipherConfig.IsAuthenticated() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScanResult_SupportsTLS(t *testing.T) {
	if (ScanResult{}).SupportsTLS() != false {
		t.Errorf("(ScanResult{}).SupportsTLS() is not false!")
	}
}

func TestScanResult_IsExportable(t *testing.T) {
	for _, cipher := range CipherSuiteMap {
		t.Run(cipher, func(t *testing.T) {
			if strings.Contains(strings.Split(cipher, "_WITH_")[0], "EXPORT") {
				if cc, _ := GetCipherConfig(cipher); !cc.IsExport {
					t.Errorf("CipherConfig.IsExportable() = false, when cipher is %s", cipher)
				}
			}
		})
	}
}

func TestScanResult_GetEncryptionKeyLength(t *testing.T) {
	for _, cipher := range CipherSuiteMap {
		t.Run(cipher, func(t *testing.T) {
			if cc, _ := GetCipherConfig(cipher); cc.GetEncryptionKeyLength() == -1 {
				t.Errorf("CipherConfig.GetEncryptionKeyLength() = -1, when cipher is %s", cc.Encryption)
			}
		})
	}
}
