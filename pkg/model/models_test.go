package tlsmodel

import (
	"reflect"
	"strings"
	"testing"

	tlsdefs "github.com/adedayo/tls-definitions"
)

type args struct {
	cipherID uint16
	cipher   string
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
				cipherID: 0xC087,
				cipher:   "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
			},
			wantConfig: CipherConfig{
				CipherID:               0xC087,
				Cipher:                 "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
				Authentication:         "ECDSA",
				IsExport:               false,
				SupportsForwardSecrecy: true,
				KeyExchange:            "ECDHE",
				Encryption:             "CAMELLIA_256_GCM",
				MACPRF:                 "SHA384",
			},
			wantErr: false,
		},
		{
			name: "TLS_NONE_EXISTENT_CIPHER",
			args: args{
				cipherID: 0xFFFF, //does not exist
			},
			wantConfig: CipherConfig{
				CipherID: 0x0,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotConfig, err := GetCipherConfig(tt.args.cipherID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCipherConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotConfig, tt.wantConfig) {
				t.Errorf("GetCipherConfig() = %v, want %#v", gotConfig, tt.wantConfig)
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
	for c, cn := range tlsdefs.CipherSuiteMap {
		_, err := GetCipherConfig(c)
		data = append(data, parseError{
			cipher: cn,
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
		name     string
		cipher   string
		cipherID uint16
		want     bool
	}{
		{
			name:     "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
			cipherID: 0xC087,
			cipher:   "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
			want:     true,
		},
		{
			name:     "TLS_KRB5_WITH_RC4_128_MD5",
			cipherID: 0x0024,
			cipher:   "TLS_KRB5_WITH_RC4_128_MD5",
			want:     true,
		},
		{
			name:     "TLS_DH_anon_WITH_DES_CBC_SHA",
			cipherID: 0x001A,
			cipher:   "TLS_DH_anon_WITH_DES_CBC_SHA",
			want:     false,
		},
		{
			name:     "TLS_NULL_WITH_NULL_NULL",
			cipherID: 0x0000,
			cipher:   "TLS_NULL_WITH_NULL_NULL",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc, _ := GetCipherConfig(tt.cipherID)
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
	for cipher, cipherName := range tlsdefs.CipherSuiteMap {
		t.Run(cipherName, func(t *testing.T) {
			if strings.Contains(strings.Split(cipherName, "_WITH_")[0], "EXPORT") {
				if cc, _ := GetCipherConfig(cipher); !cc.IsExport {
					t.Errorf("CipherConfig.IsExportable() = false, when cipher is %s", cipherName)
				}
			}
		})
	}
}

func TestScanResult_GetEncryptionKeyLength(t *testing.T) {
	for cipher, cipherName := range tlsdefs.CipherSuiteMap {
		t.Run(cipherName, func(t *testing.T) {
			if cc, _ := GetCipherConfig(cipher); cc.GetEncryptionKeyLength() == -1 {
				t.Errorf("CipherConfig.GetEncryptionKeyLength() = -1, when cipher is %s", cc.Encryption)
			}
		})
	}
}

func TestEnumerateCipherMetrics_EnsureMacPRFIsSet(t *testing.T) {
	for _, metric := range EnumerateCipherMetrics() {
		t.Run(metric.CipherConfig.Cipher, func(t *testing.T) {
			if metric.MacPRF == -1 {
				t.Errorf("MacPRF not computed for %s, %s", metric.CipherConfig.MACPRF, metric.CipherConfig.Encryption)
			}
		})
	}
}

func TestKeyExchangePerformance(t *testing.T) {
	conf := CipherConfigParameters{
		RSABitLength:           1024,
		SupportedGroupStrength: 1024,
	}
	for cipher, cipherName := range tlsdefs.CipherSuiteMap {
		t.Run(cipherName, func(t *testing.T) {
			if cc, _ := GetCipherConfig(cipher); cc.getKXPerf(conf) == -1 {
				t.Errorf("Key exchange performance = -1, when key exchange is %s", cc.KeyExchange)
			}
		})
	}
}

func TestAuthenticationPerformance(t *testing.T) {
	for cipher, cipherName := range tlsdefs.CipherSuiteMap {
		t.Run(cipherName, func(t *testing.T) {
			if cc, _ := GetCipherConfig(cipher); cc.getAuthPerf() == -1 {
				t.Errorf("Authentication performance = -1, when authentication is %s", cc.Authentication)
			}
		})
	}
}

func TestMACPRFPerformance(t *testing.T) {
	for cipher, cipherName := range tlsdefs.CipherSuiteMap {
		t.Run(cipherName, func(t *testing.T) {
			if cc, _ := GetCipherConfig(cipher); cc.getMACPRFPerf() == -1 {
				t.Errorf("MACPRF performance = -1, when MACPRF is %s", cc.MACPRF)
			}
		})
	}
}

func TestEncryptionAlgorithmPerformance(t *testing.T) {
	for cipher, cipherName := range tlsdefs.CipherSuiteMap {
		t.Run(cipherName, func(t *testing.T) {
			if cc, _ := GetCipherConfig(cipher); cc.getEncAlgPerf() == -1 {
				t.Errorf("Encryption Algorithm performance = -1, when Encryption Algorithm is %s", cc.getEncAlg())
			}
		})
	}
}

func TestEncryptionKeyPerformance(t *testing.T) {
	for cipher, cipherName := range tlsdefs.CipherSuiteMap {
		t.Run(cipherName, func(t *testing.T) {
			if cc, _ := GetCipherConfig(cipher); cc.getEncKeyPerf() == -1 {
				t.Errorf("Encryption Key performance = -1, when Encryption Key is %d", cc.GetEncryptionKeyLength())
			}
		})
	}
}

func TestEncryptionModePerformance(t *testing.T) {
	for cipher, cipherName := range tlsdefs.CipherSuiteMap {
		t.Run(cipherName, func(t *testing.T) {
			if cc, _ := GetCipherConfig(cipher); cc.getEncModePerf() == -1 {
				t.Errorf("Encryption Mode performance = -1, when encryption mode is %s", cc.getEncMode())
			}
		})
	}
}

func TestCalculateCypherPerformance(t *testing.T) {
	conf := CipherConfigParameters{
		RSABitLength:           1024,
		SupportedGroupStrength: 1024,
	}
	for cipher, cipherName := range tlsdefs.CipherSuiteMap {
		t.Run(cipherName, func(t *testing.T) {
			if cc, _ := GetCipherConfig(cipher); cc.getPerformanceMetric(conf) >= 0 {
				t.Errorf("Cypher suite performance < 0, with value %d", cc.getPerformanceMetric(conf))
			}
		})
	}
}
