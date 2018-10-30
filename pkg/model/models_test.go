package tlsmodel

import (
	"reflect"
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
				MAC:            "SHA384",
			},
			wantErr: false,
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

func TestIANACiphersNotErroing(t *testing.T) {
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
