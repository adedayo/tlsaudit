package tlsmodel

func score2009p(s *ScanResult) (result SecurityScore) {
	if s.SupportsTLS() {
		result = computeBasicScore(s)
		adjustScore2009p(&result, *s)
	} else {
		//No TLS
		result.Grade = toTLSGrade(-1, strengthMetadata{})
	}
	return
}

func score2009q(s *ScanResult) (result SecurityScore) {
	if s.SupportsTLS() {
		result = computeBasicScore(s)
		adjustScore2009q(&result, *s)
	} else {
		//No TLS
		result.Grade = toTLSGrade(-1, strengthMetadata{})
	}
	return
}

//computeBasicScore tries to mimic SSLLabs scoring system (although the algorithm description is not really clear).
//see https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
//the following is the interpretation:
//protocol score = (max_protocol_score + min_protocol_score)/2
//key exchange score = (max_keyExchange_score + min_keyExchange_score)/2 <- this piece is not well-specified
//cipher strength score = (max_cipher_strength_score + min_cipher_strength_score)/2
//Basic score = 30% protocol score + 30% key exchange score + 40% cipher strength score
func computeBasicScore(s *ScanResult) (result SecurityScore) {
	max := uint16(0)
	min := uint16(1000)
	for _, p := range s.SupportedProtocols {
		if p > max {
			max = p
		}
		if p < min {
			min = p
		}
	}

	highProtocol := scoreProtocol(max)
	lowProtocol := scoreProtocol(min)

	result.ProtocolScore = (highProtocol + lowProtocol) / 2

	keyExchangeMinScore := 1000
	keyExchangeMaxScore := 0
	cipherStrengthMinScore := 1000
	cipherStrengthMaxScore := 0
	// for _, p := range s.SupportedProtocols {
	p := s.SupportedProtocols[0] // use the strongest protocol
	var cipherSuite []uint16
	if s.HasCipherPreferenceOrderByProtocol[p] {
		cipherSuite = s.CipherPreferenceOrderByProtocol[p]
	} else {
		cipherSuite = s.CipherSuiteByProtocol[p]
	}
	for _, c := range cipherSuite {
		selectMinimalKeyExchangeScore(c, p, &keyExchangeMinScore, &keyExchangeMaxScore, &cipherStrengthMinScore, &cipherStrengthMaxScore, *s)
	}
	// }

	result.KeyExchangeScore = (keyExchangeMaxScore + keyExchangeMinScore) / 2

	result.CipherEncryptionScore = (cipherStrengthMaxScore + cipherStrengthMinScore) / 2
	var meta strengthMetadata
	if result.ProtocolScore*result.KeyExchangeScore*result.CipherEncryptionScore == 0 {
		//if any of the three protocol, key exchange or cipher encryption score is zero, then zero the result
		result.Grade = toTLSGrade(0, meta)
	} else {
		result.Grade = toTLSGrade((30*result.ProtocolScore+30*result.KeyExchangeScore+40*result.CipherEncryptionScore)/100, meta)
	}

	scoreCertificate(&result, s)
	return
}
