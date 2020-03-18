package tlsmodel

func score2009p(s *ScanResult) (result SecurityScore) {

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

	if s.SupportsTLS() {

		cipherKeyExchangeScore := 1000
		cipherStrengthMinScore := 1000
		cipherStrengthMaxScore := 0
		// for _, p := range s.SupportedProtocols {
		p := s.SupportedProtocols[0] // use the strongest protocol
		c := s.SelectedCipherByProtocol[p]
		selectMinimalKeyExchangeScore(c, p, &cipherKeyExchangeScore, &cipherStrengthMinScore, &cipherStrengthMaxScore, *s)
		var cipherSuite []uint16
		if s.HasCipherPreferenceOrderByProtocol[p] {
			cipherSuite = s.CipherPreferenceOrderByProtocol[p]
		} else {
			cipherSuite = s.CipherSuiteByProtocol[p]
		}
		for _, c := range cipherSuite {
			selectMinimalKeyExchangeScore(c, p, &cipherKeyExchangeScore, &cipherStrengthMinScore, &cipherStrengthMaxScore, *s)
		}
		// }

		result.KeyExchangeScore = cipherKeyExchangeScore

		result.CipherEncryptionScore = (cipherStrengthMaxScore + cipherStrengthMinScore) / 2

		result.Grade = toTLSGrade((30*result.ProtocolScore + 30*result.KeyExchangeScore + 40*result.CipherEncryptionScore) / 100)

		scoreCertificate(&result, s)
		result.adjustScore2009p(*s)
	} else {
		//No TLS
		result.Grade = toTLSGrade(-1)
	}
	return
}

func score2009q(s *ScanResult) (result SecurityScore) {

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

	if s.SupportsTLS() {

		cipherKeyExchangeScore := 1000
		cipherStrengthMinScore := 1000
		cipherStrengthMaxScore := 0
		// for _, p := range s.SupportedProtocols {
		p := s.SupportedProtocols[0] // use the strongest protocol
		c := s.SelectedCipherByProtocol[p]
		selectMinimalKeyExchangeScore(c, p, &cipherKeyExchangeScore, &cipherStrengthMinScore, &cipherStrengthMaxScore, *s)
		var cipherSuite []uint16
		if s.HasCipherPreferenceOrderByProtocol[p] {
			cipherSuite = s.CipherPreferenceOrderByProtocol[p]
		} else {
			cipherSuite = s.CipherSuiteByProtocol[p]
		}
		for _, c := range cipherSuite {
			selectMinimalKeyExchangeScore(c, p, &cipherKeyExchangeScore, &cipherStrengthMinScore, &cipherStrengthMaxScore, *s)
		}
		// }

		result.KeyExchangeScore = cipherKeyExchangeScore

		result.CipherEncryptionScore = (cipherStrengthMaxScore + cipherStrengthMinScore) / 2

		result.Grade = toTLSGrade((30*result.ProtocolScore + 30*result.KeyExchangeScore + 40*result.CipherEncryptionScore) / 100)

		scoreCertificate(&result, s)
		result.adjustScore2009q(*s)
	} else {
		//No TLS
		result.Grade = toTLSGrade(-1)
	}
	return
}
