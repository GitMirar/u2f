package u2f

import (
	"os"
	"testing"
)

func TestGenerateCertificate(t *testing.T) {
	if err := GenerateCertificate("localhost, 127.0.0.1", "TestOrg", "testcert.pem", "testkey.pem"); err != nil {
		t.Errorf("failed to generate a certificate due to %v", err)
	}
	_ = os.Remove("testcert.pem")
	_ = os.Remove("testkey.pem")
}
