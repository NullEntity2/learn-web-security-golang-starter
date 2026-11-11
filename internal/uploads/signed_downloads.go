package uploads

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const signedDownloadTTL = 5 * time.Minute

func CreateSignedDownloadPath(signingKey [32]byte, fileID int64, now time.Time) string {
	expires := now.Unix() + int64(signedDownloadTTL.Seconds())
	signature := signDownload(signingKey, fileID, expires)
	return fmt.Sprintf("/files/%d/signed-download?expires=%d&signature=%s", fileID, expires, signature)
}

func VerifySignedDownload(signingKey [32]byte, fileID int64, expiresValue, signature string, now time.Time) bool {
	if expiresValue == "" || strings.Trim(expiresValue, "0123456789") != "" || len(signature) != 64 {
		return false
	}
	expires, err := strconv.ParseInt(expiresValue, 10, 64)
	if err != nil {
		return false
	}
	if expires <= now.Unix() {
		return false
	}

	expected, err := hex.DecodeString(signDownload(signingKey, fileID, expires))
	if err != nil {
		return false
	}
	received, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, received)
}

func signDownload(signingKey [32]byte, fileID, expiresAt int64) string {
	mac := hmac.New(sha256.New, signingKey[:])
	msg := fmt.Sprintf("GET\nfiles/%d/signed-download\n%d", fileID, expiresAt)
	mac.Write([]byte(msg))
	expectedMac := mac.Sum(nil)
	return hex.EncodeToString(expectedMac)
}
