package ssid

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Menu navigation: Home -> Local Network -> WLAN. The SSID on/off settings live on the WLAN page.
const (
	tagHome          = "home"
	tagLocalNetwork  = "localNetStatus"
	tagWlan          = "wlanBasic"
	tagSSIDData      = "wlan_wlansssidconf_lua.lua"
	ssidInstancePref = "DEV.WIFI.AP"
)

var (
	pageTokenRe  = regexp.MustCompile(`_sessionTmpToken\s*=\s*"([^"]*)"`)
	hexEscapeRe  = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	publicKeyRe  = regexp.MustCompile(`-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----`)
	instanceRe   = regexp.MustCompile(`(?s)<Instance>(.*?)</Instance>`)
	paramRe      = regexp.MustCompile(`(?s)<ParaName>(.*?)</ParaName>\s*<ParaValue>(.*?)</ParaValue>`)
	secretParams = regexp.MustCompile(`^(KeyPassphrase|MasterAuthServerSecret|WEPKey\d+)$`)
)

// ToggleSSIDs enables or disables the given SSID numbers (e.g. 1 and 5).
func ToggleSSIDs(client *http.Client, routerURL string, enable bool, ssids ...int) error {
	base := strings.TrimRight(routerURL, "/")

	pubKey, err := fetchPublicKey(client, base)
	if err != nil {
		return err
	}

	// Click through the menu like a browser would.
	for _, tag := range []string{tagHome, tagLocalNetwork} {
		if _, err := routerRequest(client, "GET", menuViewURL(base, tag), nil); err != nil {
			return fmt.Errorf("failed to open menu %q: %v", tag, err)
		}
	}

	for _, n := range ssids {
		if err := setSSID(client, base, pubKey, n, enable); err != nil {
			return fmt.Errorf("SSID%d: %v", n, err)
		}
		state := "disabled"
		if enable {
			state = "enabled"
		}
		fmt.Printf("SSID%d %s\n", n, state)
	}
	return nil
}

func setSSID(client *http.Client, base string, pubKey *rsa.PublicKey, n int, enable bool) error {
	dataURL := fmt.Sprintf("%s/?_type=menuData&_tag=%s", base, tagSSIDData)

	// The WLAN page carries a session token that is consumed by each apply, so reload it per SSID.
	page, err := routerRequest(client, "GET", menuViewURL(base, tagWlan), nil)
	if err != nil {
		return fmt.Errorf("failed to open WLAN page: %v", err)
	}
	tm := pageTokenRe.FindSubmatch(page)
	if tm == nil {
		return fmt.Errorf("could not extract session token")
	}
	token := hexEscapeRe.ReplaceAllStringFunc(string(tm[1]), func(s string) string {
		b, _ := strconv.ParseUint(s[2:], 16, 8)
		return string(rune(b))
	})

	data, err := routerRequest(client, "GET", dataURL, nil)
	if err != nil {
		return fmt.Errorf("failed to read SSID config: %v", err)
	}
	params, err := findInstance(string(data), fmt.Sprintf("%s%d", ssidInstancePref, n))
	if err != nil {
		return err
	}

	form := url.Values{}
	for k, v := range params {
		// Keep the instance id; drop other internal fields and encrypted secrets
		// (the router keeps the stored values when they are omitted).
		if (strings.HasPrefix(k, "_") && k != "_InstID") || secretParams.MatchString(k) {
			continue
		}
		form.Set(k, v)
	}
	if enable {
		form.Set("Enable", "1")
	} else {
		form.Set("Enable", "0")
	}
	form.Set("IF_ACTION", "Apply")
	form.Set("_sessionTOKEN", token)
	body := form.Encode()

	// Integrity header: RSA(sha256(body)). The router's web UI (JSEncrypt) only speaks
	// PKCS#1 v1.5, so OAEP is not an option here despite the deprecation.
	sum := sha256.Sum256([]byte(body))
	check, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(hex.EncodeToString(sum[:])))
	if err != nil {
		return fmt.Errorf("failed to build integrity header: %v", err)
	}

	req, err := http.NewRequest("POST", dataURL, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Check", base64.StdEncoding.EncodeToString(check))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send apply request: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK || !strings.Contains(string(out), "<IF_ERRORSTR>SUCC</IF_ERRORSTR>") {
		return fmt.Errorf("apply failed (HTTP %d): %s", resp.StatusCode, strings.Join(strings.Fields(string(out)), " "))
	}
	return nil
}

// fetchPublicKey reads the RSA public key the web UI embeds for its Check header.
func fetchPublicKey(client *http.Client, base string) (*rsa.PublicKey, error) {
	page, err := routerRequest(client, "GET", base+"/", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load router page: %v", err)
	}
	raw := publicKeyRe.Find(page)
	if raw == nil {
		return nil, fmt.Errorf("public key not found on router page")
	}
	// The key is embedded in a JS string, with literal "\n" separators.
	block, _ := pem.Decode([]byte(strings.ReplaceAll(string(raw), `\n`, "\n")))
	if block == nil {
		return nil, fmt.Errorf("failed to decode router public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse router public key: %v", err)
	}
	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("router public key is not RSA")
	}
	return key, nil
}

// findInstance returns the parameters of the instance whose _InstID is instID.
func findInstance(xmlData, instID string) (map[string]string, error) {
	for _, inst := range instanceRe.FindAllStringSubmatch(xmlData, -1) {
		params := make(map[string]string)
		for _, p := range paramRe.FindAllStringSubmatch(inst[1], -1) {
			params[strings.TrimSpace(p[1])] = html.UnescapeString(strings.TrimSpace(p[2]))
		}
		if params["_InstID"] == instID {
			return params, nil
		}
	}
	return nil, fmt.Errorf("instance %s not found in router response", instID)
}

func menuViewURL(base, tag string) string {
	return fmt.Sprintf("%s/?_type=menuView&_tag=%s&Menu3Location=0", base, tag)
}
