package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Jwt struct {
	Secret string
}

func (j Jwt) CreateTokenStr(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signingKey := []byte(j.Secret)
	ss, err := signedString(signingKey, token)
	if err != nil {
		slog.Error("Failed sign JWT Claim string!", "err", err)
		return "", err
	}
	return ss, nil
}

// SignedString creates and returns a complete, signed JWT.
// The token is signed using the SigningMethod specified in the token.
func signedString(key interface{}, t *jwt.Token) (string, error) {
	var sstr string
	var sig []byte
	var err error
	if sstr, err = signingString(t); err != nil {
		return "", err
	}
	sig, err = t.Method.Sign(sstr, key)
	if err != nil {
		return "", err
	}
	encodedSig := base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join([]string{sstr, encodedSig}, "."), nil
}

// SigningString generates the signing string.  This is the
// most expensive part of the whole deal.  Unless you
// need this for something special, just go straight for
// the SignedString.
func signingString(t *jwt.Token) (string, error) {
	var err error
	var jsonValue []byte

	if jsonValue, err = json.Marshal(t.Header); err != nil {
		return "", err
	}
	header := encodeSegment(jsonValue)

	if jsonValue, err = json.Marshal(t.Claims); err != nil {
		return "", err
	}
	claim := encodeSegment(jsonValue)

	return strings.Join([]string{header, claim}, "."), nil
}

func encodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}

type Token struct {
	AccessToken  string
	RefreshToken string
}
type Claims struct {
	CustomClaims interface{} `json:"custom_claims,inline"`
	jwt.RegisteredClaims
}

func (j Jwt) CreateToken(user string) (Token, error) {
	accessToken, err := j.CreateAccessToken(user)
	if err != nil {
		slog.Error("Failed create access token!", "err", err)
		return Token{}, err
	}
	refreshToken, err := j.CreateRefreshToken(user)
	if err != nil {
		slog.Error("Failed create refresh token!", "err", err)
		return Token{}, err
	}
	return Token{
		AccessToken:  accessToken.Token,
		RefreshToken: refreshToken.Token,
	}, nil
}

func (j Jwt) ParseTokenStr(tokenStr string) (*jwt.Token, error) {
	signingKey := []byte(j.Secret)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil {
		slog.Error("Failed parse JWT string!", "err", err)
		return token, err
	}
	claims := token.Claims.(jwt.MapClaims)
	customClaims := new(Claims)
	err = LoadFromMap(customClaims, claims)
	if err == nil && token.Valid {
		return token, nil
	}
	slog.Error("Failed parse token claims!", "err", err)
	return token, errors.New("failed_parse_token_claims")
}

func LoadFromMap[T any](c *T, m map[string]interface{}) error {
	data, err := json.Marshal(m)
	if err == nil {
		err = json.Unmarshal(data, c)
	}
	return err
}

type IdmToken struct {
	Token  string
	Expiry time.Time
}

func (j Jwt) CreateAccessToken(claimData interface{}) (IdmToken, error) {
	claims := Claims{
		claimData,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC().Add(-time.Minute * 5)),
			Issuer:    "simple-idm",
			Subject:   "simple-idm",
			ID:        uuid.New().String(),
			Audience:  []string{"public"},
		},
	}
	accessToken, err := j.CreateTokenStr(claims)
	return IdmToken{Token: accessToken, Expiry: claims.ExpiresAt.Time}, err
}

func (j Jwt) CreateRefreshToken(claimData interface{}) (IdmToken, error) {
	claims := Claims{
		claimData,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC().Add(-time.Minute * 5)),
			Issuer:    "simple-idm",
			Subject:   "simple-idm",
			ID:        uuid.New().String(),
			Audience:  []string{"public"},
		},
	}
	refreshToken, err := j.CreateTokenStr(claims)
	return IdmToken{Token: refreshToken, Expiry: claims.ExpiresAt.Time}, err
}

func (j Jwt) CreatePasswordResetToken(claimData interface{}) (string, error) {
	claims := Claims{
		claimData,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(30 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC().Add(-time.Minute * 5)),
			Issuer:    "simple-idm",
			Subject:   "simple-idm",
			ID:        uuid.New().String(),
			Audience:  []string{"public"},
		},
	}
	pwdResetToken, err := j.CreateTokenStr(claims)
	return pwdResetToken, err
}
