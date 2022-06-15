package auth

import (
	"fmt"
	"os"
	"time"

	"github.com/GoAdminGroup/go-admin/modules/config"
	"github.com/golang-jwt/jwt/v4"
)

//jwt service
type JWTService interface {
	GenerateToken(username string) string
	ValidateToken(token string) (*jwt.Token, error)
}
type authCustomClaims struct {
	Name string `json:"name"`
	jwt.RegisteredClaims
}

type jwtServices struct {
	secretKey string
	issuer    string
}

//auth-jwt
func JWTAuthService() JWTService {
	return &jwtServices{
		secretKey: getSecretKey(),
		issuer:    "Group8",
	}
}

func getSecretKey() string {
	secret := os.Getenv("Secret")
	if secret == "" {
		secret = "secret"
	}
	return secret
}

// Generates a JWT token
func (service *jwtServices) GenerateToken(username string) string {

	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	claims := &authCustomClaims{
		username,
		jwt.RegisteredClaims{
			Issuer: service.issuer,
			// ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 48)),
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Duration(config.GetSessionLifeTime()) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(service.secretKey))
	if err != nil {
		panic(err)
	}
	return tokenString
}

// Validates a JWT token
func (service *jwtServices) ValidateToken(encodedToken string) (*jwt.Token, error) {
	return jwt.Parse(encodedToken, func(token *jwt.Token) (interface{}, error) {
		if _, isvalid := token.Method.(*jwt.SigningMethodHMAC); !isvalid {
			return nil, fmt.Errorf("invalid token %s", token.Header["alg"])

		}
		return []byte(service.secretKey), nil
	})

}
