// package auth

// import (
// 	"errors"
// 	"time"

// 	"github.com/golang-jwt/jwt/v4"
// 	"github.com/google/uuid"
// )

// // TokenClaims representa los datos incluidos en el token JWT básico
// type TokenClaims struct {
// 	UserID    string `json:"userId"`
// 	DNI       string `json:"dni"`
// 	Email     string `json:"email"`
// 	jwt.RegisteredClaims
// }



// // TokenClaimsWithEmpresa representa los datos incluidos en el token JWT con empresa específica
// type TokenClaimsWithEmpresa struct {
// 	UserID    string `json:"userId"`
// 	DNI       string `json:"dni"`
// 	Email     string `json:"email"`
// 	EmpresaID string `json:"empresaId,omitempty"` // Campo adicional para empresa
// 	jwt.RegisteredClaims
// }

// // JWTService proporciona métodos para trabajar con tokens JWT
// type JWTService struct {
// 	secretKey  []byte
// 	expiration time.Duration
// }

// // NewJWTService crea una nueva instancia del servicio JWT
// func NewJWTService(secretKey string, expiration time.Duration) *JWTService {
// 	return &JWTService{
// 		secretKey:  []byte(secretKey),
// 		expiration: expiration,
// 	}
// }

// // GenerateToken genera un nuevo token JWT básico para un usuario
// func (s *JWTService) GenerateToken(claims *TokenClaims) (string, error) {
// 	expirationTime := time.Now().Add(s.expiration)

// 	claims.RegisteredClaims = jwt.RegisteredClaims{
// 		ExpiresAt: jwt.NewNumericDate(expirationTime),
// 		IssuedAt:  jwt.NewNumericDate(time.Now()),
// 		NotBefore: jwt.NewNumericDate(time.Now()),
// 	}

// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenString, err := token.SignedString(s.secretKey)

// 	if err != nil {
// 		return "", err
// 	}

// 	return tokenString, nil
// }

// // GenerateTokenWithEmpresa genera un nuevo token JWT con empresa específica
// func (s *JWTService) GenerateTokenWithEmpresa(claims *TokenClaimsWithEmpresa) (string, error) {
// 	expirationTime := time.Now().Add(s.expiration)

// 	claims.RegisteredClaims = jwt.RegisteredClaims{
// 		ExpiresAt: jwt.NewNumericDate(expirationTime),
// 		IssuedAt:  jwt.NewNumericDate(time.Now()),
// 		NotBefore: jwt.NewNumericDate(time.Now()),
// 	}

// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenString, err := token.SignedString(s.secretKey)

// 	if err != nil {
// 		return "", err
// 	}

// 	return tokenString, nil
// }

// // ValidateToken valida un token JWT básico y devuelve los claims
// func (s *JWTService) ValidateToken(tokenString string) (*TokenClaims, error) {
// 	claims := &TokenClaims{}

// 	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, errors.New("método de firma inesperado")
// 		}
// 		return s.secretKey, nil
// 	})

// 	if err != nil {
// 		return nil, err
// 	}

// 	if !token.Valid {
// 		return nil, errors.New("token inválido")
// 	}

// 	return claims, nil
// }

// // ValidateTokenWithEmpresa valida un token JWT con empresa y devuelve los claims
// func (s *JWTService) ValidateTokenWithEmpresa(tokenString string) (*TokenClaimsWithEmpresa, error) {
// 	claims := &TokenClaimsWithEmpresa{}

// 	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, errors.New("método de firma inesperado")
// 		}
// 		return s.secretKey, nil
// 	})

// 	if err != nil {
// 		return nil, err
// 	}

// 	if !token.Valid {
// 		return nil, errors.New("token inválido")
// 	}

// 	return claims, nil
// }

// // ValidateAnyToken intenta validar un token como básico o con empresa
// func (s *JWTService) ValidateAnyToken(tokenString string) (interface{}, error) {
// 	// Primero intentar como token básico
// 	basicClaims, err := s.ValidateToken(tokenString)
// 	if err == nil {
// 		return basicClaims, nil
// 	}

// 	// Si falla, intentar como token con empresa
// 	empresaClaims, err := s.ValidateTokenWithEmpresa(tokenString)
// 	if err == nil {
// 		return empresaClaims, nil
// 	}

// 	return nil, errors.New("token inválido o formato no reconocido")
// }

// // RefreshToken genera un nuevo token a partir de uno existente
// func (s *JWTService) RefreshToken(tokenString string) (string, error) {
//     claims, err := s.ValidateToken(tokenString)
//     if err != nil {
//         return "", err
//     }

//     // Comprobar si el token está próximo a expirar
//     var expirationTime time.Time
//     if claims.RegisteredClaims.ExpiresAt != nil {
//         expirationTime = claims.RegisteredClaims.ExpiresAt.Time
//     } else {
//         expirationTime = time.Now()
//     }
    
//     now := time.Now()

//     // Si el token expira en menos de 12 horas, generamos uno nuevo
//     if expirationTime.Sub(now) < 12*time.Hour {
//         return s.GenerateToken(claims)
//     }

//     return tokenString, nil
// }

// // RefreshTokenWithEmpresa genera un nuevo token con empresa a partir de uno existente
// func (s *JWTService) RefreshTokenWithEmpresa(tokenString string) (string, error) {
//     claims, err := s.ValidateTokenWithEmpresa(tokenString)
//     if err != nil {
//         return "", err
//     }

//     var expirationTime time.Time
//     if claims.RegisteredClaims.ExpiresAt != nil {
//         expirationTime = claims.RegisteredClaims.ExpiresAt.Time
//     } else {
//         expirationTime = time.Now()
//     }
    
//     now := time.Now()

//     if expirationTime.Sub(now) < 12*time.Hour {
//         return s.GenerateTokenWithEmpresa(claims)
//     }

//     return tokenString, nil
// }

// // GetUserIDFromToken extrae el ID de usuario de un token
// func (s *JWTService) GetUserIDFromToken(tokenString string) (uuid.UUID, error) {
// 	claims, err := s.ValidateToken(tokenString)
// 	if err != nil {
// 		return uuid.Nil, err
// 	}

// 	return uuid.Parse(claims.UserID)
// }

// // GetUserIDFromAnyToken extrae el ID de usuario de cualquier tipo de token
// func (s *JWTService) GetUserIDFromAnyToken(tokenString string) (uuid.UUID, error) {
// 	result, err := s.ValidateAnyToken(tokenString)
// 	if err != nil {
// 		return uuid.Nil, err
// 	}

// 	switch claims := result.(type) {
// 	case *TokenClaims:
// 		return uuid.Parse(claims.UserID)
// 	case *TokenClaimsWithEmpresa:
// 		return uuid.Parse(claims.UserID)
// 	default:
// 		return uuid.Nil, errors.New("tipo de token no reconocido")
// 	}
// }

// // GetEmpresaIDFromToken extrae el ID de empresa de un token (solo si es TokenClaimsWithEmpresa)
// func (s *JWTService) GetEmpresaIDFromToken(tokenString string) (uuid.UUID, error) {
// 	claims, err := s.ValidateTokenWithEmpresa(tokenString)
// 	if err != nil {
// 		return uuid.Nil, err
// 	}

// 	if claims.EmpresaID == "" {
// 		return uuid.Nil, errors.New("token no contiene información de empresa")
// 	}

// 	return uuid.Parse(claims.EmpresaID)
// }

// // GetDNIFromToken extrae el DNI de un token
// func (s *JWTService) GetDNIFromToken(tokenString string) (string, error) {
// 	claims, err := s.ValidateToken(tokenString)
// 	if err != nil {
// 		return "", err
// 	}

// 	return claims.DNI, nil
// }

// // GetDNIFromAnyToken extrae el DNI de cualquier tipo de token
// func (s *JWTService) GetDNIFromAnyToken(tokenString string) (string, error) {
// 	result, err := s.ValidateAnyToken(tokenString)
// 	if err != nil {
// 		return "", err
// 	}

// 	switch claims := result.(type) {
// 	case *TokenClaims:
// 		return claims.DNI, nil
// 	case *TokenClaimsWithEmpresa:
// 		return claims.DNI, nil
// 	default:
// 		return "", errors.New("tipo de token no reconocido")
// 	}
// }

// // GetEmailFromToken extrae el email de un token
// func (s *JWTService) GetEmailFromToken(tokenString string) (string, error) {
// 	claims, err := s.ValidateToken(tokenString)
// 	if err != nil {
// 		return "", err
// 	}

// 	return claims.Email, nil
// }

// // GetEmailFromAnyToken extrae el email de cualquier tipo de token
// func (s *JWTService) GetEmailFromAnyToken(tokenString string) (string, error) {
// 	result, err := s.ValidateAnyToken(tokenString)
// 	if err != nil {
// 		return "", err
// 	}

// 	switch claims := result.(type) {
// 	case *TokenClaims:
// 		return claims.Email, nil
// 	case *TokenClaimsWithEmpresa:
// 		return claims.Email, nil
// 	default:
// 		return "", errors.New("tipo de token no reconocido")
// 	}
// }

// // IsTokenWithEmpresa verifica si un token contiene información de empresa
// func (s *JWTService) IsTokenWithEmpresa(tokenString string) bool {
// 	_, err := s.ValidateTokenWithEmpresa(tokenString)
// 	return err == nil
// }

// // GetTokenInfo obtiene información completa de cualquier tipo de token
// func (s *JWTService) GetTokenInfo(tokenString string) (map[string]interface{}, error) {
// 	result, err := s.ValidateAnyToken(tokenString)
// 	if err != nil {
// 		return nil, err
// 	}

// 	info := make(map[string]interface{})

// 	switch claims := result.(type) {
// 	case *TokenClaims:
// 		info["type"] = "basic"
// 		info["userId"] = claims.UserID
// 		info["dni"] = claims.DNI
// 		info["email"] = claims.Email
// 		info["hasEmpresa"] = false
// 		if claims.ExpiresAt != nil {
// 			info["expiresAt"] = claims.ExpiresAt.Time
// 		}
// 	case *TokenClaimsWithEmpresa:
// 		info["type"] = "with_empresa"
// 		info["userId"] = claims.UserID
// 		info["dni"] = claims.DNI
// 		info["email"] = claims.Email
// 		info["empresaId"] = claims.EmpresaID
// 		info["hasEmpresa"] = true
// 		if claims.ExpiresAt != nil {
// 			info["expiresAt"] = claims.ExpiresAt.Time
// 		}
// 	}

// 	return info, nil
// }

// jwt_service.go
package auth

import (
    "errors"
    "time"

    "github.com/golang-jwt/jwt/v4"
    "github.com/google/uuid"
)

// TokenClaims representa los datos incluidos en el token JWT
type TokenClaims struct {
    UserID    string `json:"userId"`
    DNI       string `json:"dni"`
    Email     string `json:"email"`
    EmpresaID string `json:"empresaId,omitempty"` // Campo opcional
    jwt.RegisteredClaims
}

// TokenClaimsWithEmpresa es un alias de TokenClaims para compatibilidad temporal
type TokenClaimsWithEmpresa = TokenClaims

// JWTService proporciona métodos para trabajar con tokens JWT
type JWTService struct {
    secretKey  []byte
    expiration time.Duration
}

// NewJWTService crea una nueva instancia del servicio JWT
func NewJWTService(secretKey string, expiration time.Duration) *JWTService {
    return &JWTService{
        secretKey:  []byte(secretKey),
        expiration: expiration,
    }
}

// GenerateToken genera un nuevo token JWT
func (s *JWTService) GenerateToken(claims *TokenClaims) (string, error) {
    expirationTime := time.Now().Add(s.expiration)

    claims.RegisteredClaims = jwt.RegisteredClaims{
        ExpiresAt: jwt.NewNumericDate(expirationTime),
        IssuedAt:  jwt.NewNumericDate(time.Now()),
        NotBefore: jwt.NewNumericDate(time.Now()),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(s.secretKey)

    if err != nil {
        return "", err
    }

    return tokenString, nil
}

// GenerateTokenWithEmpresa genera un nuevo token JWT con empresa específica (usa el mismo tipo)
func (s *JWTService) GenerateTokenWithEmpresa(claims *TokenClaims) (string, error) {
    return s.GenerateToken(claims) // Reutiliza GenerateToken
}

// ValidateToken valida un token JWT y devuelve los claims
func (s *JWTService) ValidateToken(tokenString string) (*TokenClaims, error) {
    claims := &TokenClaims{}

    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("método de firma inesperado")
        }
        return s.secretKey, nil
    })

    if err != nil {
        return nil, err
    }

    if !token.Valid {
        return nil, errors.New("token inválido")
    }

    return claims, nil
}

// ValidateTokenWithEmpresa valida un token JWT con empresa (usa el mismo tipo)
func (s *JWTService) ValidateTokenWithEmpresa(tokenString string) (*TokenClaims, error) {
    return s.ValidateToken(tokenString) // Reutiliza ValidateToken
}

// ValidateAnyToken intenta validar un token como básico o con empresa
func (s *JWTService) ValidateAnyToken(tokenString string) (interface{}, error) {
    claims, err := s.ValidateToken(tokenString)
    if err == nil {
        return claims, nil
    }
    return nil, errors.New("token inválido o formato no reconocido")
}

// RefreshToken genera un nuevo token a partir de uno existente
func (s *JWTService) RefreshToken(tokenString string) (string, error) {
    claims, err := s.ValidateToken(tokenString)
    if err != nil {
        return "", err
    }

    var expirationTime time.Time
    if claims.ExpiresAt != nil {
        expirationTime = claims.ExpiresAt.Time
    } else {
        expirationTime = time.Now()
    }
    
    now := time.Now()

    if expirationTime.Sub(now) < 12*time.Hour {
        return s.GenerateToken(claims)
    }

    return tokenString, nil
}

// RefreshTokenWithEmpresa genera un nuevo token con empresa a partir de uno existente
func (s *JWTService) RefreshTokenWithEmpresa(tokenString string) (string, error) {
    return s.RefreshToken(tokenString) // Reutiliza RefreshToken
}

// GetUserIDFromToken extrae el ID de usuario de un token
func (s *JWTService) GetUserIDFromToken(tokenString string) (uuid.UUID, error) {
    claims, err := s.ValidateToken(tokenString)
    if err != nil {
        return uuid.Nil, err
    }

    return uuid.Parse(claims.UserID)
}

// GetUserIDFromAnyToken extrae el ID de usuario de cualquier tipo de token
func (s *JWTService) GetUserIDFromAnyToken(tokenString string) (uuid.UUID, error) {
    claims, err := s.ValidateToken(tokenString)
    if err != nil {
        return uuid.Nil, err
    }
    return uuid.Parse(claims.UserID)
}

// GetEmpresaIDFromToken extrae el ID de empresa de un token
func (s *JWTService) GetEmpresaIDFromToken(tokenString string) (uuid.UUID, error) {
    claims, err := s.ValidateToken(tokenString)
    if err != nil {
        return uuid.Nil, err
    }

    if claims.EmpresaID == "" {
        return uuid.Nil, errors.New("token no contiene información de empresa")
    }

    return uuid.Parse(claims.EmpresaID)
}

// GetDNIFromToken extrae el DNI de un token
func (s *JWTService) GetDNIFromToken(tokenString string) (string, error) {
    claims, err := s.ValidateToken(tokenString)
    if err != nil {
        return "", err
    }

    return claims.DNI, nil
}

// GetDNIFromAnyToken extrae el DNI de cualquier tipo de token
func (s *JWTService) GetDNIFromAnyToken(tokenString string) (string, error) {
    claims, err := s.ValidateToken(tokenString)
    if err != nil {
        return "", err
    }
    return claims.DNI, nil
}

// GetEmailFromToken extrae el email de un token
func (s *JWTService) GetEmailFromToken(tokenString string) (string, error) {
    claims, err := s.ValidateToken(tokenString)
    if err != nil {
        return "", err
    }

    return claims.Email, nil
}

// GetEmailFromAnyToken extrae el email de cualquier tipo de token
func (s *JWTService) GetEmailFromAnyToken(tokenString string) (string, error) {
    claims, err := s.ValidateToken(tokenString)
    if err != nil {
        return "", err
    }
    return claims.Email, nil
}

// IsTokenWithEmpresa verifica si un token contiene información de empresa
func (s *JWTService) IsTokenWithEmpresa(tokenString string) bool {
    claims, err := s.ValidateToken(tokenString)
    return err == nil && claims.EmpresaID != ""
}

// GetTokenInfo obtiene información completa de un token
func (s *JWTService) GetTokenInfo(tokenString string) (map[string]interface{}, error) {
    claims, err := s.ValidateToken(tokenString)
    if err != nil {
        return nil, err
    }

    info := make(map[string]interface{})
    info["type"] = "basic"
    info["userId"] = claims.UserID
    info["dni"] = claims.DNI
    info["email"] = claims.Email
    info["hasEmpresa"] = claims.EmpresaID != ""
    if claims.EmpresaID != "" {
        info["empresaId"] = claims.EmpresaID
        info["type"] = "with_empresa"
    }
    if claims.ExpiresAt != nil {
        info["expiresAt"] = claims.ExpiresAt.Time
    }

    return info, nil
}