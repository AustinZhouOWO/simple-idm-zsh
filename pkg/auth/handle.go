package auth

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/render"
	"github.com/tendant/simple-idm/auth"
	"github.com/tendant/simple-idm/pkg/login"
)

type Handle struct {
	jwtService       auth.Jwt
	authLoginService *AuthLoginService
}

func NewHandle(jwtService auth.Jwt, service *AuthLoginService) Handle {
	return Handle{
		jwtService:       jwtService,
		authLoginService: service,
	}
}

func (h Handle) setTokenCookie(w http.ResponseWriter, tokenName, tokenValue string, expire time.Time) {
	tokenCookie := &http.Cookie{
		Name:     tokenName,
		Path:     "/",
		Value:    tokenValue,
		Expires:  expire,
		HttpOnly: true,                 // Make the cookie HttpOnly
		Secure:   true,                 // Ensure it’s sent over HTTPS
		SameSite: http.SameSiteLaxMode, // Prevent CSRF
	}

	http.SetCookie(w, tokenCookie)
}

func (h Handle) PostToken(w http.ResponseWriter, r *http.Request) *Response {
	var (
		response SuccessResponse
	)

	authUser, ok := r.Context().Value(login.AuthUserKey).(*login.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

	accessToken, err := h.jwtService.CreateAccessToken(authUser)
	if err != nil {
		slog.Error("Failed to create access token", "user", authUser, "err", err)
		return &Response{
			body: "Failed to create access token",
			Code: http.StatusInternalServerError,
		}
	}

	refreshToken, err := h.jwtService.CreateRefreshToken(authUser)
	if err != nil {
		slog.Error("Failed to create refresh token", "user", authUser, "err", err)
		return &Response{
			body: "Failed to create refresh token",
			Code: http.StatusInternalServerError,
		}
	}

	h.setTokenCookie(w, login.ACCESS_TOKEN_NAME, accessToken.Token, accessToken.Expiry)
	h.setTokenCookie(w, login.REFRESH_TOKEN_NAME, refreshToken.Token, refreshToken.Expiry)

	response.Result = "success"
	return PostTokenJSON200Response(response)
}

func (h Handle) PutPassword(w http.ResponseWriter, r *http.Request) *Response {
	var (
		response SuccessResponse
	)
	data := PutPasswordJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "Unable to parse request body",
		}
	}
	authUser, ok := r.Context().Value(login.AuthUserKey).(*login.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}
	// check password match
	passMatch, err := h.authLoginService.MatchPasswordByUuids(r.Context(), MatchPassParam{
		UserUuid: authUser.UserUUID,
		Password: data.CurrentPassword,
	})
	if err != nil {
		slog.Error("Failed to match password by user uuid", "user uuid", authUser.UserUUID, "err", err)
		return &Response{
			body: "Internal system error",
			Code: http.StatusInternalServerError,
		}
	} else if !passMatch {
		slog.Warn("Password not match", "user uuid", authUser.UserUUID)
		return &Response{
			body: "Bad request",
			Code: http.StatusBadRequest, // prevent info leakage
		}
	}
	// check password complexity
	err = h.authLoginService.VerifyPasswordComplexity(r.Context(), data.NewPassword)
	if err != nil {
		slog.Warn("Password complexity check failed", "err", err)
		return &Response{
			body: err.Error(),
			Code: http.StatusBadRequest,
		}
	}
	// update password
	err = h.authLoginService.UpdatePassword(r.Context(), UpdatePassParam{
		UserUuid:    authUser.UserUUID,
		NewPassword: data.NewPassword,
	})
	if err != nil {
		slog.Error("Failed to update user password", "user uuid", authUser.UserUUID, "err", err)
		return &Response{
			body: "Internal system error",
			Code: http.StatusInternalServerError,
		}
	}
	response.Result = "success"
	return PutPasswordJSON200Response(response)
}
