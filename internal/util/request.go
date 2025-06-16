package util

import (
	"net/http"

	"github.com/jamesyang124/webauthn-example/types"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

// ConvertFastHTTPToHTTPRequest converts a fasthttp.RequestCtx to a net/http.Request.
func ConvertFastHTTPToHTTPRequest(ctx *fasthttp.RequestCtx) (*http.Request, error) {
	var httpRequest http.Request
	err := fasthttpadaptor.ConvertRequest(ctx, &httpRequest, true)
	if err != nil {
		types.RespondWithError(
			ctx,
			fasthttp.StatusInternalServerError,
			`{"error": "Failed to convert request"}`,
			"Error converting fasthttp request",
			err,
		)
		return nil, err
	}
	return &httpRequest, nil
}
