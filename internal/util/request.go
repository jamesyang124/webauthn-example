package util

import (
	"net/http"

	"github.com/jamesyang124/webauthn-example/internal/weberror"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

// ConvertFastHTTPToHTTPRequest converts a fasthttp.RequestCtx to a net/http.Request.
func ConvertFastHTTPToHTTPRequest(ctx *fasthttp.RequestCtx, req *http.Request) (*http.Request, error) {
	var httpRequest http.Request
	err := fasthttpadaptor.ConvertRequest(ctx, &httpRequest, true)
	if err != nil {
		return nil, weberror.RequestConversionError(err).Log()
	}
	*req = httpRequest
	return req, nil
}
