package resthelper

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/myimilo/resthelper/errorx"
)

func OkJson(w http.ResponseWriter, v any) {
	doWriteJson(w, http.StatusOK, v)
}

func ErrorJson(w http.ResponseWriter, err error) {
	if errx, ok := err.(*errorx.Error); ok {
		doWriteJson(w, errx.Code, errorx.ErrorResponse{Error: *errx})
	} else {
		doWriteJson(w, http.StatusInternalServerError, errorx.ErrorResponse{Error: errorx.Error{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		}})
	}
}

func doWriteJson(w http.ResponseWriter, code int, v any) error {
	bs, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return fmt.Errorf("marshal json failed, error: %w", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	if n, err := w.Write(bs); err != nil {
		return fmt.Errorf("write response failed, error: %w", err)
	} else if n < len(bs) {
		return fmt.Errorf("actual bytes: %d, written bytes: %d", len(bs), n)
	}

	return nil
}
