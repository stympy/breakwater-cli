package images

import (
	"errors"
	"net/http"
	"testing"

	ggcrtransport "github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

func TestRateLimitErrorKeepsTheRegistryError(t *testing.T) {
	inner := &ggcrtransport.Error{StatusCode: http.StatusTooManyRequests}
	err := error(&RateLimitError{msg: "docker.io rate-limited this anonymous pull", err: inner})

	var terr *ggcrtransport.Error
	if !errors.As(err, &terr) || terr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("errors.As lost the registry error: %v", err)
	}
	if err.Error() != "docker.io rate-limited this anonymous pull" {
		t.Fatalf("message = %q", err.Error())
	}
}
