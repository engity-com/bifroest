package environment

import (
	"encoding/json"
	"io"
	"iter"
	"strings"

	"github.com/docker/docker/pkg/jsonmessage"
	log "github.com/echocat/slf4g"
)

func toJsonMessageSeq(reader io.Reader) iter.Seq2[*jsonmessage.JSONMessage, error] {
	return func(yield func(*jsonmessage.JSONMessage, error) bool) {
		dec := json.NewDecoder(reader)
		for {
			var jm jsonmessage.JSONMessage
			err := dec.Decode(&jm)
			if err == io.EOF {
				return
			}
			if !yield(&jm, err) {
				return
			}
		}
	}
}

func handleImagePullProgress(reader io.Reader, target PreparationProgress, logger log.Logger) error {
	type layer struct {
		last     int64
		total    int64
		complete bool
	}

	calculateProgress := func(layers map[string]layer) float32 {
		var last, total float64
		for _, l := range layers {
			lTotal := l.total
			lLast := l.last
			if !l.complete && lTotal <= 0 {
				return 0.0
			}
			if l.complete && lLast <= 0 {
				lLast = lTotal
			}
			last += float64(lLast)
			total += float64(lTotal)
		}
		if total < last {
			total = last
		}
		if total == 0 {
			total = 1
		}
		return float32(last / total)
	}

	layers := map[string]layer{}
	var progress float32 = 0.0

	for jm, err := range toJsonMessageSeq(reader) {
		if err != nil {
			return err
		}

		layerId := jm.ID
		status := jm.Status

		if err := jm.Error; err != nil {
			return err
		}

		if status == "Pulling fs layer" {
			layers[layerId] = layer{}
		} else if status == "Downloading layer" || status == "Downloading" {
			if p := jm.Progress; p != nil {
				layers[layerId] = layer{p.Current, p.Total, false}
			}
		} else if status == "Download complete" || status == "Already exists" {
			existing := layers[layerId]
			existing.complete = true
			layers[layerId] = existing
		} else if strings.HasPrefix(status, "Pulling from ") {
			// Ignore, usually the start
		} else if strings.HasPrefix(status, "Digest: ") {
			// Ignore, shortly before the end
		} else if strings.HasPrefix(status, "Status: Downloaded newer image for ") || strings.HasPrefix(status, "Status: Image is up to date for ") {
			// Ignore, usually the end
		} else {
			logger.With("payload", jm).
				Warn("received an unknown payload from docker daemon while pulling image")
		}

		progressCandidate := calculateProgress(layers)
		if progressCandidate > progress {
			progress = progressCandidate
			if err := target.Report(progress); err != nil {
				return err
			}
		}
	}

	return target.Done()
}
