/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"strconv"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

const (
	AnnotationKey_AddLatency = "add_latency"
	AnnotationKey_Priority   = "priority"
)

type Annotation struct {
	AddLatency time.Duration
	Priority   int
}

func NewAnnotation(annotation []*config_parser.Param) (*Annotation, error) {
	var anno Annotation
	for _, param := range annotation {
		switch param.Key {
		case AnnotationKey_AddLatency:
			latency, err := time.ParseDuration(param.Val)
			if err != nil {
				return nil, fmt.Errorf("incorrect latency format: %w", err)
			}
			// Only the first setting is valid.
			if anno.AddLatency == 0 {
				anno.AddLatency = latency
			}
		case AnnotationKey_Priority:
			priority, err := strconv.Atoi(param.Val)
			if err != nil {
				return nil, fmt.Errorf("incorrect priority format: %w", err)
			}
			if anno.Priority == 0 {
				anno.Priority = priority
			}
		default:
			return nil, fmt.Errorf("unknown filter annotation: %v", param.Key)
		}
	}
	return &anno, nil
}
