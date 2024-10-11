package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

type buildStage uint8

const (
	buildStageBinary buildStage = iota
	buildStageArchive
	buildStageImage
	buildStageDigest
	buildStagePublish
)

func (this buildStage) String() string {
	v, ok := buildStageToString[this]
	if !ok {
		return fmt.Sprintf("illegal-build-stage-%d", this)
	}
	return v
}

func (this *buildStage) Set(plain string) error {
	v, ok := stringToBuildStage[plain]
	if !ok {
		return fmt.Errorf("illegal-build-stage: %s", plain)
	}
	*this = v
	return nil
}

type buildStages []buildStage

func (this buildStages) contains(v buildStage) bool {
	return slices.Contains(this, v)
}

func (this buildStages) filter(predicate func(buildStage) bool) buildStages {
	var result buildStages
	for _, v := range this {
		if predicate(v) {
			result = append(result, v)
		}
	}
	return result
}

func (this buildStages) String() string {
	return strings.Join(this.Strings(), ",")
}

func (this buildStages) Strings() []string {
	strs := make([]string, len(this))
	for i, v := range this {
		strs[i] = v.String()
	}
	return strs
}

func (this *buildStages) Set(plain string) error {
	parts := strings.Split(plain, ",")
	buf := make(buildStages, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if err := buf[i].Set(part); err != nil {
			return err
		}
	}
	sort.Sort(buf)
	*this = buf
	return nil
}

func (x buildStages) Len() int           { return len(x) }
func (x buildStages) Less(i, j int) bool { return x[i] < x[j] }
func (x buildStages) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }

var (
	buildStageToString = map[buildStage]string{
		buildStageBinary:  "binary",
		buildStageArchive: "archive",
		buildStageImage:   "image",
		buildStageDigest:  "digest",
		buildStagePublish: "publish",
	}
	stringToBuildStage = func(in map[buildStage]string) map[string]buildStage {
		result := make(map[string]buildStage, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(buildStageToString)
	allBuildStageVariants = func(in map[buildStage]string) buildStages {
		result := make(buildStages, len(in))
		var i int
		for k := range in {
			result[i] = k
			i++
		}
		sort.Sort(result)
		return result
	}(buildStageToString)
)
