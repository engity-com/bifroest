package id

import (
	"context"
	"fmt"
	"strings"

	cli "github.com/echocat/cli4g"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/uuidtext"
)

type options struct {
	IDs []string `argument:"id" required:"true" description:"UUIDs in conventional or Base58 notation."`
}

func CreateCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{cli.NewSimpleCommand("id", "Inspect UUID notations without accessing configuration or repositories.").
		WithProfiles(common.ProfileExecutable).
		WithCommand(cli.NewCommand[options]("convert", "Write one UUID,Base58 pair per input, without a header.").WithAliases("parse").WithProfiles(common.ProfileExecutable).WithHandler(handle))}
}

func handle(ctx context.Context, o options) error {
	if len(o.IDs) == 0 {
		return fmt.Errorf("at least one ID is required")
	}
	var output strings.Builder
	for index, text := range o.IDs {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, err := uuidtext.Parse(text)
		if err != nil {
			return fmt.Errorf("ID argument %d: %w", index+1, err)
		}
		output.WriteString(uuidtext.Classic(value))
		output.WriteByte(',')
		output.WriteString(uuidtext.Format(value))
		output.WriteByte('\n')
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := fmt.Fprint(cli.StdoutOfContext(ctx), output.String())
	return err
}
