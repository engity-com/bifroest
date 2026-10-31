package service

import (
	"context"
	"fmt"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	managementview "github.com/engity-com/bifroest/pkg/management/view"
	"github.com/engity-com/bifroest/pkg/recording"
)

func (this *service) managementAuditlogPage(ctx context.Context, request protocol.ReadRequest) (protocol.Page[protocol.AuditlogSummary], error) {
	page := protocol.Page[protocol.AuditlogSummary]{Items: make([]protocol.AuditlogSummary, 0)}
	after, _, err := request.Cursor()
	if err != nil {
		return page, err
	}
	var items []readSlot[protocol.AuditlogSummary]
	for _, conf := range this.Configuration.Auditlogs {
		if err := ctx.Err(); err != nil {
			return page, err
		}
		name := conf.Name.String()
		if name <= after {
			continue
		}
		items = insertRead(items, name, managementview.Auditlog(conf), request.Limit+1)
	}
	for i, item := range items {
		if i == request.Limit {
			page.Next = request.Next(items[i-1].value.Name, "")
			break
		}
		page.Items = append(page.Items, item.value)
	}
	return page, nil
}

func (this *service) managementRecordingPage(ctx context.Context, request protocol.ReadRequest) (protocol.Page[protocol.RecordingView], error) {
	page := protocol.Page[protocol.RecordingView]{Items: make([]protocol.RecordingView, 0)}
	_, after, err := request.Cursor()
	if err != nil {
		return page, err
	}
	options := recording.SealedPageOptions{Limit: uint(request.Limit + 1)}
	if after != "" {
		if err := options.After.UnmarshalText([]byte(after)); err != nil {
			return page, err
		}
	}
	name := configuration.AuditlogName(request.Auditlog)
	repository := this.recordingRepositories[name]
	if repository == nil || repository.native == nil {
		return page, fmt.Errorf("no active recording repository")
	}
	// The native bounded, ordered inventory supplies one lookahead ID. Only
	// selected records are inspected; an unselected artifact's content cannot
	// change this page's verification scope or turn the lookahead into evidence.
	ids, err := repository.native.ListSealedPage(ctx, options)
	if err != nil {
		return page, err
	}
	browser := managementRecordingBrowser{service: this}
	for index, id := range ids {
		if err := ctx.Err(); err != nil {
			return page, err
		}
		if index == request.Limit {
			page.Next = request.Next(request.Auditlog, page.Items[len(page.Items)-1].ID)
			break
		}
		row, err := browser.Detail(ctx, name, id)
		if err != nil {
			return page, err
		}
		page.Items = append(page.Items, row)
	}
	return page, nil
}
