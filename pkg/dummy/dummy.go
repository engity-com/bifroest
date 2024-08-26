package dummy

import (
	"fmt"
	"io"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/engity-com/bifroest/pkg/errors"
)

type Dummy struct {
	Screen tcell.Screen

	Introduction string
	ShowEvents   bool
}

func (this *Dummy) Execute() error {
	s := this.Screen
	if s == nil {
		panic("Screen nil")
	}

	pg, reset := this.createPlayground()

	var app *tview.Application
	onKeyEvent := func(e *tcell.EventKey) *tcell.EventKey {
		if e.Key() == tcell.KeyEscape || e.Rune() == 'q' || e.Rune() == 'Q' || e.Key() == tcell.KeyCtrlC || e.Key() == tcell.KeyCtrlD {
			app.Stop()
		}
		if e.Rune() == 'c' || e.Rune() == 'C' {
			reset()
		}

		return e
	}
	onMouseEvent := func(e *tcell.EventMouse, action tview.MouseAction) (*tcell.EventMouse, tview.MouseAction) {
		return e, action
	}

	container := tview.NewGrid().
		SetRows(0).
		SetColumns(45, 0).
		AddItem(this.createSide(&app, &onKeyEvent, &onMouseEvent), 0, 0, 1, 1, 0, 0, false).
		AddItem(pg, 0, 1, 1, 1, 0, 0, true)

	app = tview.NewApplication().
		SetScreen(s).
		SetInputCapture(onKeyEvent).
		SetMouseCapture(onMouseEvent).
		EnableMouse(true).
		EnablePaste(true).
		SetRoot(container, true).
		SetFocus(container)

	if err := app.Run(); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil
		}
		return fmt.Errorf("cannot run application: %w", err)
	}

	s.Clear()
	s.ShowCursor(0, 0)
	s.Fini()

	return nil
}

func (this *Dummy) createSide(
	app **tview.Application,
	onKeyEvent *func(e *tcell.EventKey) *tcell.EventKey,
	onMouseEvent *func(e *tcell.EventMouse, action tview.MouseAction) (*tcell.EventMouse, tview.MouseAction),
) tview.Primitive {
	result := tview.NewFlex().
		SetDirection(tview.FlexRow)
	result.
		SetBackgroundColor(tcell.ColorNavy).
		SetBorderPadding(0, 0, 0, 1)

	this.addIntroduction(result)
	this.addProperties(result, app, onKeyEvent, onMouseEvent)

	return result
}

func (this *Dummy) addIntroduction(to *tview.Flex) {
	if v := this.Introduction; v != "" {
		this.addSectionHeader(to, "Introduction")
		view := tview.NewTextView().
			SetDynamicColors(true).
			SetText(strings.TrimSpace(v))
		to.AddItem(view, 0, 1, false)
	}
}

func (this *Dummy) addSectionHeader(to *tview.Flex, title string) {
	header := tview.NewTextView().
		SetText(title)
	header.SetBackgroundColor(tcell.ColorNavy)
	to.AddItem(header, 1, 0, false)
}

func (this *Dummy) addProperties(to *tview.Flex, app **tview.Application, onKeyEvent *func(e *tcell.EventKey) *tcell.EventKey, onMouseEvent *func(e *tcell.EventMouse, action tview.MouseAction) (*tcell.EventMouse, tview.MouseAction)) {
	newLabelCell := func(label string) *tview.TableCell {
		return tview.NewTableCell(label).
			SetAlign(tview.AlignLeft | tview.AlignTop)
	}
	newValueCell := func(value string) *tview.TableCell {
		return tview.NewTableCell(value).
			SetAlign(tview.AlignLeft | tview.AlignTop)
	}

	this.addSectionHeader(to, "Properties")

	properties := tview.NewTable()
	row := 0
	to.AddItem(properties, 0, 1, false)

	if this.ShowEvents {
		{
			value := newValueCell("")
			properties.SetCell(row, 0, newLabelCell("Last key:")).
				SetCell(row, 1, value)
			row++

			old := *onKeyEvent
			*onKeyEvent = func(e *tcell.EventKey) *tcell.EventKey {
				if e.Key() == tcell.KeyEscape || e.Rune() == 'q' || e.Rune() == 'Q' || e.Key() == tcell.KeyCtrlC || e.Key() == tcell.KeyCtrlD {
					if app != nil {
						(*app).Stop()
					}
				}

				value.Text = tview.Escape(e.Name())
				if value.Text == "" {
					value.Text = "None"
				}

				return old(e)
			}
			(*onKeyEvent)(&tcell.EventKey{})
		}

		{
			value := newValueCell("")
			properties.SetCell(row, 0, newLabelCell("Last click at: ")).
				SetCell(row, 1, value)
			row++
			old := *onMouseEvent
			*onMouseEvent = func(e *tcell.EventMouse, action tview.MouseAction) (*tcell.EventMouse, tview.MouseAction) {
				x, v := e.Position()
				value.Text = fmt.Sprintf("%dx%d", x, v)
				return old(e, action)
			}
			(*onMouseEvent)(&tcell.EventMouse{}, 0)

		}
	}
}

type playgroundPixel struct {
	left   bool
	middle bool
	right  bool
}

type playground struct {
	*tview.Box
	matrix     [][]playgroundPixel
	leftDown   bool
	middleDown bool
	rightDown  bool
}

func (this *playground) reset() {
	for y, row := range this.matrix {
		for x := range row {
			this.matrix[y][x] = playgroundPixel{}
		}
	}
}

func (this *playground) SetRect(x, y, width, height int) {
	this.Box.SetRect(x, y, width, height)
	if len(this.matrix) > height {
		this.matrix = this.matrix[:height]
	}
	if len(this.matrix) < height {
		oldMatrix := this.matrix
		this.matrix = make([][]playgroundPixel, height)
		copy(this.matrix, oldMatrix)
	}

	for rowI := 0; rowI < height; rowI++ {
		row := this.matrix[rowI]

		if len(row) > width {
			row = row[:width]
			this.matrix[rowI] = row
		} else if len(row) < width {
			oldRow := row
			row = make([]playgroundPixel, width)
			copy(row, oldRow)
			this.matrix[rowI] = row
		}
	}
}

func (this *playground) Draw(s tcell.Screen) {
	style := tcell.StyleDefault.
		Background(tcell.ColorWhite).
		Foreground(tcell.ColorBlack)

	this.DrawForSubclass(s, this)
	viewX, viewY, _, _ := this.GetInnerRect()
	for y, row := range this.matrix {
		for x, col := range row {
			ts := style
			c := ' '
			if col.left {
				ts = ts.Background(tcell.ColorBlue).Foreground(tcell.ColorWhite)
				c = 'L'
			} else if col.right {
				ts = ts.Background(tcell.ColorYellow).Foreground(tcell.ColorWhite)
				c = 'R'
			} else if col.middle {
				ts = ts.Background(tcell.ColorPurple).Foreground(tcell.ColorWhite)
				c = 'M'
			}
			s.SetContent(x+viewX, y+viewY, c, nil, ts)
		}
	}
}

func (this *playground) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (consumed bool, capture tview.Primitive) {
	return this.WrapMouseHandler(func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (consumed bool, capture tview.Primitive) {
		x, y := event.Position()
		rectX, rectY, _, _ := this.GetInnerRect()
		if !this.InRect(x, y) {
			return false, nil
		}
		x -= rectX
		y -= rectY

		switch action {
		case tview.MouseLeftUp:
			this.leftDown = false
			return false, nil
		case tview.MouseLeftDown:
			this.leftDown = true

		case tview.MouseMiddleUp:
			this.middleDown = false
			return false, nil
		case tview.MouseMiddleDown:
			this.middleDown = true

		case tview.MouseRightUp:
			this.rightDown = false
			return false, nil
		case tview.MouseRightDown:
			this.rightDown = true

		case tview.MouseMove:
			if !this.leftDown && !this.middleDown && !this.rightDown {
				return false, nil
			}

		default:
			return false, nil
		}

		this.matrix[y][x] = playgroundPixel{
			left:   this.leftDown,
			middle: this.middleDown,
			right:  this.rightDown,
		}

		return true, this
	})
}

func (this *Dummy) createPlayground() (tview.Primitive, func()) {
	instance := &playground{
		Box: tview.NewBox(),
	}

	instance.
		SetBackgroundColor(tcell.ColorWhite)

	return instance, instance.reset
}

func (this *Dummy) evaluateButtons(e *tcell.EventMouse) []string {
	var mbs []string
	m := func(match tcell.ButtonMask, name string) {
		if e.Buttons()&match != 0 {
			mbs = append(mbs, name)
		}
	}
	m(tcell.Button1, "Button1")
	m(tcell.Button2, "Button2")
	m(tcell.Button3, "Button3")
	m(tcell.Button4, "Button4")
	m(tcell.Button5, "Button5")
	m(tcell.Button6, "Button6")
	m(tcell.Button7, "Button7")
	m(tcell.Button8, "Button8")
	m(tcell.WheelUp, "WheelUp")
	m(tcell.WheelDown, "WheelDown")
	m(tcell.WheelLeft, "WheelLeft")
	m(tcell.WheelRight, "WheelRight")

	return mbs
}
