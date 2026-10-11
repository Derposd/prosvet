// Command assets renders the project's raster graphics from code, so they can
// be regenerated reproducibly:
//
//	go run ./tools/assets -out docs/assets
//
// It writes logo.svg, logo-512.png and social-preview.png (1280×640).
package main

import (
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"path/filepath"

	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/gomono"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
	"golang.org/x/image/vector"

	"github.com/ordinarysim/prosvet/internal/brand"
)

var (
	bg      = hex("#0D1117")
	surface = hex("#161B22")
	text    = hex("#E6EDF3")
	muted   = hex("#8B949E")
	accent  = hex("#7C9CFF")
	accent2 = hex("#B9F2FF")
	okC     = hex("#3FB950")
	thrC    = hex("#D29922")
	partC   = hex("#F0883E")
	badC    = hex("#F85149")
)

func hex(s string) color.RGBA {
	var r, g, b uint8
	_, _ = fmt.Sscanf(s, "#%02x%02x%02x", &r, &g, &b)
	return color.RGBA{r, g, b, 255}
}

func main() {
	out := flag.String("out", "docs/assets", "output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o750); err != nil {
		fail(err)
	}
	if err := os.WriteFile(filepath.Join(*out, "logo.svg"), []byte(brand.LogoSVG+"\n"), 0o644); err != nil { //nolint:gosec // public asset
		fail(err)
	}
	logo := image.NewRGBA(image.Rect(0, 0, 512, 512))
	drawLogo(logo, 0, 0, 512)
	save(filepath.Join(*out, "logo-512.png"), logo)
	save(filepath.Join(*out, "social-preview.png"), social())
	fmt.Println("assets written to", *out)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func save(path string, img image.Image) {
	f, err := os.Create(path)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		fail(err)
	}
}

// fillPath rasterises a closed polygon with src.
func fillPath(dst draw.Image, src image.Image, pts [][2]float64) {
	b := dst.Bounds()
	r := vector.NewRasterizer(b.Dx(), b.Dy())
	r.MoveTo(float32(pts[0][0]), float32(pts[0][1]))
	for _, p := range pts[1:] {
		r.LineTo(float32(p[0]), float32(p[1]))
	}
	r.ClosePath()
	r.Draw(dst, b, src, image.Point{})
}

func roundRect(x, y, w, h, rad float64) [][2]float64 {
	var pts [][2]float64
	corner := func(cx, cy, start float64) {
		for i := 0; i <= 8; i++ {
			a := start + float64(i)*math.Pi/16
			pts = append(pts, [2]float64{cx + rad*math.Cos(a), cy + rad*math.Sin(a)})
		}
	}
	corner(x+w-rad, y+rad, -math.Pi/2)
	corner(x+w-rad, y+h-rad, 0)
	corner(x+rad, y+h-rad, math.Pi/2)
	corner(x+rad, y+rad, math.Pi)
	return pts
}

// hGradient is a horizontal gradient between x0 and x1 with alpha ramp.
type hGradient struct {
	x0, x1 float64
	stops  []stop
}

type stop struct {
	at float64
	c  color.RGBA
	a  float64
}

func (g hGradient) ColorModel() color.Model { return color.RGBAModel }
func (g hGradient) Bounds() image.Rectangle {
	return image.Rect(-1e6, -1e6, 1e6, 1e6)
}

func (g hGradient) At(x, _ int) color.Color {
	t := (float64(x) - g.x0) / (g.x1 - g.x0)
	t = math.Max(0, math.Min(1, t))
	for i := 1; i < len(g.stops); i++ {
		a, b := g.stops[i-1], g.stops[i]
		if t <= b.at {
			u := (t - a.at) / (b.at - a.at)
			lerp := func(p, q uint8) uint8 { return uint8(float64(p) + (float64(q)-float64(p))*u) }
			alpha := a.a + (b.a-a.a)*u
			c := color.RGBA{lerp(a.c.R, b.c.R), lerp(a.c.G, b.c.G), lerp(a.c.B, b.c.B), 255}
			return color.NRGBA{c.R, c.G, c.B, uint8(alpha * 255)}
		}
	}
	last := g.stops[len(g.stops)-1]
	return color.NRGBA{last.c.R, last.c.G, last.c.B, uint8(last.a * 255)}
}

// drawLogo renders the logo (same geometry as brand.LogoSVG, 64-unit grid).
func drawLogo(dst draw.Image, ox, oy, size float64) {
	s := size / 64
	p := func(x, y float64) [2]float64 { return [2]float64{ox + x*s, oy + y*s} }
	fillPath(dst, image.NewUniform(bg), roundRect(ox, oy, 64*s, 64*s, 14*s))
	ray := hGradient{x0: ox + 6*s, x1: ox + 58*s, stops: []stop{{0, accent, .1}, {.45, accent, 1}, {1, accent2, 1}}}
	faint := hGradient{x0: ox + 6*s, x1: ox + 58*s, stops: []stop{{0, accent, .05}, {.45, accent, .55}, {1, accent2, .55}}}
	fillPath(dst, faint, [][2]float64{p(6, 30.2), p(30, 29.4), p(30, 34.6), p(6, 33.8)})
	fillPath(dst, ray, [][2]float64{p(34, 29.4), p(58, 19), p(58, 45), p(34, 34.6)})
	fillPath(dst, image.NewUniform(text), roundRect(ox+28.5*s, oy+9*s, 7*s, 18.5*s, 2.2*s))
	fillPath(dst, image.NewUniform(text), roundRect(ox+28.5*s, oy+36.5*s, 7*s, 18.5*s, 2.2*s))
}

func face(ttf []byte, size float64) font.Face {
	f, err := opentype.Parse(ttf)
	if err != nil {
		fail(err)
	}
	fc, err := opentype.NewFace(f, &opentype.FaceOptions{Size: size, DPI: 72, Hinting: font.HintingFull})
	if err != nil {
		fail(err)
	}
	return fc
}

func say(dst draw.Image, fc font.Face, c color.Color, x, y int, s string) int {
	d := &font.Drawer{Dst: dst, Src: image.NewUniform(c), Face: fc, Dot: fixed.P(x, y)}
	d.DrawString(s)
	return d.Dot.X.Round()
}

func social() image.Image {
	const w, h = 1280, 640
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	// Background with a soft diagonal glow.
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			d := math.Hypot(float64(x-300), float64(y-320)) / 900
			glow := math.Max(0, 1-d)
			r := float64(bg.R) + 12*glow
			g := float64(bg.G) + 16*glow
			b := float64(bg.B) + 34*glow
			img.SetRGBA(x, y, color.RGBA{uint8(r), uint8(g), uint8(b), 255})
		}
	}
	// Heatmap motif in the bottom-right corner.
	palette := []color.RGBA{okC, okC, okC, thrC, partC, badC, badC, surface}
	seed := uint32(7)
	for row := 0; row < 3; row++ {
		for col := 0; col < 15; col++ {
			seed = seed*1664525 + 1013904223
			c := palette[(seed>>24)%uint32(len(palette))]
			x := float64(730 + col*34)
			y := float64(532 + row*34)
			alpha := 0.15 + 0.55*float64(col)/15
			fillPath(img, image.NewUniform(color.NRGBA{c.R, c.G, c.B, uint8(alpha * 255)}), roundRect(x, y, 26, 26, 6))
		}
	}
	drawLogo(img, 96, 150, 300)

	title := face(gobold.TTF, 112)
	sub := face(goregular.TTF, 34)
	ru := face(goregular.TTF, 30)
	mono := face(gomono.TTF, 22)
	say(img, title, text, 450, 270, "Prosvet")
	say(img, sub, muted, 456, 330, "network diagnostics & censorship measurement")
	say(img, ru, muted, 456, 374, "диагностика сети и измерение цензуры")

	x := 456
	for _, chip := range []struct {
		c     color.RGBA
		label string
	}{{okC, "works"}, {thrC, "throttled"}, {badC, "blocked"}} {
		fillPath(img, image.NewUniform(chip.c), roundRect(float64(x), 420, 18, 18, 9))
		x = say(img, sub, text, x+28, 438, chip.label) + 30
	}
	say(img, mono, accent, 456, 500, "DNS · IP · SNI · TLS · QUIC · 16 KB · whitelists")
	say(img, mono, muted, 96, 560, "github.com/"+brand.Repo)
	return img
}
