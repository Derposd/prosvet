# Records docs/assets/demo.gif:  vhs docs/vhs/demo.tape   (needs vhs, ttyd, ffmpeg)
# Build first: go build -o bin/prosvet ./cmd/prosvet
# The demo runs against a simulated censored network on localhost — no real traffic.
Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1180
Set Height 760
Set Padding 18
Set Theme "GitHub Dark"
Set TypingSpeed 40ms
Set WindowBar Colorful
Set CursorBlink false

Hide
Sleep 2s
Type "export PATH=./bin:$PATH PROSVET_LANG=en CLICOLOR_FORCE=1 COLORTERM=truecolor && clear"
Enter
Sleep 1500ms
Show

# 1. Plain scan output (first screen of the report).
Type "prosvet demo --brief 2>/dev/null"
Sleep 300ms
Enter
Sleep 10s
Sleep 2500ms

# 2. Interactive TUI: live progress, then the results browser.
Type "clear && prosvet demo --tui"
Sleep 300ms
Enter
Sleep 10500ms
# Messenger A (DPI by SNI) is selected first.
Sleep 2500ms
Down
Sleep 2200ms
Down
Down
Sleep 2200ms
Down
Sleep 2000ms
Down
Sleep 2000ms
Down
Sleep 1800ms
Down
Down
Sleep 2200ms
Type "f"
Sleep 2000ms
Type "q"
Sleep 600ms
