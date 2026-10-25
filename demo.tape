# Records demo.gif embedded in README.md. Run from the repository root:
#
#   make build && vhs demo.tape
#
# Requires vhs and its dependencies (ttyd, ffmpeg) on PATH.
# testdata/demo is copied to /tmp/scomp-demo as the scan target; the scan
# itself runs against the OSV API, so network access is needed.

Output demo.gif
Set FontSize 15
Set Width 1200
Set Height 600
Set Padding 12
Set WaitTimeout 60s

Hide
Type "test -d /tmp/scomp-demo || (cp -r testdata/demo /tmp/scomp-demo && git -C /tmp/scomp-demo init -q)"
Enter
Sleep 2s
Show

Type "./scomp /tmp/scomp-demo"
Enter
Wait +Screen /Findings/
Sleep 1.5s

Type "severity:critical"
Sleep 2s

Down
Down
Sleep 1.5s

Escape
