# Records docs/demo/scan.gif: a ~15 s terminal capture of a real scan producing SARIF.
# .github/workflows/demo-gif.yml records it on a runner and commits the GIF to the branch.
# To record locally instead you need vhs (https://github.com/charmbracelet/vhs) and Docker,
# then from the repo root:
#   docker build -t agent-perimeter-fixture:demo tests/fixtures/servers
#   vhs docs/demo/scan.tape
Output docs/demo/scan.gif
Set FontSize 16
Set Width 1100
Set Height 560
Set TypingSpeed 35ms
Type "agent-perimeter scan --target '' --image agent-perimeter-fixture:demo --env AP_FIXTURE_FLAW=imperative_injection --sarif demo.sarif"
Enter
Sleep 8s
Type "jq '.runs[0].results[] | {ruleId, level}' demo.sarif"
Enter
Sleep 4s
