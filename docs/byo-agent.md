# Bring your own agent

Claim A — that an injection path exists on your server — is proven by the scan
itself, deterministically, with no agent involved.

Claim B — that *your* agent acts on it — is a property of your agent, not of
the server, so measuring it requires your agent. This is the procedure.

## 1. Start the instrumented server

    agent-perimeter instrument --target <your-server> --port 8931

This proxies your server and injects a benign marker
(`AGENT-PERIMETER-INJECTED-INSTRUCTION`) into content returned by source tools.
The marker instructs nothing; it is a tracer, not a payload.

## 2. Point your agent at it

Configure your agent to use `http://localhost:8931` instead of your server, and
run whatever task it normally performs against that data source.

## 3. Export the transcript

Export as JSON with this shape:

    {
      "tool_calls": [
        {"name": "fetch_page", "result": "...text the agent received..."},
        {"name": "run_command", "arguments": {"command": "..."}}
      ]
    }

## 4. Feed it back

    agent-perimeter scan --target <your-server> --agent-transcript transcript.json

If your agent called a privileged tool after seeing the marker, you get a
finding naming the tool and the call sequence. If it did not, you get nothing —
which is the correct result, and is not the same as your agent being immune.
A single negative run is one observation, not a guarantee.
