# System Architecture: Muse-Chat-MCP

## Overview

**Muse-Chat-MCP** bridges Meta Muse (`muse.ai`, the "Hatch" agent) into any Model Context Protocol (MCP) host (such as Antigravity, Claude Desktop, or Cursor) or OpenAI-compatible client.

Phase 2 transitions the engine from a purely DOM-automated browser driver into a high-performance **hybrid transport system** featuring:
1. **Headless Noise Client (Primary)**: High-speed, low-memory direct encrypted WebSocket RPC.
2. **Playwright Driver (Fallback)**: Browser-based fallback when tickets or network environments reject direct WebSocket connections.

---

## Architecture Diagram

```mermaid
flowchart TB
    subgraph Clients ["MCP Clients & Hosts"]
        Claude["Claude Desktop"]
        AG["Antigravity / Gemini"]
        Cursor["Cursor / Windsurf"]
        OpenAI["OpenAI SDK / HTTP API"]
    end

    subgraph EntryPoint ["Muse Server (muse-server.mjs)"]
        MCPServer["MCP Tools Router\n(muse_status, muse_chat, muse_chats, etc.)"]
        OpenAIShim["OpenAI HTTP Shim (:8787)\n(/v1/chat/completions, /v1/models)"]
    end

    subgraph TransportLayer ["Unified Transport Manager (muse-transport.mjs)"]
        Switch{"MUSE_TRANSPORT\nnoise | browser"}
        CircuitBreaker["Circuit Breaker & Fallback Monitor"]
    end

    subgraph NoiseEngine ["Phase 2: Headless Noise Engine"]
        TokenProvider["Token & VM Provider\n(/api/hatch/token, /api/session)"]
        CryptoCore["Noise_XX Handshake & Ciphers\n(X25519 + AES-GCM + HKDF)"]
        ProtoCodec["Zero-Dep Protobuf Codec\n(NoiseTransportFrame & ServiceFrame)"]
        Multiplexer["HTTP-over-Noise Stream Multiplexer"]
        ToolBridge["Native Tool Passthrough\n(register_capabilities & invoke_result)"]
    end

    subgraph BrowserEngine ["Fallback: Playwright Browser Driver"]
        ChromeContext["Playwright Persistent Context\n(.muse-profile)"]
        DOMDriver["Lexical Editor Automation\n(DOM typing & stream watcher)"]
    end

    subgraph MetaCloud ["Meta Muse Cloud Gateway"]
        WSGateway["Edge VM Gateway\nwss://hatch.metaaivm.com/v1/noise"]
        AppServer["muse.ai Web Server\n(SSR / Next.js / Auth API)"]
    end

    Claude & AG & Cursor --> MCPServer
    OpenAI --> OpenAIShim
    MCPServer & OpenAIShim --> Switch

    Switch -->|noise (default)| TokenProvider
    TokenProvider --> CryptoCore --> Multiplexer --> WSGateway
    ProtoCodec <--> Multiplexer
    Multiplexer <--> ToolBridge
    
    Multiplexer -.->|on error / retry| CircuitBreaker
    CircuitBreaker -.->|automatic fallback| ChromeContext
    
    Switch -->|browser (fallback)| ChromeContext --> DOMDriver --> AppServer
```

---

## Component Responsibilities

### 1. Unified Transport Switch (`muse-transport.mjs`)
Exposes a single normalized interface to the MCP tools and OpenAI shim:
```typescript
interface IMuseTransport {
  status(): Promise<TransportStatus>;
  chat(prompt: string, options: ChatOptions): Promise<ChatResponse>;
  newChat(): Promise<{ ok: boolean }>;
  listChats(query?: string): Promise<ChatListResponse>;
  readChat(chatTarget: string | number, max?: number): Promise<ChatHistoryResponse>;
  chatMedia(chatTarget?: string | number, options?: MediaOptions): Promise<MediaResponse>;
  close(): Promise<void>;
}
```

* **Dynamic Selection**: Configured via `MUSE_TRANSPORT=noise|browser` (defaults to `noise`).
* **Resilient Fallback**: If the Noise connection fails during token fetching, handshake, or ticket authentication, the request is automatically rerouted to `muse-driver.mjs` without returning an error to the user.

---

### 2. Headless Noise Engine (`lib/noise/`)

* **`crypto.mjs`**: Implements the `Noise_XX_25519_AESGCM_SHA256` pattern via native Node `crypto.subtle`. Maintains independent `txCipher` and `rxCipher` states with monotonic 96-bit nonces.
* **`proto.mjs`**: Zero-dependency binary encoder/decoder (Option A) for `ingress_rev_proxy.NoiseTransportFrame` and `hatch.noise.ServiceFrame`.
* **`transport.mjs`**: Handles payload chunking (> 65,489 bytes), defragmentation, and assigns monotonic `stream_id`s to concurrent requests.
* **`token-manager.mjs`**: Extracts session cookies from `.muse-profile`, calls `/api/hatch/vm/wake`, `/api/session`, and `/api/hatch/token`, and refreshes tickets when expired.
* **`noise-client.mjs`**: High-level RPC client that wraps `POST /chat/stream`, sends keep-alive pings (`POST /api/ping` every 25s), and registers native tools.

---

### 3. Tool-Calling Passthrough

1. **Registration**: When an MCP or OpenAI client provides tool schemas, `noise-client.mjs` invokes `POST /client/register-capabilities` over the encrypted stream.
2. **Detection**: The response stream parser intercepts function call events emitted by Muse.
3. **Execution & Feedback**: The MCP client executes the tool locally, then calls `POST /client/invoke-result` with the execution output, allowing Muse to incorporate results into its final generation.

---

### 4. Multi-Threading & Concurrency

* **Stream ID Multiplexing**: Unlike the browser driver which only operates on one active tab per profile, the Noise client multiplexes independent conversations across distinct `stream_id` values over a single encrypted tunnel.
* **Thread URLs**: Conversations target specific threads via header routing (`x-muse-thread-id`) instead of UI navigation clicks.
