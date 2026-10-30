import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { AgentRequestError } from "./agent.error";
import type { AgentControlAddr } from "./agent.types";
import { messageOf } from "./agent.utils";
import type { AgentLogger } from "./agent-log";

export type ControlHandlers = {
    openChannel(body: unknown): Promise<unknown>;
    authorize(body: unknown): Promise<unknown>;
    shutdown(): void;
};

// Fiber's agent bails on a request past it without answering; this one answers 400.
export const MAX_CONTROL_BODY_BYTES = 1024 * 1024;

const CONTROL_HEADERS = { "Content-Type": "application/json", Connection: "close" };

type ControlBody = { tooLarge: true } | { tooLarge: false; text: string };

/**
 * Writes a whole response and closes the connection.
 * @param response The response.
 * @param status The HTTP status.
 * @param body The body.
 * @param onFlushed Called once the response was handed to the operating system.
 */
function send(response: ServerResponse, status: number, body: Uint8Array, onFlushed?: () => void): void {
    response.writeHead(status, { ...CONTROL_HEADERS, "Content-Length": body.length });
    response.end(body, onFlushed);
}

/**
 * Writes a JSON response and closes the connection.
 * @param response The response.
 * @param status The HTTP status.
 * @param body The value written as JSON.
 */
function sendJson(response: ServerResponse, status: number, body: unknown): void {
    send(response, status, Buffer.from(JSON.stringify(body)));
}

/**
 * Reads a request body, keeping at most `MAX_CONTROL_BODY_BYTES` and draining the rest.
 * @param request The request.
 * @returns The body as UTF-8 text, or that it was too large.
 */
function readBody(request: IncomingMessage): Promise<ControlBody> {
    return new Promise((resolve, reject) => {
        const chunks: Buffer[] = [];
        let length = 0;
        request.on("data", (chunk: Buffer) => {
            length += chunk.length;
            if (length <= MAX_CONTROL_BODY_BYTES) chunks.push(chunk);
            else chunks.length = 0;
        });
        request.on("end", () =>
            resolve(
                length > MAX_CONTROL_BODY_BYTES ? { tooLarge: true } : { tooLarge: false, text: Buffer.concat(chunks).toString("utf8") },
            ),
        );
        request.on("error", reject);
    });
}

/**
 * Serves the status file's bytes, or 503 while it cannot be read.
 * @param response The response.
 * @param statusFile The status file.
 */
async function serveStatus(response: ServerResponse, statusFile: string): Promise<void> {
    let body: Buffer;
    try {
        body = await readFile(statusFile);
    } catch (error) {
        sendJson(response, 503, { error: `status unavailable: ${messageOf(error)}` });
        return;
    }
    send(response, 200, body);
}

/**
 * Serves a request the agent answers: 200 with its result, 400 for any failure, as fiber's agent, logging those not refused.
 * @param request The request.
 * @param response The response.
 * @param handler The agent's handler.
 * @param log The agent's log.
 */
async function serveCommand(
    request: IncomingMessage,
    response: ServerResponse,
    handler: (body: unknown) => Promise<unknown>,
    log: AgentLogger,
): Promise<void> {
    const body = await readBody(request);
    if (body.tooLarge) {
        sendJson(response, 400, { error: "control request too large" });
        return;
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(body.text);
    } catch (error) {
        sendJson(response, 400, { error: `malformed JSON: ${messageOf(error)}` });
        return;
    }
    try {
        sendJson(response, 200, { result: await handler(parsed) });
    } catch (error) {
        if (!(error instanceof AgentRequestError)) log("control_request_failed", { route: `${request.method} ${request.url}`, error });
        sendJson(response, 400, { error: messageOf(error) });
    }
}

/**
 * Routes one control request.
 * @param request The request.
 * @param response The response.
 * @param statusFile The status file `GET /status` serves.
 * @param handlers The agent.
 * @param log The agent's log.
 * @returns Settles once the request was answered.
 */
async function route(
    request: IncomingMessage,
    response: ServerResponse,
    statusFile: string,
    handlers: ControlHandlers,
    log: AgentLogger,
): Promise<void> {
    switch (`${request.method} ${request.url}`) {
        case "GET /status":
            return serveStatus(response, statusFile);
        case "POST /open-channel":
            return serveCommand(request, response, (body) => handlers.openChannel(body), log);
        case "POST /authorize":
            return serveCommand(request, response, (body) => handlers.authorize(body), log);
        case "POST /shutdown":
            send(response, 200, Buffer.from(JSON.stringify({ status: "restarting" })), () => handlers.shutdown());
            return;
        default:
            sendJson(response, 404, { error: "not found" });
    }
}

/**
 * Listens for the driver's control requests, fiber's test agent contract, before the agent initializes.
 * @param address Where to listen.
 * @param statusFile The status file `GET /status` serves.
 * @param handlers The agent.
 * @param log The agent's log.
 * @returns The server, listening.
 */
export function startControlServer(
    address: AgentControlAddr,
    statusFile: string,
    handlers: ControlHandlers,
    log: AgentLogger,
): Promise<Server> {
    const server = createServer((request, response) => {
        route(request, response, statusFile, handlers, log).catch((error: unknown) => {
            log("control_connection_failed", { route: `${request.method} ${request.url}`, error });
            response.destroy();
        });
    });
    return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(address.port, address.host, () => {
            server.off("error", reject);
            server.on("error", (error) => log("control_server_failed", { error }));
            log("control_server_listening", { host: address.host, port: (server.address() as AddressInfo).port });
            resolve(server);
        });
    });
}
