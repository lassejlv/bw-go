// Package serve implements `bw serve`, the RESTful API webserver (apps/cli/src/serve.program.ts,
// commands/serve.command.ts and oss-serve-configurator.ts).
//
// The koa middleware stack of upstream is reproduced on top of net/http:
//
//	origin protection (Host allow-list + Origin rejection) -> body parser -> koa-json -> router
//
// Commands mutate process-global state (BW_SESSION, the state file), so every routed request
// runs under one mutex, which mirrors Node's single-threaded execution of upstream's handlers.
package serve
