# Creating Your Own Handler

The Evals C2 server is designed with customization in mind. Developers can easily add new handlers to the C2 server, 
and users can easily toggle which handlers to enable/disable and configure their settings. This guide describes how developers can add a new
handler to the C2 server.

In this guide, we'll use an HTTP C2 handler as a basic example, and we'll call it `examplehttphandler`.

## Add Your Handler Source Code
Within the `handlers` folder, create a new folder for your C2 handler. In our case, we'll call it `examplehttphandler`. This folder will contain a Golang
package for your C2 handler - all your handler source code and associated test files will go here.

We'll pretend that we created the following files for our demo C2 handler:
- `handlers/examplehttphandler/examplehttphandler.go`
- `handlers/examplehttphandler/examplehttphandler_test.go`

### Handler Init Function
In one of your handler source code files, you will need to mark your C2 handler as an available handler in an `init` function. This way, when
your handler package gets imported, the C2 server will know that your handler is available and where to reach it. You will also need to use
a struct to represent your handler, as your handler will need to implement the util.Handler interface. The below code provides an example:

```
// Represents our dummy HTTP handler. Will implement the util.Handler interface.
type ExampleHttpHandler struct {
	restAPIaddress string
	server *http.Server
	listenAddress string
}

// Factory method for creating our handler
func exampleHttpHandlerFactory() *ExampleHttpHandler {
	// restAPIaddress, server, and listenAddress will be initialized when handler is started
	return &ExampleHttpHandler{}
}

// Creates and adds the ExampleHttpHandler to the map of available C2 handlers.
func init() {
	util.AvailableHandlers["examplehttphandler"] = exampleHttpHandlerFactory()
}
```

Note that we use a factory method to return our struct - this gives us more flexibility if we need to add more 
variables to our handler struct, and it allows easier handler creation in unit tests.

`util.AvailableHandlers` maps handler names (`string`) to handler structs that implement the `util.Handler` interface. This means that our new handler
must implement the util.Handler interface:
```
// The Handler interface provides methods that all C2 handlers must implement.
type Handler interface {
	// Starts the handler given the rest API address string and configuration map.
	StartHandler(string, config.HandlerConfigEntry) error

	// Stops the given handler.
	StopHandler() error
}
```

Since each handler may operate differently, we leave it up to the handler creaters to determine how to start and stop their handlers.
The only requirements are the method signatures - both methods must return `error` if something goes wrong, and `StartHandler` must take in
a `string` (the REST API server address) and a `config.HandlerConfigEntry`, which represents the handler config entry for our specific
handler. You will not need to call these methods outside of your unit tests - `main.go` will handle that for you when starting up enabled C2 handlers.

For our HTTP handler, we can use `StartHandler` to listen on the address specified in our configuration entry (which we will create momentarily)
and to serve URL paths of our choice. Feel free to reference other handler implementations to get an idea of how you can set up your C2 handler.
`StopHandler` will take care of gracefully tearing down the handler components.

## Register Our C2 Handler
There are two steps for registering our C2 handler - creating a configuration entry and making sure our handler package gets imported.

### Import Handler
In order for the C2 server executable to incorporate our new handler code, we need to import the package so that the `init` function in our 
handler source code runs. We can do this by adding a new import statement in `handler/handlers.go` (change your package name accordingly):
```
_ "attackevals.mitre-engenuity.org/control_server/handlers/examplehttphandler"
```
The `_` underscore in front of the import means that we're only importing the package for its side effects, in particular the `init` function.
Remember that the `init` function is what stores our handler struct in the map of available handlers. `handlers.go` will not directly reference
individual C2 handlers, so we can't use a typical import.

### Config Entry
`config/handler_config.yml` contains the configuration entries for all of the available handlers in the C2 server. Each entry is a dictionary that
maps the handler name to an inner dictionary that maps a configuration setting name to its value. 

For example:
```yaml
sidetwist:
  host: 192.168.0.4
  port: 443
  enabled: false
```

In the above example, the handler name is `sidetwist`, and there are three configuration settings: 
- `host` - the IP address that the handler should bind to when listening for C2 traffic
- `port` - the port that the handler should listen on
- `enabled`: whether or not the handler should run when the C2 server starts up.

Since different handlers can use different protocols and methods for handling C2 traffic, you may see that some handlers have different settings in their
config entries. The only one that is required is the `enabled` setting, since this tells the C2 server whether or not to run the handler.

When creating your own handler, think about what configuration settings it will need. If the C2 traffic will be over HTTP, perhaps you want
to allow users to specify the host/port combination to listen on.

In this guide, we'll use an HTTP C2 handler as a basic example, and we'll call it `examplehttphandler`. Our config file entry will look as follows:
```yaml
examplehttphandler:
  host: 192.168.0.4
  port: 80
  enabled: true
```

Note that we set `enabled` to `true` so that our handler will start up when the server is run. 
We'll simply add the above entry at the end of `config/handler_config.yml`. 

## Unit Tests
Don't forget your unit tests! You will need to create unit tests for your new handler and update existing unit tests in `handler/handlers_test.go` 
to account for your newly available C2 handler:
- The `TestStartStopHandlers` and `TestStartStopHandlersSomeEnabled` test functions will need to be updated so that the number of available C2 handlers reflects your newly added handler. 
- The auxiliary functions `mockHandlerConfigFileReaderAllEnabled` and `mockHandlerConfigFileReaderSomeEnabled` will also need to be updated to include dummy entries for your new handler.

When ready, run `go test ./...` in the main control server repo directory to confirm that all your tests are working.

## Recompile binary
Recompile the control server binary to include your new C2 handler and perform any additional testing.

Run `go build -o controlServer main.go` in the main directory to recompile, and run `sudo ./controlServer` to run the control server.
