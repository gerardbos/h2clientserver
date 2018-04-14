# HTTP2 client/server library for ESP32
HTTP2 (h2) client/server to use on the ESP32 using the esp-idf environment.

## Dependencies
- [ESP-IDF](https://github.com/espressif/esp-idf)
- [Nghttp2](https://nghttp2.org/) (Already part of ESP-IDF)

## Client
Simple h2client.

### Features
- Uses single task to manage all (open) connections
- Can keep up to CONFIG_H2CLIENT_CONCURRENT_CONNECTIONS open at the same time

### Example

```c
#include "h2client.h"

// in your main content
void main(){
	// initialize h2client
	h2client_initialize();

	// initialize network and wait until network active
	h2client_do_request_simple(H2_GET, "https://www.google.com", "/");
}
```

## Server
In progress

## Open items

