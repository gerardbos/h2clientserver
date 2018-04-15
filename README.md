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

### Open items
- Set/configure the allowed certificates on the server side
- Add client certificate support

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

### Features
The h2 server supports
- h2 webserver over ssl
- GET/POST/PUT endpoints
- Set specific headers per endpoint
- Handle multiple connections via a single thread

### Open items
- Query parameters
- URL pattern matching (only static URLs)
- Mutliple servers (The architecture supports it, but the ESP32 does not have enough menory to handle it properly)

### Example

```c
#include "h2server.h"

struct copy_data{
	unsigned int read;
	char * read_buffer;
	unsigned int written;
};

#define min(a, b)		(a < b?a:b)

const static char certificate[] = "-----BEGIN CERTIFICATE-----\n"
"MIICrDCCAZQCCQCXHL3FD0cfBTANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA0x\n"
"OTIuMTY4LjEuMTAwMB4XDTE4MDYwNzIwMjE1MloXDTE5MDYwNzIwMjE1MlowGDEW\n"
"MBQGA1UEAwwNMTkyLjE2OC4xLjEwMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n"
"AQoCggEBAMwp/UmN+Z5LRKyRXiyZ5R5KQSsAvLMjrpigzJTt8noKtQZLb42PhUnC\n"
"TojhK+9YEiSHCbYDEcTBSitxv92oXrXpPmdZvWCm0Fmk/AitmLJwEtOvOCr6EWva\n"
"EJTmWGm/ILoMhN/6yuJ2YiskG+sP0+gnhmuA/Q4sa/VkAn8tPZDo4e5iIAPTTDSZ\n"
"4gDSc6TW9yU8VW4Y0US3TU+UDNo9Bzg26S4jOmwLE7Wn6JS8FrOoRopkYlAk/LPj\n"
"+XTzuRwUYkNPVMzX3Gsm4bIyHJyex8tbbQQmj13llXx8Lj68TmrMwNqGJsAcvvCD\n"
"vS7Y+qHTS3QKQhXGzFHHDeZAdL8ntNcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA\n"
"Ub/iyxBH0LqL0gII+PBHsAZ3SqKSUevY91UoK0g8ruYFgiTrogmz4nam6PmHQrmA\n"
"AqAy2KjohJSOtfDm/xPkv3yu4+ua5zjYC13rbqDCQttzGueAjBSUaSs6g56XWoZn\n"
"B1AOCrgSRO6mqeC8YA73dwTTgzq2NiKmojH5mcap3zqqiJrG8i++PKog8ReHqwNn\n"
"lVey7Usy9XGPCqUi9gzRa6c/GiR4aJPgbLKZB7leITtjUSxWV2rs9JW4aAFjkVBn\n"
"tSz6GglBoR8IhLUM1UHw6edXiJ40coriKgmtc6NiEtPdDMm25hjnXY8zzd1ET828\n"
"4Hk2mbZQ+38p7bWqfZ4rUA==\n"
"-----END CERTIFICATE-----"

const static char private_key[] = "-----BEGIN PRIVATE KEY-----\n"
"MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDMKf1JjfmeS0Ss\n"
"kV4smeUeSkErALyzI66YoMyU7fJ6CrUGS2+Nj4VJwk6I4SvvWBIkhwm2AxHEwUor\n"
"cb/dqF616T5nWb1gptBZpPwIrZiycBLTrzgq+hFr2hCU5lhpvyC6DITf+sridmIr\n"
"JBvrD9PoJ4ZrgP0OLGv1ZAJ/LT2Q6OHuYiAD00w0meIA0nOk1vclPFVuGNFEt01P\n"
"lAzaPQc4NukuIzpsCxO1p+iUvBazqEaKZGJQJPyz4/l087kcFGJDT1TM19xrJuGy\n"
"MhycnsfLW20EJo9d5ZV8fC4+vE5qzMDahibAHL7wg70u2Pqh00t0CkIVxsxRxw3m\n"
"QHS/J7TXAgMBAAECggEBAMFYQnYV7f7qaO7D+9thIom86FpBKHK9p+sC3LttW+QX\n"
"n7eGWO5GrINdb+JQ27qePRA6kge8gGdEZWkfIARaHtdHO8HESoPtdgJvK/9L5v+V\n"
"Az9VAGwyxazNpkZcnf4G8oc+s9cpOlmcovsYBxhktNl2FOZaEUwK5XJOc87cmSFQ\n"
"uQ5/ErzjWAARLpv42Gz8tpdUkLWQog2KCTyKHhXLo4oGFNRMSfq8jf0OEJgMSfSa\n"
"3hK+naomHaAvUNTj6Fj4t9/CXJyJtEqDUT6BS6SgQkwmYjwawdd3+hY3vB/451Dc\n"
"7KfAkkz3YKXnyE0S6PNZsn/1RFnQFFUn/XzlG9DPvoECgYEA6QFgC+rSRtedyvFD\n"
"ZA7OL1R0VgjcfikUZN/XCxff6H1ZT7WLIZWAR8UbJQhw6i+XmkX7U6aCO/rsMiO2\n"
"rlcoUppj2loXW86zgnTSiKs7VZPF+/2mTl5Wgad1ku0CEtTxmQsHMySeYzkddFGx\n"
"yumfJKfHghnbLOoYCn5DxbFn9TMCgYEA4E/4G6NOrbS42GA93f+sXu48UOzaSeBB\n"
"eCZFPt9Lylz6pIQBw6x5u8wBDyeYlFMTbwhNI50DzSt79xTVCwvMP1cbq6+j/RAc\n"
"aAJ+fQSLWG1mqB9DFW51VRwpkzxj0DwmRQcTiLQSAIVGBRDIMVf4Va523otP8eEA\n"
"C8SA1rFwOc0CgYEA1rTDsneRiGILLwSemsbhy89A3D6SH1bvSfzRhZFcbDmFYOPi\n"
"7vF6IahJWRisI7/zLN+rtetLOsX/fDxYi9IYf/VwabZ2q8yOsXnAvts6c6MV3xxe\n"
"cPyRLiwHNXpcXMoIToRRABmQMdJhh9v3vwkD8p0ARKxawMp9mL286aCOMO0CgYEA\n"
"g07M0oD6obzVJ/TOwpHUeY3ESSsdbXmVWZwtlOxqFX/wSTXtQnpImKKHTDPFoa4w\n"
"BiM55MsZWpVF8BGF1P2HBt0bGZmryYwQ1OIA4XYzjAQev/Ps9TLABJ6Dx+jmFRPg\n"
"4y+NQ80FbMCXiIeWaSwx9xY2B3hNyC4KNNlHAmbEZ1ECgYBa716jtmSM9c9v4Sdt\n"
"6YKeB8BlPyDZtLTnHPY9DgS39iZi2coEE8K8EtLmQbUVx0VOOhOGvwEfFcRv1viN\n"
"RUQi3aDUPVYpZ/8X3PFPNmJtoBWc1GcVcEc9Mt97a2Bw5wGBXtFhJe5LoYuM0gH4\n"
"S8QNsjvWFt/qyGNQ2cZulQvNEA==\n"
"-----END PRIVATE KEY-----"

static const char root_data[] = "<html><title>It works!</title><body><h1>It works!</h1></body></html>";

static int callback_root(char * buf, size_t length, bool * finished, void ** private_data)
{
	if(*private_data == NULL){
		*private_data = malloc(sizeof(struct copy_data));
		memset(*private_data, 0, sizeof(struct copy_data));
	}

	struct copy_data * bookkeeping = *private_data;
	int copy_bytes = min(length, sizeof(root_data) - bookkeeping->written);

	memcpy(buf, &root_data[bookkeeping->written], copy_bytes);

	bookkeeping->written += copy_bytes;

	if(bookkeeping->written >= sizeof(root_data))
		*finished = true;

	if(*finished){
		free(bookkeeping);
	}

	return copy_bytes;
}

// in your main content
void main(){
	h2server_initialize(certificate, sizeof(certificate) - 1, private_key, sizeof(private_key) - 1);

	struct h2server_handle * server = h2server_start(443);
	if(server != NULL){
		struct h2server_endpoint_header content_type_html = {.name = h2_header_contenttype, .value = "text/html"};

		struct h2server_endpoint e0 = h2server_endpoint_initialize("/", H2_GET);
		e0.callback_response = callback_root;
		h2server_endpoint_add_header(&e0, &content_type_html);
		h2server_register_endpoint(server, &e0);
	}
}
```
